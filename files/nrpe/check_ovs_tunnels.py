#!/usr/bin/env python3
# -*- coding: us-ascii -*-
#
# Author: JuanJo Ciarlante <jjo@canonical.com>
# Modified: Alvaro Uria <alvaro.uria@canonical.com>
# Copyright (C) 2015, 2019 Canonical
# License: GPLv3

"""
Verify that all local OVS tun flows match the ones expected from locally
running nova instances

Example usage:
{0}
{0} -i br-tun                                     # peek at other OVS interface
{0} --conf-file=/etc/nova/nova.conf               # config file to peek creds
{0} --conf-username=neutron_admin_username        # config file username key
{0} --conf-password=neutron_admin_password        # config file password key
{0} --conf-tenant-name=neutron_admin_project_name # config file project_name key
{0} --conf-auth-url=neutron_admin_auth_url        # config file auth_url key

Installation requires os_client_config, found in

"""
import sys
import os
import re
import logging
import argparse
import configparser
import socket
import subprocess

import os_client_config

(STATUS_OK, STATUS_WARN, STATUS_CRIT, STATUS_UNKNOWN) = range(0, 4)


def get_creds(args):
    """ return creds dictionary from conf-file (/etc/nova/nova.conf),
        overridden by OS_ environment vars """
    config = configparser.RawConfigParser()
    config.read(args.conf_file)
    # create a dictionary as e.g.: {'username': env['OS_USERNAME'], ...}
    creds = {}
    for key in ('auth_url', 'username', 'password', 'project_name',
                'user_domain_name', 'project_domain_name'):
        env_key = "OS_{}".format(key.upper())
        creds[key] = config.get('neutron', key)
        os.environ[env_key] = creds[key]
    logging.debug("creds: username={username} project_name={project_name} "
                  "auth_url={auth_url} password=...".format(**creds))

    return creds


def nova_list_instances(nova_cli, host):
    """Retrieves all instances running on a host, and returns their IDs
    """
    logging.info('getting all instances running at host="{}" ...'.format(
        socket.gethostname()))
    all_instances = nova_cli.get(
        '/servers/detail?all_tenants=True&host={}'.format(host))
    filtered_instances = set()
    for inst in all_instances.json()['servers']:
        if inst.get('status', 'ERROR') == 'ACTIVE':
            filtered_instances.add(inst.get('id'))
    logging.info('instances count={}'.format(len(filtered_instances)))
    logging.debug('instances: {}'.format(filtered_instances))
    return list(filtered_instances)


def instances_port_nets(neutron_cli, instances):
    """Retrieves all ports per previously found instance and returns a list of
    network_ids
    """
    logging.info('getting all instances networks ...')
    instances_nets = set()
    for instance in instances:
        ports = neutron_cli.get('/v2.0/ports?device_id={}'.format(instance))
        for port in ports.json()['ports']:
            if port.get('network_id'):
                instances_nets.add(port.get('network_id'))
    logging.info('instances networks count={}'.format(len(instances_nets)))
    logging.debug('instances networks: {}'.format(instances_nets))
    return instances_nets


def neutron_networks_by_id(neutron_cli):
    "return all neutron networks, keyed by id"
    logging.info('getting all neutron networks ...')
    # all_nets = neutron_cli.list_networks().get('networks')
    all_nets = neutron_cli.get('/v2.0/networks')
    networks_by_id = {net['id']: net for net in all_nets.json()['networks']}
    logging.info('neutron networks count={}'.format(len(networks_by_id)))
    logging.debug('neutron networks: {}'.format(networks_by_id.keys()))
    return networks_by_id


def get_instances_tun_ids(instances_nets, all_nets_by_id):
    """return tun_ids from for passed instances networks
       by looking up all_nets_by_id info"""
    logging.info('getting network segmentation_id info for all instances...')
    instances_tun_ids = {all_nets_by_id[net_id].get('provider:segmentation_id')
                         for net_id in instances_nets}
    logging.info('instances_tun_ids: {}'.format(instances_tun_ids))
    return instances_tun_ids


def get_ovs_tun_ids(interface):
    """get local tun_ids from ovs-ofctl output, ala:
       ovs-ofctl dump-flows br-tun |egrep -o 'tun_id=\w+' """
    logging.info('local tun_ids: running: ovs-ofctl dump-flows {}'.format(
        interface))
    ovs_dump = subprocess.check_output(["ovs-ofctl", "dump-flows", interface])
    ovs_tun_ids = set()
    # match lines with: ... tun_id=0x<TUN_ID> ...
    for line in ovs_dump.decode().split('\n'):
        match = re.search("tun_id=(?P<tun_id>0x\w+)", line)
        if match:
            ovs_tun_ids.add(int(match.group(1), 16))
    logging.info('ovs_tun_ids: {}'.format(ovs_tun_ids))
    return ovs_tun_ids


def nrpe_check_tun_ids(expected_tun_ids, local_tun_ids, all_nets_by_id):
    # order is important: substract local_tun_ids from expected_tun_ids,
    # result should be empty
    tun_ids_diff = expected_tun_ids.difference(local_tun_ids)
    rc = STATUS_OK
    msg = []
    if tun_ids_diff:
        tun_ids_str = ' '.join(['tun_id=0x{0:x}'.format(x)
                                for x in tun_ids_diff])
        msg.append('CRITICAL: missing local tun_ids: {}'.format(tun_ids_str))
        # helper dict by tun_id
        net_by_tun_id = {net_val.get('provider:segmentation_id'): net_val
                         for net_id, net_val in all_nets_by_id.items()}
        for tun_id in tun_ids_diff:
            net = net_by_tun_id.get(tun_id, {})
            msg.append('CRITICAL: tun_id=0x{0:x} network.id={id} '
                       'network.name="{name}"'.format(tun_id, **net))
        logging.warning('exp_tun_ids: {}'.format(sorted(expected_tun_ids)))
        logging.warning('loc_tun_ids: {}'.format(sorted(local_tun_ids)))
        rc = STATUS_CRIT
    else:
        msg.append('OK: all needed tun_ids present: {}'
                   ''.format(list(local_tun_ids)))
    return (rc, msg)


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__.format(*sys.argv),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--conf-username',
                        default='username',
                        help='config file username key')
    parser.add_argument('--conf-password',
                        default='password',
                        help='config file password key')
    parser.add_argument('--conf-project-name',
                        default='project_name',
                        help='config file project_name key')
    parser.add_argument('--conf-auth-url',
                        default='auth_url',
                        help='config file auth-url key')
    parser.add_argument('--conf-file', default='/etc/nova/nova.conf',
                        help='config file to peek creds from')
    parser.add_argument('-i', '--interface', default='br-tun',
                        help='OVS iface where to find tun_ids, as: '
                        'ovs-ofctl dump-flows <interface>')
    parser.add_argument('--test', default=False, action='store_true',
                        help='simulate missing local tun_ids, force CRITICAL')
    parser.add_argument('--verbose', default=False, action='store_true')
    parser.add_argument('--debug', default=False, action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    # initialize needed clients
    creds = get_creds(args)
    for key, value in creds.items():
        os.environ[key] = value

    logging.info("initializing nova_client")
    nova_cli = os_client_config.session_client('compute', cloud='envvars')
    logging.info("initializing neutron_client")
    neutron_cli = os_client_config.session_client('network', cloud='envvars')

    # The Neutron API queries need v2.0, this checks and exits if that is not available
    neutron_versions = neutron_cli.get('/').json()['versions']
    supports_neutron_2 = any(version['id'] == 'v2.0' for version in neutron_versions)
    if not supports_neutron_2:
        rc = 3
        print('UNKNOWN: Nagios plugin requires Neutron API v2.0')
        sys.exit(rc)

    # instances:      local instances id-s (ie running at this host)
    # instances_nets: local instances' networks id-s
    # all_nets_by_id: all neutron networks, keyed by id
    # exp_tun_ids:    local instances' networks' segmentation_id-s
    # loc_tun_ids:    locally present tun_ids from ovs-ofctl dump-flows br-tun
    instances = nova_list_instances(nova_cli, socket.gethostname())
    instances_nets = instances_port_nets(neutron_cli, instances)
    all_nets_by_id = neutron_networks_by_id(neutron_cli)
    exp_tun_ids = get_instances_tun_ids(instances_nets, all_nets_by_id)
    loc_tun_ids = get_ovs_tun_ids(args.interface)

    if args.test:
        logging.info('TEST: remove a local tun_id'.format(args.interface))
        loc_tun_ids.pop()

    rc, msg = nrpe_check_tun_ids(exp_tun_ids, loc_tun_ids, all_nets_by_id)
    print("\n".join(msg))
    sys.exit(rc)

