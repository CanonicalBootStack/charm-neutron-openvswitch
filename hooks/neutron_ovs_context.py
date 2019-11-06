# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import glob
import os
import re
import socket
import uuid
from pci import PCINetDevices
from charmhelpers.core.hookenv import (
    config,
    log,
    relation_get,
    relation_ids,
    related_units,
    unit_get,
    network_get_primary_address,
)
from charmhelpers.core.host import (
    CompareHostReleases,
    lsb_release,
    write_file,
)
from charmhelpers.contrib.openstack import context
from charmhelpers.contrib.openstack.utils import (
    config_flags_parser,
    get_host_ip,
)
from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_relation_ip,
)
from charmhelpers.contrib.openstack.context import (
    OSContextGenerator,
    NeutronAPIContext,
    parse_data_port_mappings
)
from charmhelpers.contrib.openstack.utils import (
    os_release,
    CompareOpenStackReleases,
)
import charmhelpers.contrib.openstack.utils as os_utils
from charmhelpers.core.unitdata import kv

IPTABLES_HYBRID = 'iptables_hybrid'
OPENVSWITCH = 'openvswitch'
VALID_FIREWALL_DRIVERS = (IPTABLES_HYBRID, OPENVSWITCH)

NFG_LOG_RATE_LIMIT_MIN = 100
NFG_LOG_BURST_LIMIT_MIN = 25


def _get_firewall_driver(ovs_ctxt):
    '''
    Determine the firewall driver to use based on configuration,
    OpenStack and Ubuntu releases.

    @returns str: firewall driver to use for OpenvSwitch
    '''
    driver = config('firewall-driver') or IPTABLES_HYBRID
    release = lsb_release()['DISTRIB_CODENAME']
    if driver not in VALID_FIREWALL_DRIVERS:
        return IPTABLES_HYBRID

    if driver == IPTABLES_HYBRID and ovs_ctxt['enable_nsg_logging']:
        msg = "NSG logging can not be enabled - need to set " \
              "firewall driver to 'openvswitch' explicitly"
        log(msg, "WARN")

    if (driver == OPENVSWITCH and
            CompareHostReleases(release) < 'xenial'):
        # NOTE(jamespage): Switch back to iptables_hybrid for
        #                  Ubuntu releases prior to Xenial due
        #                  to requirements for Linux >= 4.4 and
        #                  Open vSwitch >= 2.5
        return IPTABLES_HYBRID

    return driver


def get_nsg_log_path(desired_nsg_log_path):
    if not desired_nsg_log_path:
        # None means "we need to use syslog" - no need
        # to check anything on filesystem
        return None

    dst_dir, _ = os.path.split(desired_nsg_log_path)
    path_exists = os.path.exists(dst_dir)
    if not path_exists:
        log(
            "Desired NSG log directory {} not exists! "
            "falling back to syslog".format(dst_dir),
            "WARN"
        )
        return None

    if path_exists and os.path.isdir(desired_nsg_log_path):
        log(
            "Desired NSG log path {} should be file, not directory! "
            "falling back to syslog".format(desired_nsg_log_path),
            "WARN"
        )
        return None

    return desired_nsg_log_path


def validate_nfg_log_path(desired_nfg_log_path):
    if not desired_nfg_log_path:
        # None means "we need to use syslog" - no need
        # to check anything on filesystem
        return None

    dst_dir, _ = os.path.split(desired_nfg_log_path)
    path_exists = os.path.exists(dst_dir)
    if not path_exists:
        log(
            "Desired NFG log directory {} not exists! "
            "falling back to syslog".format(dst_dir),
            "WARN"
        )
        return None

    if path_exists and os.path.isdir(desired_nfg_log_path):
        log(
            "Desired NFG log path {} should be file, not directory! "
            "falling back to syslog".format(desired_nfg_log_path),
            "WARN"
        )
        return None

    return desired_nfg_log_path


def get_net_dev():
    return os.listdir('/sys/class/net')


def matches(pattern, strings):
    '''
    >>> matches(r'eth', ['eth1', 'veth', 'br1'])
    ['eth1', 'veth']
    '''
    regexp = re.compile(pattern)
    l = [s for s in strings if regexp.search(s)]
    return l


def expand_net_devs(whitelist, devicelist):
    '''
    expand_net_devs('physnet1:eno2 physnet2:enp(216|131)s0f1',
        ['lxcbr0', 'eno2', 'enp131s0f1'])
    # 'physnet1:eno2,physnet2:enp131s0f1'
    '''
    res = []
    for entry in whitelist:
        label, devpattern = entry.split(':')
        m = matches(devpattern, devicelist)
        log(("Matched {} devices for pattern {}, out of "
             "total: {}").format(m, devpattern, devicelist))
        if len(m) != 1:
            raise Exception(
                "Need exactly 1 match for {} in device list {}".format(
                    devpattern, devicelist)
            )
        res.append("{}:{}".format(label, m[0]))
    log("Expanded sriov mapping: {}". format(res))
    return ",".join(res)


class OVSPluginContext(context.NeutronContext):
    interfaces = []

    @property
    def plugin(self):
        return 'ovs'

    @property
    def network_manager(self):
        return 'neutron'

    @property
    def neutron_security_groups(self):
        if config('disable-security-groups'):
            return False
        neutron_api_settings = NeutronAPIContext()()
        return neutron_api_settings['neutron_security_groups']

    def ovs_ctxt(self):
        # In addition to generating config context, ensure the OVS service
        # is running and the OVS bridge exists. Also need to ensure
        # local_ip points to actual IP, not hostname.
        ovs_ctxt = super(OVSPluginContext, self).ovs_ctxt()
        if not ovs_ctxt:
            return {}

        conf = config()

        fallback = get_host_ip(unit_get('private-address'))
        if config('os-data-network'):
            # NOTE: prefer any existing use of config based networking
            ovs_ctxt['local_ip'] = \
                get_address_in_network(config('os-data-network'),
                                       fallback)
        else:
            # NOTE: test out network-spaces support, then fallback
            try:
                ovs_ctxt['local_ip'] = get_host_ip(
                    network_get_primary_address('data')
                )
            except NotImplementedError:
                ovs_ctxt['local_ip'] = fallback

        neutron_api_settings = NeutronAPIContext()()
        ovs_ctxt['neutron_security_groups'] = self.neutron_security_groups
        ovs_ctxt['l2_population'] = neutron_api_settings['l2_population']
        ovs_ctxt['distributed_routing'] = neutron_api_settings['enable_dvr']
        ovs_ctxt['extension_drivers'] = neutron_api_settings[
            'extension_drivers']
        ovs_ctxt['overlay_network_type'] = \
            neutron_api_settings['overlay_network_type']
        ovs_ctxt['polling_interval'] = neutron_api_settings['polling_interval']
        ovs_ctxt['rpc_response_timeout'] = \
            neutron_api_settings['rpc_response_timeout']
        ovs_ctxt['report_interval'] = neutron_api_settings['report_interval']
        # TODO: We need to sort out the syslog and debug/verbose options as a
        # general context helper
        ovs_ctxt['use_syslog'] = conf['use-syslog']
        ovs_ctxt['verbose'] = conf['verbose']
        ovs_ctxt['debug'] = conf['debug']
        ovs_ctxt['prevent_arp_spoofing'] = conf['prevent-arp-spoofing']
        ovs_ctxt['enable_dpdk'] = conf['enable-dpdk']

        net_dev_mtu = neutron_api_settings.get('network_device_mtu')
        if net_dev_mtu:
            # neutron.conf
            ovs_ctxt['network_device_mtu'] = net_dev_mtu
            # ml2 conf
            ovs_ctxt['veth_mtu'] = net_dev_mtu

        mappings = config('bridge-mappings')
        if mappings:
            ovs_ctxt['bridge_mappings'] = ','.join(mappings.split())

        sriov_mappings = config('sriov-device-mappings')
        if sriov_mappings:
            ovs_ctxt['sriov_device_mappings'] = \
                expand_net_devs(sriov_mappings.split(), get_net_dev())

        enable_sriov = config('enable-sriov')
        if enable_sriov:
            ovs_ctxt['enable_sriov'] = True

        sriov_numvfs = config('sriov-numvfs')
        if sriov_numvfs:
            try:
                if sriov_numvfs != 'auto':
                    int(sriov_numvfs)
            except ValueError:
                ovs_ctxt['sriov_vfs_list'] = sriov_numvfs
            else:
                ovs_ctxt['sriov_vfs_blanket'] = sriov_numvfs

        flat_providers = config('flat-network-providers')
        if flat_providers:
            ovs_ctxt['network_providers'] = ','.join(flat_providers.split())

        vlan_ranges = config('vlan-ranges')
        if vlan_ranges:
            ovs_ctxt['vlan_ranges'] = ','.join(vlan_ranges.split())

        ovs_ctxt['enable_nsg_logging'] = \
            neutron_api_settings['enable_nsg_logging']

        ovs_ctxt['nsg_log_output_base'] = get_nsg_log_path(
            config('security-group-log-output-base')
        )
        ovs_ctxt['nsg_log_rate_limit'] = \
            config('security-group-log-rate-limit')
        ovs_ctxt['nsg_log_burst_limit'] = \
            config('security-group-log-burst-limit')

        ovs_ctxt['firewall_driver'] = _get_firewall_driver(ovs_ctxt)

        if ovs_ctxt['firewall_driver'] != OPENVSWITCH:
            ovs_ctxt['enable_nsg_logging'] = False

        return ovs_ctxt


class ZoneContext(OSContextGenerator):

    def __call__(self):
        """Return the 'default_availability_zone' from the principal that this
        ovs unit is attached to (as a subordinate)

        :returns: {} if no relation set, or
            {'availability_zone': availability_zone from principal relation}
        """
        # as ovs is a subordinate charm, it should only have one relation to
        # its principal charm.  Thus we can take the 1st (only) element in each
        # list.
        rids = relation_ids('neutron-plugin')
        ctxt = {}
        if rids:
            rid = rids[0]
            units = related_units(rid)
            if units:
                availability_zone = relation_get(
                    'default_availability_zone',
                    rid=rid,
                    unit=units[0])
                if availability_zone:
                    ctxt['availability_zone'] = availability_zone
        return ctxt


class DHCPAgentContext(ZoneContext):

    def __call__(self):
        """Return the 'default_availability_zone' from the principal that this
        ovs unit is attached to (as a subordinate) and the 'dns_domain' from
        the neutron-plugin-api relations (if one is set).

        :returns: {} if no relation set, or
            {'availability_zone': availability_zone from principal relation}
        """
        ctxt = super(DHCPAgentContext, self).__call__()

        dnsmasq_flags = config('dnsmasq-flags')
        if dnsmasq_flags:
            ctxt['dnsmasq_flags'] = config_flags_parser(dnsmasq_flags)
        ctxt['dns_servers'] = config('dns-servers')

        neutron_api_settings = NeutronAPIContext()()
        if neutron_api_settings.get('dns_domain'):
            ctxt['dns_domain'] = neutron_api_settings.get('dns_domain')

        ctxt['instance_mtu'] = config('instance-mtu')

        return ctxt


class L3AgentContext(OSContextGenerator):

    def __call__(self):
        neutron_api_settings = NeutronAPIContext()()
        ctxt = {}
        if neutron_api_settings['enable_dvr']:
            use_dvr_snat = config('use-dvr-snat')
            agent_mode = 'dvr_snat' if use_dvr_snat else 'dvr'
            ctxt['agent_mode'] = agent_mode
            ctxt['use_l3ha'] = neutron_api_settings.get('enable_l3ha', False)
            if not config('ext-port'):
                ctxt['external_configuration_new'] = True
        else:
            ctxt['agent_mode'] = 'legacy'

        ctxt['enable_nfg_logging'] = (
            neutron_api_settings['enable_nfg_logging']
        )

        ctxt['nfg_log_output_base'] = validate_nfg_log_path(
            config('firewall-group-log-output-base')
        )
        ctxt['nfg_log_rate_limit'] = config(
            'firewall-group-log-rate-limit'
        )
        if ctxt['nfg_log_rate_limit'] is not None:
            ctxt['nfg_log_rate_limit'] = max(
                ctxt['nfg_log_rate_limit'],
                NFG_LOG_RATE_LIMIT_MIN
            )
        ctxt['nfg_log_burst_limit'] = config(
            'firewall-group-log-burst-limit'
        )
        if ctxt['nfg_log_burst_limit'] is not None:
            ctxt['nfg_log_burst_limit'] = max(
                ctxt['nfg_log_burst_limit'],
                NFG_LOG_BURST_LIMIT_MIN
            )

        cmp_os_release = CompareOpenStackReleases(os_release('neutron-common'))

        l3_extension_plugins = neutron_api_settings.get(
            'l3_extension_plugins', [])

        # per Change-Id If1b332eb0f581e9acba111f79ba578a0b7081dd2
        # only enable it for stein although fwaasv2 was added in Queens
        is_stein = cmp_os_release >= 'stein'
        if is_stein:
            l3_extension_plugins.append('fwaas_v2')

        if (is_stein and neutron_api_settings.get('enable_nfg_logging')):
            l3_extension_plugins.append('fwaas_v2_log')

        ctxt['l3_extension_plugins'] = ','.join(l3_extension_plugins)

        return ctxt


def resolve_dpdk_bridges():
    '''
    Resolve local PCI devices from configured mac addresses
    using the data-port configuration option

    @return: OrderDict indexed by PCI device address.
    '''
    ports = config('data-port')
    devices = PCINetDevices()
    resolved_devices = collections.OrderedDict()
    db = kv()
    if ports:
        # NOTE: ordered dict of format {[mac]: bridge}
        portmap = parse_data_port_mappings(ports)
        for mac, bridge in portmap.items():
            pcidev = devices.get_device_from_mac(mac)
            if pcidev:
                # NOTE: store mac->pci allocation as post binding
                #       to dpdk, it disappears from PCIDevices.
                db.set(mac, pcidev.pci_address)
                db.flush()

            pci_address = db.get(mac)
            if pci_address:
                resolved_devices[pci_address] = bridge

    return resolved_devices


def resolve_dpdk_bonds():
    '''
    Resolve local PCI devices from configured mac addresses
    using the dpdk-bond-mappings configuration option

    @return: OrderDict indexed by PCI device address.
    '''
    bonds = config('dpdk-bond-mappings')
    devices = PCINetDevices()
    resolved_devices = collections.OrderedDict()
    db = kv()
    if bonds:
        # NOTE: ordered dict of format {[mac]: bond}
        bondmap = parse_data_port_mappings(bonds)
        for mac, bond in bondmap.items():
            pcidev = devices.get_device_from_mac(mac)
            if pcidev:
                # NOTE: store mac->pci allocation as post binding
                #       to dpdk, it disappears from PCIDevices.
                db.set(mac, pcidev.pci_address)
                db.flush()

            pci_address = db.get(mac)
            if pci_address:
                resolved_devices[pci_address] = bond

    return resolved_devices


def parse_cpu_list(cpulist):
    '''
    Parses a linux cpulist for a numa node

    @return list of cores
    '''
    cores = []
    ranges = cpulist.split(',')
    for cpu_range in ranges:
        if "-" in cpu_range:
            cpu_min_max = cpu_range.split('-')
            cores += range(int(cpu_min_max[0]),
                           int(cpu_min_max[1]) + 1)
        else:
            cores.append(int(cpu_range))
    return cores


def numa_node_cores():
    '''Dict of numa node -> cpu core mapping'''
    nodes = {}
    node_regex = '/sys/devices/system/node/node*'
    for node in glob.glob(node_regex):
        index = node.lstrip('/sys/devices/system/node/node')
        with open(os.path.join(node, 'cpulist')) as cpulist:
            nodes[index] = parse_cpu_list(cpulist.read().strip())
    return nodes


class DPDKDeviceContext(OSContextGenerator):

    def __call__(self):
        driver = config('dpdk-driver')
        if driver is None:
            return {}
        # Resolve PCI devices for both directly used devices (_bridges)
        # and devices for use in dpdk bonds (_bonds)
        pci_devices = resolve_dpdk_bridges()
        pci_devices.update(resolve_dpdk_bonds())
        return {'devices': pci_devices,
                'driver': driver}


class OVSDPDKDeviceContext(OSContextGenerator):

    def cpu_mask(self):
        '''
        Hex formatted CPU mask based on using the first
        config:dpdk-socket-cores cores of each NUMA node
        in the unit.
        '''
        num_cores = config('dpdk-socket-cores')
        mask = 0
        for cores in numa_node_cores().values():
            for core in cores[:num_cores]:
                mask = mask | 1 << core
        return format(mask, '#04x')

    def socket_memory(self):
        '''
        Formatted list of socket memory configuration for dpdk using
        config:dpdk-socket-memory per NUMA node.
        '''
        sm_size = config('dpdk-socket-memory')
        node_regex = '/sys/devices/system/node/node*'
        mem_list = [str(sm_size) for _ in glob.glob(node_regex)]
        if mem_list:
            return ','.join(mem_list)
        else:
            return str(sm_size)

    def devices(self):
        '''List of PCI devices for use by DPDK'''
        pci_devices = resolve_dpdk_bridges()
        pci_devices.update(resolve_dpdk_bonds())
        return pci_devices

    def _formatted_whitelist(self, flag):
        '''Flag formatted list of devices to whitelist

        :param flag: flag format to use
        :type flag: str
        :rtype: str
        '''
        whitelist = []
        for device in self.devices():
            whitelist.append(flag.format(device=device))
        return ' '.join(whitelist)

    def device_whitelist(self):
        '''
        Formatted list of devices to whitelist for dpdk
        using the old style '-w' flag

        :rtype: str
        '''
        return self._formatted_whitelist('-w {device}')

    def pci_whitelist(self):
        '''
        Formatted list of devices to whitelist for dpdk
        using the new style '--pci-whitelist' flag

        :rtype: str
        '''
        return self._formatted_whitelist('--pci-whitelist {device}')

    def __call__(self):
        ctxt = {}
        whitelist = self.device_whitelist()
        if whitelist:
            ctxt['dpdk_enabled'] = config('enable-dpdk')
            ctxt['device_whitelist'] = self.device_whitelist()
            ctxt['socket_memory'] = self.socket_memory()
            ctxt['cpu_mask'] = self.cpu_mask()
        return ctxt


SHARED_SECRET = "/etc/neutron/secret.txt"


def get_shared_secret():
    secret = None
    if not os.path.exists(SHARED_SECRET):
        secret = str(uuid.uuid4())
        write_file(SHARED_SECRET, secret,
                   perms=0o400)
    else:
        os.chmod(SHARED_SECRET, 0o400)
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret


class SharedSecretContext(OSContextGenerator):

    def __call__(self):
        if NeutronAPIContext()()['enable_dvr'] or \
                config('enable-local-dhcp-and-metadata'):
            ctxt = {
                'shared_secret': get_shared_secret(),
            }
        else:
            ctxt = {}
        return ctxt


class RemoteRestartContext(OSContextGenerator):

    def __init__(self, interfaces=None):
        self.interfaces = interfaces or ['neutron-plugin']

    def __call__(self):
        rids = []
        for interface in self.interfaces:
            rids.extend(relation_ids(interface))
        ctxt = {}
        for rid in rids:
            for unit in related_units(rid):
                remote_data = relation_get(
                    rid=rid,
                    unit=unit)
                for k, v in remote_data.items():
                    if k.startswith('restart-trigger'):
                        restart_key = k.replace('-', '_')
                        try:
                            ctxt[restart_key].append(v)
                        except KeyError:
                            ctxt[restart_key] = [v]
        for restart_key in ctxt.keys():
            ctxt[restart_key] = '-'.join(sorted(ctxt[restart_key]))
        return ctxt


class APIIdentityServiceContext(context.IdentityServiceContext):

    def __init__(self):
        super(APIIdentityServiceContext,
              self).__init__(rel_name='neutron-plugin-api')

    def __call__(self):
        ctxt = super(APIIdentityServiceContext, self).__call__()
        if not ctxt:
            return
        for rid in relation_ids('neutron-plugin-api'):
            for unit in related_units(rid):
                rdata = relation_get(rid=rid, unit=unit)
                ctxt['region'] = rdata.get('region')
                if ctxt['region']:
                    return ctxt
        return ctxt


class HostIPContext(context.OSContextGenerator):
    def __call__(self):
        ctxt = {}
        # Use the address used in the neutron-plugin subordinate relation
        host_ip = get_relation_ip('neutron-plugin')

        cmp_release = os_utils.CompareOpenStackReleases(
            os_utils.os_release('neutron-common', base='icehouse'))
        # the contents of the Neutron ``host`` configuration option is
        # referenced throughout a OpenStack deployment, an example being
        # Neutron port bindings.  It's value should not change after a
        # individual units initial deployment.
        #
        # We do want to migrate to using FQDNs so we enable this for new
        # installations.
        db = kv()
        if (db.get('neutron-ovs-charm-use-fqdn', False) and
                cmp_release >= 'stein' and
                host_ip):
            fqdn = socket.getfqdn(host_ip)
            if '.' in fqdn:
                # only populate the value if getfqdn() is able to find an
                # actual FQDN for this host.  If not, we revert back to
                # not setting the configuration option and use Neutron's
                # default behaviour.
                ctxt['host'] = fqdn
        return ctxt
