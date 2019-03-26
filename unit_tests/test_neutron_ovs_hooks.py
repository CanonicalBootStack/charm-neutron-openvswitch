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

from mock import ANY, MagicMock, patch, mock_open

from test_utils import CharmTestCase

with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'neutron'
    import neutron_ovs_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

import neutron_ovs_hooks as hooks

utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
    'create_sysctl',
    'config',
    'CONFIGS',
    'get_shared_secret',
    'log',
    'relation_ids',
    'relation_set',
    'configure_ovs',
    'configure_sriov',
    'use_dvr',
    'use_l3ha',
    'install_packages',
    'install_l3ha_packages',
    'purge_packages',
    'enable_nova_metadata',
    'enable_local_dhcp',
    'install_tmpfilesd',
    'purge_packages',
    'determine_purge_packages',
]
NEUTRON_CONF_DIR = "/etc/neutron"

NEUTRON_CONF = '%s/neutron.conf' % NEUTRON_CONF_DIR


class NeutronOVSHooksTests(CharmTestCase):

    def setUp(self):
        super(NeutronOVSHooksTests, self).setUp(hooks, TO_PATCH)

        self.config.side_effect = self.test_config.get
        hooks.hooks._config_save = False

    def _call_hook(self, hookname):
        hooks.hooks.execute([
            'hooks/{}'.format(hookname)])

    def test_install_hook(self):
        self._call_hook('install')
        self.install_packages.assert_called_with()

    @patch.object(hooks, 'restart_map')
    @patch.object(hooks, 'restart_on_change')
    def test_migrate_ovs_default_file(self, mock_restart, mock_restart_map):
        # Tests that the /etc/default/openvswitch-switch file is/isn't
        # migrated on the upgrade-charm hook and that no restarts are
        # attempted of the openvswitch-switch service.
        tests = [
            ('package-provided-openvswitch-switch', True),
            ('16.07-dpdk-openvswitch-switch', True),
            ('16.10-openvswitch-switch', False),
        ]
        for sample, should_migrate in tests:
            self.CONFIGS.write.reset_mock()
            with open('unit_tests/%s' % sample, 'r') as f:
                content = f.read()

            for ovs_default_exists in [False, True]:
                if ovs_default_exists:
                    mock_restart_map.return_value = {utils.OVS_DEFAULT: {}}
                else:
                    mock_restart_map.return_value = {}

                with patch('builtins.open', mock_open(read_data=content),
                           create=True):
                    self.CONFIGS.write.reset_mock()
                    self._call_hook('upgrade-charm')
                    if should_migrate and ovs_default_exists:
                        self.CONFIGS.write.assert_called_with(
                            utils.OVS_DEFAULT)
                    else:
                        self.CONFIGS.write.assert_not_called()
                    self.assertEqual(0, mock_restart.call_count)

    def test_config_changed_dvr(self):
        self._call_hook('config-changed')
        self.install_packages.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        self.configure_ovs.assert_called_with()

    def test_config_changed_sysctl_overrides(self):
        self.test_config.set(
            'sysctl',
            '{foo : bar}'
        )
        self._call_hook('config-changed')
        self.create_sysctl.assert_called_with(
            '{foo : bar}',
            '/etc/sysctl.d/50-openvswitch.conf')

    @patch.object(hooks, 'neutron_plugin_joined')
    def test_config_changed_rocky_upgrade(self, _plugin_joined):
        self.determine_purge_packages.return_value = ['python-neutron']
        self.relation_ids.return_value = ['neutron-plugin:42']
        self._call_hook('config-changed')
        self.install_packages.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        self.configure_ovs.assert_called_with()
        self.purge_packages.assert_called_with(['python-neutron'])
        _plugin_joined.assert_called_with(
            relation_id='neutron-plugin:42',
            request_restart=True)

    @patch.object(hooks, 'os_release')
    @patch.object(hooks, 'neutron_plugin_joined')
    def test_neutron_plugin_api(self, _plugin_joined, _os_release):
        _os_release.return_value = 'newton'
        self.use_dvr.return_value = True
        self.use_l3ha.return_value = False
        self.relation_ids.return_value = ['rid']
        self._call_hook('neutron-plugin-api-relation-changed')
        self.configure_ovs.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        _plugin_joined.assert_called_with(relation_id='rid')
        self.install_packages.assert_called_with()

    @patch.object(hooks, 'neutron_plugin_joined')
    def test_neutron_plugin_api_nodvr(self, _plugin_joined):
        self.use_dvr.return_value = False
        self.use_l3ha.return_value = False
        self.relation_ids.return_value = ['rid']
        self._call_hook('neutron-plugin-api-relation-changed')
        self.configure_ovs.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        _plugin_joined.assert_called_with(relation_id='rid')
        self.purge_packages.assert_called_with(['neutron-l3-agent',
                                                'keepalived'])

    def test_neutron_plugin_joined_dvr_dhcp(self):
        self.enable_nova_metadata.return_value = True
        self.enable_local_dhcp.return_value = True
        self.use_dvr.return_value = True
        self.get_shared_secret.return_value = 'secret'
        self._call_hook('neutron-plugin-relation-joined')
        rel_data = {
            'metadata-shared-secret': 'secret',
        }
        self.relation_set.assert_called_with(
            relation_id=None,
            **rel_data
        )
        self.assertTrue(self.install_packages.called)

    def test_neutron_plugin_joined_dvr_nodhcp(self):
        self.enable_nova_metadata.return_value = True
        self.enable_local_dhcp.return_value = False
        self.use_dvr.return_value = True
        self.get_shared_secret.return_value = 'secret'
        self._call_hook('neutron-plugin-relation-joined')
        rel_data = {
            'metadata-shared-secret': 'secret',
        }
        self.relation_set.assert_called_with(
            relation_id=None,
            **rel_data
        )
        self.purge_packages.assert_called_with(['neutron-dhcp-agent'])
        self.assertFalse(self.install_packages.called)

    def test_neutron_plugin_joined_nodvr_nodhcp(self):
        self.enable_nova_metadata.return_value = False
        self.enable_local_dhcp.return_value = False
        self.use_dvr.return_value = False
        self.get_shared_secret.return_value = 'secret'
        self._call_hook('neutron-plugin-relation-joined')
        rel_data = {
            'metadata-shared-secret': None,
        }
        self.relation_set.assert_called_with(
            relation_id=None,
            **rel_data
        )
        self.purge_packages.assert_called_with(['neutron-dhcp-agent',
                                                'neutron-metadata-agent'])
        self.assertFalse(self.install_packages.called)

    @patch.object(hooks, 'os_release')
    @patch.object(hooks, 'neutron_plugin_joined')
    def test_neutron_plugin_api_dvr_no_l3ha(self, _plugin_joined, _os_release):
        _os_release.return_value = 'newton'
        self.use_dvr.return_value = True
        self.use_l3ha.return_value = False
        self.relation_ids.return_value = ['rid']
        self._call_hook('neutron-plugin-api-relation-changed')
        self.configure_ovs.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        _plugin_joined.assert_called_with(relation_id='rid')
        self.purge_packages.assert_not_called()

    @patch.object(hooks, 'os_release')
    @patch.object(hooks, 'neutron_plugin_joined')
    def test_neutron_plugin_api_dvr_l3ha(self, _plugin_joined, _os_release):
        _os_release.return_value = 'newton'
        self.use_dvr.return_value = True
        self.use_l3ha.return_value = True
        self.relation_ids.return_value = ['rid']
        self._call_hook('neutron-plugin-api-relation-changed')
        self.configure_ovs.assert_called_with()
        self.assertTrue(self.CONFIGS.write_all.called)
        _plugin_joined.assert_called_with(relation_id='rid')
        self.install_packages.assert_called_with()
        self.install_l3ha_packages.assert_called_with()

    def test_amqp_joined(self):
        self._call_hook('amqp-relation-joined')
        self.relation_set.assert_called_with(
            username='neutron',
            vhost='openstack',
            relation_id=None
        )

    def test_amqp_changed(self):
        self.CONFIGS.complete_contexts.return_value = ['amqp']
        self._call_hook('amqp-relation-changed')
        self.assertTrue(self.CONFIGS.write.called_with(NEUTRON_CONF))

    def test_amqp_departed(self):
        self._call_hook('amqp-relation-departed')
        self.assertTrue(self.CONFIGS.write.called_with(NEUTRON_CONF))

    @patch('os.path.exists')
    @patch('shutil.copy2')
    @patch('neutron_ovs_hooks.nrpe')
    def test_update_nrpe_config(self, mock_nrpe,
                                mock_copy2, mock_path_exists):
        mock_copy2.return_value = True
        mock_path_exists.return_value = True
        self._call_hook('nrpe-external-master-relation-changed')
        mock_nrpe.add_init_service_checks.assert_called_with(
            ANY,
            ['openvswitch-switch', 'neutron-plugin-openvswitch-agent'],
            ANY)
