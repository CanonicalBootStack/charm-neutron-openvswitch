from unittest import TestCase
from mock import patch

import files.nrpe.check_ovs_tunnels as check_ovs_tunnels


class TestCheckOVSTunnels(TestCase):

    @patch('configparser.RawConfigParser.read')
    def test_get_creds(self, mock_config):

        class a:
            pass

        args = a()
        args.conf_file = 'unittest-nova.conf'

        mock_config.return_value = 'something'
        check_ovs_tunnels.get_creds(args)

        self.fail()
