"""Host-inert checks for restricted transport configuration rendering."""
import base64
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('transport', Path(__file__).parent/'tools/render_transport.py')
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


class TransportTests(unittest.TestCase):
    def config(self):
        key = 'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+bytes(32)).decode()
        return dict(schema=1, client_address='192.0.2.10', server_address='192.0.2.20',
                    server_port=22, listen_address='10.55.0.1', listen_port=10473,
                    target_address='192.168.50.10', target_port=3389,
                    public_key=key, host_key=key)

    def test_local_tcp_only_and_pinned_supervised_client(self):
        files = transport.render(self.config())
        for requirement in ('AllowTcpForwarding local', 'AllowStreamLocalForwarding no',
                            'PermitListen none', 'PermitOpen 192.168.50.10:3389',
                            'MaxSessions 0', 'PasswordAuthentication no'):
            self.assertIn(requirement, files['sshd.conf'])
        self.assertIn('from="192.0.2.10",restrict,port-forwarding,', files['authorized_keys'])
        self.assertIn('LocalForward 10.55.0.1:10473 192.168.50.10:3389', files['client.conf'])
        self.assertIn('StrictHostKeyChecking yes', files['client.conf'])
        self.assertIn('/usr/bin/ssh -N -F ', files['portal-rdp-transport.service'])

    def test_invalid_configuration_cannot_inject_ssh_options(self):
        for key, invalid in [('schema', True), ('server_address', '192.0.2.20\nProxyCommand bad'),
                             ('listen_address', '0.0.0.0'), ('listen_address', '8.8.8.8'),
                             ('server_port', True), ('target_port', 0),
                             ('public_key', 'ssh-ed25519 AAAA\ncommand=bad')]:
            with self.subTest(key=key, invalid=invalid):
                config = self.config(); config[key] = invalid
                with self.assertRaises((ValueError, TypeError)):
                    transport.render(config)

    def mixed(self):
        old = self.config()
        forward_keys = ('listen_address', 'listen_port', 'target_address', 'target_port')
        current = {key: value for key, value in old.items() if key not in forward_keys}
        current['schema'] = 2
        current['forwards'] = [{key: old[key] for key in forward_keys},
            dict(listen_address='10.55.0.1', listen_port=10475,
                 target_address='192.168.50.1', target_port=22)]
        return current

    def test_schema1_matches_equivalent_schema2_exactly(self):
        current = self.mixed()
        current['forwards'] = current['forwards'][:1]
        self.assertEqual(transport.render(self.config()), transport.render(current))

    def test_mixed_has_exact_two_forwards_and_retains_every_restriction(self):
        output = transport.render(self.mixed())
        self.assertIn('PermitOpen 192.168.50.10:3389 192.168.50.1:22\n', output['sshd.conf'])
        self.assertEqual(output['authorized_keys'].count('permitopen='), 2)
        self.assertEqual(output['client.conf'].count('LocalForward '), 2)
        for name in ('known_hosts', 'portal-rdp-transport.service'):
            self.assertEqual(output[name], transport.render(self.config())[name])
        for requirement in ('MaxSessions 0', 'PermitTTY no', 'PermitListen none',
                            'AllowAgentForwarding no', 'AllowStreamLocalForwarding no'):
            self.assertIn(requirement, output['sshd.conf'])

    def test_schema2_bounds_duplicate_endpoints_interfaces_and_unknown_fields(self):
        for forwards in ([], None, self.mixed()['forwards'] * 5,
                         [self.mixed()['forwards'][0]] * 2,
                         [{**self.mixed()['forwards'][0], 'extra': 1}],
                         [self.mixed()['forwards'][0], {**self.mixed()['forwards'][1], 'listen_address': '10.55.0.2'}],
                         [self.mixed()['forwards'][0], {**self.mixed()['forwards'][1], 'listen_port': 10473}],
                         [{**self.mixed()['forwards'][0], 'target_address': True}]):
            config = self.mixed()
            config['forwards'] = forwards
            with self.subTest(forwards=forwards), self.assertRaises(ValueError):
                transport.render(config)


if __name__ == '__main__':
    unittest.main()
