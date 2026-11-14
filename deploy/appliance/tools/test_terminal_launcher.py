"""Fixed command admission executes before tmux; no host tmux is started."""
import os
import subprocess
import unittest

import terminal_launcher as launcher


class LauncherTests(unittest.TestCase):
    def arguments(self):
        return dict(launcher='/usr/local/libexec/portal-tmux',
            socket='/var/lib/portal-terminal/tmux/socket',
            config='/etc/portal-terminal/tmux.conf',home='/var/lib/portal-terminal',
            username='terminal')

    def test_missing_or_unexpected_original_command_exits_before_tmux(self):
        source=launcher.render(**self.arguments())
        for value in (None,'','id','/usr/local/libexec/portal-tmux x',
                      '/usr/local/libexec/portal-tmux\nid'):
            env={'PATH':'/nonexistent'}
            if value is not None:env['SSH_ORIGINAL_COMMAND']=value
            result=subprocess.run(['/bin/sh'],input=source.encode(),env=env,
                capture_output=True,timeout=2)
            self.assertEqual(result.returncode,126)
            self.assertEqual(result.stdout,b'')
            self.assertEqual(result.stderr,b'')

    def test_rendered_command_is_valid_shell_and_uses_only_explicit_tmux(self):
        source=launcher.render(**self.arguments())
        subprocess.run(['/bin/sh','-n'],input=source.encode(),check=True,timeout=2)
        self.assertIn('unset TMUX TMUX_PANE SSH_AUTH_SOCK SSH_AGENT_PID',source)
        self.assertIn('/usr/bin/env -i',source)
        self.assertIn('/usr/bin/tmux -S /var/lib/portal-terminal/tmux/socket -f /etc/portal-terminal/tmux.conf',source)
        self.assertIn("'/bin/bash --noprofile --norc'",source)

    def test_unsafe_or_aliasing_configuration_is_rejected(self):
        for field,value in [('launcher','/tmp/x;id'),('socket','/x/../socket'),
                ('home','/'),('config','//etc/config'),('username','x\nid'),
                ('session','x;id'),('socket','/etc/portal-terminal/tmux.conf')]:
            args=self.arguments();args[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                launcher.render(**args)


if __name__=='__main__':unittest.main()
