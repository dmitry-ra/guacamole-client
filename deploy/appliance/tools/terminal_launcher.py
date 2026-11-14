#!/usr/bin/env python3
"""Render a fixed-command, dedicated-socket tmux launcher; never install it."""
import argparse
from pathlib import PurePosixPath
import re
import shlex


def absolute(value):
    if not isinstance(value,str) or not re.fullmatch(r'/[a-zA-Z0-9_./-]+',value):
        raise ValueError('Literal absolute path required')
    path=PurePosixPath(value)
    if '..' in path.parts or str(path)!=value or value=='/' or value.startswith('//'):
        raise ValueError('Normalized non-root path required')
    return value


def render(*, launcher, socket, config, home, username, session='portal'):
    """The operator must protect launcher/config and the socket parent first.

    This uses the configured Unix account. A separate socket is not an account
    isolation boundary and must never be advertised as one.
    """
    launcher,socket,config,home=map(absolute,(launcher,socket,config,home))
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',username):
        raise ValueError('Literal Unix account required')
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}',session):
        raise ValueError('Literal tmux session required')
    if socket in (launcher,config) or launcher==config:
        raise ValueError('Distinct launcher, socket and configuration required')
    q=shlex.quote
    return ('#!/bin/sh\nset -eu\numask 077\n'
        'case "${SSH_ORIGINAL_COMMAND-}" in\n'
        '  '+q(launcher)+') ;;\n  *) exit 126 ;;\nesac\n'
        'unset TMUX TMUX_PANE SSH_AUTH_SOCK SSH_AGENT_PID\n'
        'exec /usr/bin/env -i '+q('HOME='+home)+' '+q('USER='+username)+' '
        +q('LOGNAME='+username)+' PATH=/usr/bin:/bin LANG=C.UTF-8 '
        'TERM="${TERM:-xterm-256color}" '
        '/usr/bin/tmux -S '+q(socket)+' -f '+q(config)
        +' new-session -A -s '+q(session)+' '+q('/bin/bash --noprofile --norc')+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('launcher','socket','config','home','username'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--session',default='portal')
    print(render(**vars(parser.parse_args())),end='')


if __name__=='__main__':main()
