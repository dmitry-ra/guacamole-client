#!/usr/bin/env python3
"""Prepare/review/apply additive client forwards; never restart the tunnel."""
from upgrade_transport_server import main


if __name__ == '__main__':
    main('client')
