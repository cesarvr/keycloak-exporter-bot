#!/usr/bin/env python

import logging
import argparse
import sys

_level = logging.INFO
# _level = logging.DEBUG
logging.basicConfig(level=_level)
logger = logging.getLogger(__name__)

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def main(args):
    logger.debug(f"args={args}")

def arg_parse(argv):
    parser = argparse.ArgumentParser(description='Import data into RedHat SSO (Keycloak)')

    sso_group = parser.add_argument_group('sso')
    sso_group.add_argument('--url', required=True,
                           help="Keycloak API URL")
    sso_group.add_argument('--username', required=True,
                           help="Admin user username. Administrator rights are required.")
    sso_group.add_argument('--password', required=True,
                           help="Admin user password")

    parser.add_argument('--datadir', required=True,
                        help="Directory with data dump")

    args = parser.parse_args(argv)
    return args


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    args = arg_parse(sys.argv[1:])
    main(args)
