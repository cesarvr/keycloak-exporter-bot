#!/usr/bin/env python
# kctransform/main.py --input test/data/kcfetcher-0.0.8 --output test/data/kcfetcher-0.0.8-new --vars kctransform/ci0-rules.yml

import logging
import argparse
import sys
import os

from kcfetcher.utils import normalize

_level = logging.INFO
_level = logging.DEBUG
logging.basicConfig(level=_level)
logger = logging.getLogger(__name__)


def main(args):
    logger.debug(f"args={args}")
    # just a mockup


def arg_parse(argv):
    parser = argparse.ArgumentParser(
        description="""
        Modify Keycloak datadump generated kcfetcher to make is suitable
         for loading into a different Keycloak server.
        """)

    parser.add_argument('--input', required=True,
                        help="Directory with input data dump")
    parser.add_argument('--output', required=True,
                        help="Directory for output data dump")
    parser.add_argument('--vars', required=True,
                        help="Variables (URLs etc.) for modifications")
    parser.add_argument('--realm-name', required=False,
                        default="",
                        help="Realm to modify")

    args = parser.parse_args(argv)
    return args


if __name__ == '__main__':
    if os.environ.get("KEYCLOAK_API_CA_BUNDLE") == "":
        # disable annoying warning
        import requests
        requests.packages.urllib3.disable_warnings()

    args = arg_parse(sys.argv[1:])
    main(args)
