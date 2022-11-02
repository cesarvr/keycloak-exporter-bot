#!/usr/bin/env python

import logging
import argparse
import sys
import os

from kcapi import Keycloak, OpenID

# lib is the keycloak-exporter-bot main source directory
from lib.resource import Resource, ResourcePublisher, SingleResource
from lib.tools import bfs_folder, read_from_json

_level = logging.INFO
# _level = logging.DEBUG
logging.basicConfig(level=_level)
logger = logging.getLogger(__name__)

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def load_realm_empty(realm_name, keycloak_api, datadir, master_realm):
    # Just create an empty realm
    body = {
        'id': 'realm',
        'realm': realm_name,
    }
    return ResourcePublisher('realm', body).publish(master_realm)


def load_realm(realm_name, keycloak_api, datadir):
    # See testing_single_resource_class_creation
    # files = bfs_folder(datadir)
    realm_payload = os.path.join(datadir, f'{realm_name}/{realm_name}.json')

    params = {
        'path': realm_payload,
        'name': 'realm',
        'id': 'realm',
        'keycloak_api': keycloak_api,
        'realm': None,
    }
    # document = read_from_json(realm_payload)

    single_resource = SingleResource(params)

    creation_state = single_resource.publish()
    # self.assertTrue(creation_state, 'Publish operation should be completed')
    # created_realm = self.admin.findFirstByKV('realm', document['realm'])
    # self.assertIsNotNone(created_realm, "The realm should be created.")
    # self.assertEqual('acme', created_realm['emailTheme'], "The theme should be updated.")

def load_authentication_flow(realm_name, auth_flow_name, keycloak_api, datadir):
    # TODO SingleCustomAuthenticationResource
    payload = os.path.join(datadir, f'{realm_name}/authentication/{auth_flow_name}/{auth_flow_name}.json')

    params = {
        'path': payload,
        'name': 'authentication',
        'id': 'alias',
        'keycloak_api': keycloak_api,
        'realm': realm_name,
    }
    # document = read_from_json(realm_payload)

    single_resource = SingleResource(params)

    creation_state = single_resource.publish()



def main(args):
    logger.debug(f"args={args}")
    datadir = args.datadir

    token = OpenID.createAdminClient(args.username, args.password, url=args.url).getToken()
    keycloak_api = Keycloak(token, args.url)
    master_realm = keycloak_api.admin()

    load_realm_empty("4pl", keycloak_api, datadir, master_realm)
    load_authentication_flow("4pl", "adidas_first_broker_login", keycloak_api, datadir)
    load_realm("4pl", keycloak_api, datadir)


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
