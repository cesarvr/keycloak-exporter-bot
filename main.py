#!/usr/bin/env python

import logging
import argparse
import sys
import os
from glob import glob

from kcapi import Keycloak, OpenID

from kcloader.resource import ResourcePublisher, ManyResources, SingleResource, \
    SingleClientResource, SingleCustomAuthenticationResource, RoleResource, ClientScopeResource, \
    IdentityProviderResource, IdentityProviderMapperResource, UserFederationResource
from kcloader.tools import read_from_json

_level = logging.INFO
# _level = logging.DEBUG
logging.basicConfig(level=_level)
logger = logging.getLogger(__name__)

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def load_realm_empty(realm_name, keycloak_api, master_realm):
    # Just create an empty realm
    body = {
        'id': 'realm',
        'realm': realm_name,
    }
    return ResourcePublisher('realm', body).publish(master_realm)


def load_realm(realm_filepath, keycloak_api):
    # See testing_single_resource_class_creation
    # files = bfs_folder(datadir)
    # realm_filename = os.path.join(datadir, f'{realm_name}/{realm_name}.json')

    params = {
        'path': realm_filepath,
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


def load_authentication_flow(realm_name, auth_flow_filepath, keycloak_api):
    params = {
        'path': auth_flow_filepath,
        'name': 'authentication',
        'id': 'alias',
        'keycloak_api': keycloak_api,
        'realm': realm_name,
    }
    single_resource = SingleCustomAuthenticationResource(params)
    creation_state = single_resource.publish()


def load_client(realm_name, client_filepath, keycloak_api):
    params = {
        'path': client_filepath,
        'name': 'clients',
        'id': 'clientId',
        'keycloak_api': keycloak_api,
        'realm': realm_name,
    }
    single_resource = SingleClientResource(params)
    creation_state = single_resource.publish()


# def load_role(realm_name, role_filepath, keycloak_api):
#     params = {
#         'path': role_filepath,
#         'name': 'roles',
#         'id': 'name',
#         'keycloak_api': keycloak_api,
#         'realm': realm_name,
#     }
#     single_resource = SingleResource(params)
#     creation_state = single_resource.publish()


def main_4pl(args):
    logger.debug(f"args={args}")
    datadir = args.datadir

    token = OpenID.createAdminClient(args.username, args.password, url=args.url).getToken()
    keycloak_api = Keycloak(token, args.url)
    master_realm = keycloak_api.admin()

    load_realm_empty("4pl", keycloak_api, master_realm)
    load_authentication_flow("4pl", "adidas_first_broker_login", keycloak_api, datadir)
    load_realm("4pl", keycloak_api, datadir)


def main(args):
    logger.debug(f"args={args}")
    datadir = args.datadir
    realm_name = args.realm_name
    assert realm_name

    token = OpenID.createAdminClient(args.username, args.password, url=args.url).getToken()
    keycloak_api = Keycloak(token, args.url)
    master_realm = keycloak_api.admin()

    load_realm_empty(realm_name, keycloak_api, master_realm)
    # load_authentication_flow("4pl", "adidas_first_broker_login", keycloak_api, datadir)
    realm_filepath = os.path.join(datadir, f"{realm_name}/{realm_name}.json")  # often correct
    load_realm(realm_filepath, keycloak_api)

    # load all auth flows
    auth_flow_filepaths = glob(os.path.join(datadir, f"{realm_name}/authentication/*/*.json"))
    for auth_flow_filepath in auth_flow_filepaths:
        load_authentication_flow(realm_name, auth_flow_filepath, keycloak_api)

    # load identity providers
    idp_filepaths = glob(os.path.join(datadir, f"{realm_name}/identity-provider/*.json"))
    for idp_filepath in idp_filepaths:
        idp_params = {
            'path': idp_filepath,
            'name': 'identity-provider/instances',
            'id': 'alias',
            'keycloak_api': keycloak_api,
            'realm': realm_name,
        }
        idp_resource = IdentityProviderResource(idp_params)
        creation_state = idp_resource.publish()
    # ManyResources(idp_params, ResourceClass=IdentityProviderResource).publish()

    # load IdP mappers
    realm_doc = read_from_json(realm_filepath)
    idp_mappers = IdentityProviderMapperResource.create_from_realm_doc(realm_doc, keycloak_api, realm_name)
    for idp_mapper in idp_mappers:
        idp_mapper.publish()

    # User federations
    user_federation_filepaths = glob(os.path.join(datadir, f"{realm_name}/user-federations/*/*.json"))
    for user_federation_filepath in user_federation_filepaths:
        user_federation_param = {
            'path': user_federation_filepath,
            'name': 'components',
            'id': 'name',
            'keycloak_api': keycloak_api,
            'realm': realm_name,
        }
        user_federation_resource = UserFederationResource(user_federation_param)
        creation_state = user_federation_resource.publish()

    # load clients
    client_filepaths = glob(os.path.join(datadir, f"{realm_name}/clients/*/*.json"))
    # TODO move scope-mappings.json into subdirecotry ?
    for client_filepath in client_filepaths:
        # TODO move client-scopes into subdirecotry?
        if client_filepath.endswith("scope-mappings.json"):
            continue
        load_client(realm_name, client_filepath, keycloak_api)

    # load roles
    # role_filepaths = glob(os.path.join(datadir, f"{realm_name}/roles/*.json"))
    # for role_filepath in role_filepaths:
    #     load_role(realm_name, role_filepath, keycloak_api)
    roles = {
        'folder': os.path.join(datadir, f"{realm_name}/roles"),
        'name': 'roles',
        'id': 'name',
        'keycloak_api': keycloak_api,
        'realm': realm_name,
    }
    # TODO .composites needs to be computed
    # ManyResources(roles, ResourceClass=RoleResource).publish()
    role_filepaths = glob(os.path.join(datadir, f"{realm_name}/roles/*.json"))
    for role_filepath in role_filepaths:
        params = {
            'path': role_filepath,
            'name': 'roles',
            'id': 'name',
            'keycloak_api': keycloak_api,
            'realm': realm_name,
        }
        role_resource = RoleResource(params)
        creation_state = role_resource.publish_simple()
    # TODO realm role can contain client role.
    # TODO client role can contain realm role.
    for role_filepath in role_filepaths:
        params = {
            'path': role_filepath,
            'name': 'roles',
            'id': 'name',
            'keycloak_api': keycloak_api,
            'realm': realm_name,
        }
        role_resource = RoleResource(params)
        creation_state = role_resource.publish_composite()

    # setup client-scopes
    client_scope_filepaths = glob(os.path.join(datadir, f"{realm_name}/client-scopes/*.json"))
    for client_scope_filepath in client_scope_filepaths:
        params = {
            'path': client_scope_filepath,
            'name': 'client-scopes',
            'id': 'name',
            'keycloak_api': keycloak_api,
            'realm': realm_name,
        }
        client_scope_resource = ClientScopeResource(params)
        creation_state = client_scope_resource.publish()
        # TODO assign realm/client roles after they are created
        creation_state = client_scope_resource.publish_scope_mappings()

    # setup client composite roles
    for client_filepath in client_filepaths:
        # TODO move client-scopes into subdirecotry?
        if client_filepath.endswith("scope-mappings.json"):
            continue
        params = {
            'path': client_filepath,
            'name': 'clients',
            'id': 'clientId',
            'keycloak_api': keycloak_api,
            'realm': realm_name,
        }
        single_resource = SingleClientResource(params)
        creation_state = single_resource.publish_roles(include_composite=True)
        # also set defaultRoles
        single_resource.publish_self()


def main_try_sample_payloads(args):
    # call like
    # python3 main.py --url https://172.17.0.2:8443 --username admin --password admin --datadir test/sample_payloads
    logger.debug(f"args={args}")
    datadir = args.datadir

    token = OpenID.createAdminClient(args.username, args.password, url=args.url).getToken()
    keycloak_api = Keycloak(token, args.url)
    master_realm = keycloak_api.admin()

    # create realm
    realm_name = "realm-testing-acme"
    realm_filepath = os.path.join(datadir, f"realms/complex_realms.json")
    load_realm(realm_filepath, keycloak_api)
    # update realm
    realm_filepath = os.path.join(datadir, f"realms/complex_realms_update.json")
    load_realm(realm_filepath, keycloak_api)

    # load all auth flows
    auth_flow_filepaths = glob(os.path.join(datadir, f"authentication/*/*.json"))
    for auth_flow_filepath in auth_flow_filepaths:
        load_authentication_flow(realm_name, auth_flow_filepath, keycloak_api)

    # load clients
    client_filepaths = glob(os.path.join(datadir, f"clients/*/*.json"))
    for client_filepath in client_filepaths:
        load_client(realm_name, client_filepath, keycloak_api)

    # load roles
    role_filepaths = glob(os.path.join(datadir, f"roles/*.json"))
    for role_filepath in role_filepaths:
        load_role(realm_name, role_filepath, keycloak_api)
    # or use ManyResources(roles).publish()


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
    parser.add_argument('--realm-name', required=False,
                        default="",
                        help="Realm name to load")

    args = parser.parse_args(argv)
    return args


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    if os.environ.get("KEYCLOAK_API_CA_BUNDLE") == "":
        # disable annoying warning
        import requests
        requests.packages.urllib3.disable_warnings()

    args = arg_parse(sys.argv[1:])
    main(args)
    # main_try_sample_payloads(args)
