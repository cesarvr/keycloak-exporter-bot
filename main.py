#!/usr/bin/env python

import logging
import argparse
import sys
import os

from kcapi import Keycloak, OpenID
from kcfetcher.utils import normalize
from kcloader.resource import \
    RealmResource, ClientScopeManager, \
    DefaultDefaultClientScopeManager, DefaultOptionalClientScopeManager, \
    UserFederationManager, AuthenticationFlowManager
from kcloader.resource import IdentityProviderManager, ClientManager, RealmRoleManager
from kcloader.resource.group_resource import GroupManager
from kcloader.tools import read_from_json

_level = logging.INFO
_level = logging.DEBUG
logging.basicConfig(level=_level)
logger = logging.getLogger(__name__)


def main(args):
    logger.debug(f"args={args}")
    datadir = args.datadir
    realm_name_commandline = args.realm_name
    assert realm_name_commandline

    token = OpenID.createAdminClient(args.username, args.password, url=args.url).getToken()
    keycloak_api = Keycloak(token, args.url)
    master_realm = keycloak_api.admin()

    normalized_realm_name = normalize(realm_name_commandline)
    realm_filepath = os.path.join(datadir, f"{normalized_realm_name}/{normalized_realm_name}.json")  # often correct
    realm_name = read_from_json(realm_filepath)["realm"]
    realm_res = RealmResource({
        'path': realm_filepath,
        # 'name': '',
        # 'id': 'realm',
        'keycloak_api': keycloak_api,
        'realm': realm_name,
    })
    # ==========================================================================
    # BEGIN copy-paste
    # create realm before mangers
    states = list()
    states.append(realm_res.publish(minimal_representation=True))

    auth_manager = AuthenticationFlowManager(keycloak_api, realm_name, datadir)
    idp_manager = IdentityProviderManager(keycloak_api, realm_name, datadir)
    uf_manager = UserFederationManager(keycloak_api, realm_name, datadir)
    group_manager = GroupManager(keycloak_api, realm_name, datadir)
    client_manager = ClientManager(keycloak_api, realm_name, datadir)
    realm_role_manager = RealmRoleManager(keycloak_api, realm_name, datadir)
    client_scope_manager = ClientScopeManager(keycloak_api, realm_name, datadir)
    default_default_client_scope_manager = DefaultDefaultClientScopeManager(keycloak_api, realm_name, datadir)
    default_optional_client_scope_manager = DefaultOptionalClientScopeManager(keycloak_api, realm_name, datadir)

    # --------------------------------------------
    # Pass 1 - create minimal realm, simple roles, etc
    states.append(auth_manager.publish())
    states.append(idp_manager.publish())
    states.append(uf_manager.publish())
    states.append(realm_role_manager.publish(include_composite=False))
    states.append(client_manager.publish(include_composite=False))
    states.append(group_manager.publish())
    # new client_scopes are not yet created, we need setup_new_links=False.
    states.append(default_default_client_scope_manager.publish(setup_new_links=False))
    states.append(default_optional_client_scope_manager.publish(setup_new_links=False))
    states.append(client_scope_manager.publish(include_scope_mappings=False))

    # ---------------------------------
    # Pass 2, resolve circular dependencies
    states.append(realm_res.publish(minimal_representation=True))
    states.append(realm_role_manager.publish(include_composite=True))
    states.append(client_manager.publish(include_composite=True))
    states.append(default_default_client_scope_manager.publish(setup_new_links=True))
    states.append(default_optional_client_scope_manager.publish(setup_new_links=True))
    states.append(client_scope_manager.publish(include_scope_mappings=True))
    # END copy-paste
    # ==========================================================================

    # logger.info(f"states={states}")
    changed_state_ind = [ii for ii,state in enumerate(states) if state]
    logger.info(f"changed_state_ind={changed_state_ind}")
    return


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
