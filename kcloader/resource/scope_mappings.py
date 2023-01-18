# import json
import logging
# import os
# from copy import copy
# from glob import glob

import kcapi
from kcapi.rest.crud import KeycloakCRUD

# from sortedcontainers import SortedDict
#
# from kcloader.resource import SingleResource
# from kcloader.tools import find_in_list, read_from_json
from kcloader.resource.base_manager import BaseManager

logger = logging.getLogger(__name__)


class RealmClientScopeScopeMappingsRealmManager(BaseManager):
    _resource_name = "client-scopes/{client_scope_id}/scope-mappings/realm"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = []

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,
                 # client_scope_name: str,
                 client_scope_id: str,
                 ):
        # Manager will directly update the links - less REST calls.
        # A single ClientScopeScopeMappingsRealmCRUD will be enough.
        client_scopes_api = keycloak_api.build("client-scopes", realm)
        self.realm_roles_api = keycloak_api.build("roles", realm)
        self.resource_api = client_scopes_api.scope_mappings_realm_api(client_scope_id=client_scope_id)
        assert list(requested_doc.keys()) in [["roles"], []]
        assert isinstance(requested_doc.get("roles", []), list)
        self.cssm_realm_doc = requested_doc

    def publish(self):
        create_ids, delete_objs = self._difference_ids()

        realm_roles = self.realm_roles_api.all(
            params=dict(briefRepresentation=True)
        )
        create_roles = [rr for rr in realm_roles if rr["name"] in create_ids]
        status_created = False
        if create_roles:
            self.resource_api.create(create_roles).isOk()
            status_created = True

        status_deleted = False
        if delete_objs:
            self.resource_api.remove(None, delete_objs).isOk()
            status_deleted = True

        return any([status_created, status_deleted])

    def _object_docs_ids(self):
        file_ids = self.cssm_realm_doc.get("roles", [])
        return file_ids


class ClientClientScopeScopeMappingsRealmManager(RealmClientScopeScopeMappingsRealmManager):
    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,
                 # client_scope_name: str,
                 client_id: str,
                 ):
        # Manager will directly update the links - less REST calls.
        # A single ClientScopeScopeMappingsRealmCRUD will be enough.
        clients_api = keycloak_api.build("clients", realm)
        self.realm_roles_api = keycloak_api.build("roles", realm)

        # self.resource_api = client_scopes_api.scope_mappings_realm_api(client_scope_id=client_scope_id)
        self.resource_api = KeycloakCRUD.get_child(clients_api, client_id, "scope-mappings/realm")

        assert isinstance(requested_doc, list)
        if requested_doc:
            assert isinstance(requested_doc[0], str)
        self.cssm_realm_doc = requested_doc

    def _object_docs_ids(self):
        return self.cssm_realm_doc


class RealmClientScopeScopeMappingsAllClientsManager:
    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,  # dict read from json files, only part relevant clients mappings
                 client_scope_id: int,
                 ):
        assert isinstance(requested_doc, dict)
        # self._client_scope_id = client_scope_id
        # self._cssm_clients_doc = requested_doc

        # create a manager for each client
        clients_api = keycloak_api.build("clients", realm)
        clients = clients_api.all()
        self.resources = [
            RealmClientScopeScopeMappingsClientManager(
                keycloak_api,
                realm,
                datadir,
                requested_doc=requested_doc.get(client["clientId"], []),
                client_scope_id=client_scope_id,
                client_id=client["id"],
                )
            for client in clients
        ]

        # We assume all clients were already created.
        # If there is in json file some unknown clientId - it will be ignored.
        # Write this to logfile.
        clientIds = [client["clientId"] for client in clients]
        for doc_clientId in requested_doc:
            if doc_clientId not in clientIds:
                msg = f"clientID={doc_clientId} not present on server"
                logger.error(msg)
                raise Exception(msg)

    def publish(self):
        status_created = [
            resource.publish()
            for resource in self.resources
        ]
        return any(status_created)

    def _difference_ids(self):
        # Not needed for this class.
        raise NotImplementedError()


class RealmClientScopeScopeMappingsClientManager(BaseManager):
    _resource_name = "client-scopes/{client_scope_id}/scope-mappings/clients/{client_id}"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = []

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,  # dict read from json files, only part relevant for this client-scope - client mapping
                 client_scope_id: int,
                 client_id: int,
                 ):
        # self._client_scope_doc = client_scope_doc
        self._client_scope_id = client_scope_id
        self._client_id = client_id

        # Manager will directly update the links - less REST calls.
        # A single ClientScopeScopeMappingsRealmCRUD will be enough.
        client_scopes_api = keycloak_api.build("client-scopes", realm)
        clients_api = keycloak_api.build("clients", realm)
        client_query = dict(key="id", value=client_id)
        self._this_client_roles_api = clients_api.roles(client_query)

        self.resource_api = client_scopes_api.scope_mappings_client_api(client_scope_id=client_scope_id, client_id=client_id)
        assert isinstance(requested_doc, list)
        if requested_doc:
            assert isinstance(requested_doc[0], str)
        self.cssm_client_doc = requested_doc  # list of client role names

    def publish(self):
        create_ids, delete_objs = self._difference_ids()

        client_roles = self._this_client_roles_api.all()
        create_roles = [rr for rr in client_roles if rr["name"] in create_ids]
        status_created = False
        if create_roles:
            self.resource_api.create(create_roles).isOk()
            status_created = True

        status_deleted = False
        if delete_objs:
            self.resource_api.remove(None, delete_objs).isOk()
            status_deleted = True

        return any([status_created, status_deleted])

    def _object_docs_ids(self):
        # we already have role names, just return the list
        file_ids = self.cssm_client_doc
        return file_ids


