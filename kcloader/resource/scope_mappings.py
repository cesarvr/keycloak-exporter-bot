# import json
import logging
import sys

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


class BaseScopeMappingsRealmManager(BaseManager):
    # _resource_name = "client-scopes/{client_scope_id}/scope-mappings/realm"
    # _resource_name = "clients/{client_id}/scope-mappings/realm"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = []

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,
                 ):
        assert isinstance(requested_doc, list)
        if requested_doc:
            assert isinstance(requested_doc[0], str)
        super().__init__(keycloak_api, realm, datadir)
        # Manager will directly update the links - less REST calls.
        # A single ClientScopeScopeMappingsRealmCRUD will be enough.
        self.realm_roles_api = keycloak_api.build("roles", realm)
        self._cssm_realm_doc = requested_doc

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
        return self._cssm_realm_doc


class ClientScopeScopeMappingsRealmManager(BaseScopeMappingsRealmManager):
    _resource_name = "client-scopes/{client_scope_id}/scope-mappings/realm"

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,
                 client_scope_id: str,
                 ):
        self._client_scope_id = client_scope_id
        super().__init__(keycloak_api, realm, datadir, requested_doc=requested_doc)

    def _get_resource_api(self):
        client_scopes_api = self.keycloak_api.build("client-scopes", self.realm)
        resource_api = client_scopes_api.scope_mappings_realm_api(client_scope_id=self._client_scope_id)
        return resource_api


class ClientScopeMappingsRealmManager(BaseScopeMappingsRealmManager):
    _resource_name = "clients/{client_id}/scope-mappings/realm"

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,
                 client_id: str,
                 ):
        self._client_id = client_id
        super().__init__(keycloak_api, realm, datadir, requested_doc=requested_doc)

    def _get_resource_api(self):
        clients_api = self.keycloak_api.build("clients", self.realm)
        resource_api = KeycloakCRUD.get_child(clients_api, self._client_id, "scope-mappings/realm")
        return resource_api


class BaseScopeMappingsAllClientsManager:
    def publish(self):
        status_created = [
            resource.publish()
            for resource in self.resources
        ]
        return any(status_created)


class ClientScopeScopeMappingsAllClientsManager(BaseScopeMappingsAllClientsManager):
    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,  # dict read from json files, only part relevant clients mappings
                 client_scope_id: int,
                 ):
        # super().__init__(keycloak_api, realm, datadir)  #, requested_doc=requested_doc, client_scope_id=client_scope_id)
        assert isinstance(requested_doc, dict)

        # Create a manager for each client.
        clients_api = keycloak_api.build("clients", realm)
        clients = clients_api.all()
        self.resources = [
            ClientScopeScopeMappingsClientManager(
                keycloak_api,
                realm,
                datadir,
                requested_doc=requested_doc.get(src_client["clientId"], []),
                client_scope_id=client_scope_id,
                src_client_id=src_client["id"],
                )
            for src_client in clients
        ]
        # List of clients is retrieved from server (not from json files) -
        # code assumes all clients were already created on server!
        # If there is in json file some unknown clientId - report to log, and exit with error.
        clientIds = [client["clientId"] for client in clients]
        for doc_clientId in requested_doc:
            if doc_clientId not in clientIds:
                msg = f"clientID={doc_clientId} not present on server"
                logger.error(msg)
                raise Exception(msg)


class ClientScopeMappingsAllClientsManager(BaseScopeMappingsAllClientsManager):
    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,  # dict read from json files, only part relevant clients mappings
                 client_id: int,
                 ):
        assert isinstance(requested_doc, dict)

        # Create a manager for each client.
        clients_api = keycloak_api.build("clients", realm)
        clients = clients_api.all()
        self.resources = [
            ClientScopeMappingsClientManager(
                keycloak_api,
                realm,
                datadir,
                requested_doc=requested_doc.get(src_client["clientId"], []),
                dest_client_id=client_id,
                src_client_id=src_client["id"],
                )
            for src_client in clients
        ]
        # List of clients is retrieved from server (not from json files) -
        # code assumes all clients were already created on server!
        # If there is in json file some unknown clientId - report to log, and exit with error.
        clientIds = [client["clientId"] for client in clients]
        for doc_clientId in requested_doc:
            if doc_clientId not in clientIds:
                msg = f"clientID={doc_clientId} not present on server"
                logger.error(msg)
                raise Exception(msg)


class BaseScopeMappingsClientManager(BaseManager):
    # _resource_name = "client-scopes/{client_scope_id}/scope-mappings/clients/{src_client_id}"
    # _resource_name = "clients/{dest_client_id}/scope-mappings/clients/{src_client_id}"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = []

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,  # dict read from json files, only part relevant for this client-scope - client mapping
                 src_client_id: int,
                 ):
        # requested_doc is a list of client role names
        assert isinstance(requested_doc, list)
        if requested_doc:
            assert isinstance(requested_doc[0], str)
        self._requested_doc = requested_doc
        self._src_client_id = src_client_id
        super().__init__(keycloak_api, realm, datadir)

        clients_api = keycloak_api.build("clients", realm)
        src_client_query = dict(key="id", value=self._src_client_id)
        self._src_client_roles_api = clients_api.roles(src_client_query)

    def publish(self):
        create_ids, delete_objs = self._difference_ids()

        client_roles = self._src_client_roles_api.all()
        create_roles = [rr for rr in client_roles if rr["name"] in create_ids]
        if len(create_roles) != len(create_ids):
            to_be_created_ids = [rr["name"] for rr in create_roles]
            missing_role_ids = set(create_ids) - set(to_be_created_ids)
            ## extra_msg = f" GET URL: " + str(self.resource_api.targets.targets["read"])
            extra_msg = f" GET URL: " + str(self._src_client_roles_api.targets.targets["read"])
            logger.error(f"scope-mappings setup cannot assign roles {missing_role_ids} - they are missing." + extra_msg)
            # likely this would work on second pass. But make problem obvious.
            sys.exit(1)
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
        return self._requested_doc


class ClientScopeScopeMappingsClientManager(BaseScopeMappingsClientManager):
    _resource_name = "client-scopes/{client_scope_id}/scope-mappings/clients/{src_client_id}"

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,  # dict read from json files, only part relevant for this client-scope - client mapping
                 client_scope_id: int,
                 src_client_id: int,
                 ):
        self._client_scope_id = client_scope_id
        super().__init__(keycloak_api, realm, datadir, requested_doc=requested_doc, src_client_id=src_client_id)

    def _get_resource_api(self):
        client_scopes_api = self.keycloak_api.build("client-scopes", self.realm)
        resource_api = client_scopes_api.scope_mappings_client_api(
            client_scope_id=self._client_scope_id,
            client_id=self._src_client_id,
        )
        return resource_api


class ClientScopeMappingsClientManager(BaseScopeMappingsClientManager):
    _resource_name = "clients/{dest_client_id}/scope-mappings/clients/{src_client_id}"

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *,
                 requested_doc: dict,  # dict read from json files, only part relevant for this client-scope - client mapping
                 dest_client_id: int,
                 src_client_id: int,
                 ):
        self._dest_client_id = dest_client_id
        super().__init__(keycloak_api, realm, datadir, requested_doc=requested_doc, src_client_id=src_client_id)

    def _get_resource_api(self):
        clients_api = self.keycloak_api.build("clients", self.realm)
        resource_api = KeycloakCRUD.get_child(clients_api, self._dest_client_id, f"scope-mappings/clients/{self._src_client_id}")
        return resource_api
