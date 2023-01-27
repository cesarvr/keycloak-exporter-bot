import json
import logging
import os
from copy import copy
from glob import glob

import kcapi
from kcapi.rest.crud import KeycloakCRUD
from kcfetcher.utils import normalize
from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list, read_from_json
from kcloader.resource.base_manager import BaseManager

logger = logging.getLogger(__name__)


class BaseDefaultClientScopeManager(BaseManager):
    # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/default-default-client-scopes/ee3a3fed-af78-4c04-b9d9-3fc1b614a0a2
    # _resource_name = "default-default-client-scopes"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = []

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str):
        """
        requested_doc is like '["ci0-client-scope", "email", ...]'
        """
        super().__init__(keycloak_api, realm, datadir)
        self.client_scopes_api = keycloak_api.build("client-scopes", realm)
        ## self.realm_roles_api = keycloak_api.build("roles", realm)
        ## self.resource_api = self._get_resource_api()

    def publish(self, *, setup_new_links: bool):
        """
        :param setup_new_links: If false, we only remove client_scopes from default client-scopes on the server.
        If true, client_scopes are also added to default client-scopes on the server.
        """
        create_ids, delete_objs = self._difference_ids()

        # PUT to URL https://172.17.0.2:8443/auth/admin/realms/ci0-realm/default-default-client-scopes/ee3a3fed-af78-4c04-b9d9-3fc1b614a0a2
        # payload like: {"realm":"ci0-realm","clientScopeId":"ee3a3fed-af78-4c04-b9d9-3fc1b614a0a2"}
        status_created = False
        if setup_new_links:
            client_scopes = self.client_scopes_api.all()
            for create_id in create_ids:
                client_scope = find_in_list(client_scopes, name=create_id)
                create_obj = self._get_put_payload(client_scope)
                self.resource_api.update(client_scope["id"], create_obj).isOk()
                status_created = True

        status_deleted = False
        for delete_obj in delete_objs:
            self.resource_api.remove(delete_obj["id"], None).isOk()
            status_deleted = True

        return any([status_created, status_deleted])

    def _get_put_payload(self, client_scope: dict):
        return dict(
            realm=self.realm,
            clientScopeId=client_scope["id"],
        )

    def _object_docs_ids(self):
        # requested_doc contains only client-scope names
        requested_doc = read_from_json(os.path.join(self.datadir, normalize(self.realm), f"client-scopes/default/{normalize(self._resource_name)}.json"))
        return requested_doc


class DefaultDefaultClientScopeManager(BaseDefaultClientScopeManager):
    _resource_name = "default-default-client-scopes"


class DefaultOptionalClientScopeManager(BaseDefaultClientScopeManager):
    _resource_name = "default-optional-client-scopes"


# Reuse this to also manage client client-scopes - PUT {realm}/clients/{client_id}/default-client-scopes.
class BaseClientXClientScopeManager(BaseDefaultClientScopeManager):
    # _resource_name = "default-client-scopes"

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *, client_id: str, client_filepath: str):
        """
        requested_doc is like '["ci0-client-scope", "email", ...]'
        """
        self._client_id = client_id
        super().__init__(keycloak_api, realm, datadir)
        self._client_filepath = client_filepath
        self.client_scopes_api = keycloak_api.build("client-scopes", realm)
        ## self.realm_roles_api = keycloak_api.build("roles", realm)
        self.resource_api = self._get_resource_api()

    def _get_put_payload(self, client_scope: dict):
        return dict(
            realm=self.realm,
            client=self._client_id,
            clientScopeId=client_scope["id"],
        )

    def _get_resource_api(self):
        assert self._resource_name != ''
        clients_api = self.keycloak_api.build("clients", self.realm)
        resource_api = KeycloakCRUD.get_child(clients_api, self._client_id, self._resource_name)
        return resource_api

    def _object_docs_ids(self):
        # requested_doc contains only client-scope names
        client_dirname = os.path.dirname(self._client_filepath)
        object_filepath = os.path.join(client_dirname, f"client-scopes/{normalize(self._resource_name)}.json")
        requested_doc = read_from_json(object_filepath)
        # self.requested_doc = requested_doc
        return requested_doc


class ClientDefaultClientScopeManager(BaseClientXClientScopeManager):
    _resource_name = "default-client-scopes"


class ClientOptionalClientScopeManager(BaseClientXClientScopeManager):
    _resource_name = "optional-client-scopes"
