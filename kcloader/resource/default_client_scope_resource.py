import json
import logging
import os
from copy import copy
from glob import glob

import kcapi
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
        self.resource_api = self._get_resource_api()

        requested_doc = read_from_json(os.path.join(datadir, realm, f"client-scopes/default/{self._resource_name}.json"))
        self.requested_doc = requested_doc
        self.requested_doc = requested_doc

    def publish(self):
        create_ids, delete_objs = self._difference_ids()

        # PUT to URL https://172.17.0.2:8443/auth/admin/realms/ci0-realm/default-default-client-scopes/ee3a3fed-af78-4c04-b9d9-3fc1b614a0a2
        # payload like: {"realm":"ci0-realm","clientScopeId":"ee3a3fed-af78-4c04-b9d9-3fc1b614a0a2"}
        status_created = False
        client_scopes = self.client_scopes_api.all()
        for create_id in create_ids:
            client_scope = find_in_list(client_scopes, name=create_id)
            create_obj = dict(
                realm=self.realm,
                clientScopeId=client_scope["id"],
            )
            self.resource_api.update(client_scope["id"], create_obj).isOk()
            status_created = True

        status_deleted = False
        for delete_obj in delete_objs:
            self.resource_api.remove(delete_obj["id"], None).isOk()
            status_deleted = True

        return any([status_created, status_deleted])

    def _object_docs_ids(self):
        # requested_doc contains only client-scope names
        return self.requested_doc


class DefaultDefaultClientScopeManager(BaseDefaultClientScopeManager):
    _resource_name = "default-default-client-scopes"


class DefaultOptionalClientScopeManager(BaseDefaultClientScopeManager):
    _resource_name = "default-optional-client-scopes"
