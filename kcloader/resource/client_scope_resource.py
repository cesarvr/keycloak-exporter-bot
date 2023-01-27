import json
import logging
import os
from copy import copy
from glob import glob

import kcapi
from kcfetcher.utils import normalize
from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list, read_from_json
from kcloader.resource.base_manager import BaseManager
from kcloader.resource.scope_mappings import ClientScopeScopeMappingsRealmManager, ClientScopeScopeMappingsAllClientsManager
from kcloader.resource.protocol_mapper import ClientScopeProtocolMapperResource, ClientScopeProtocolMapperManager

logger = logging.getLogger(__name__)


class ClientScopeResource(SingleResource):
    def __init__(
            self,
            resource: dict,
         ):
        super().__init__({
            "name": "client-scopes",
            "id": "name",
            **resource,
        })
        self.datadir = resource['datadir']
        # self._client_scope_id = None
        self.scope_mappings_realm_manager = None
        self.scope_mappings_clients_manager = None
        self.protocol_mapper_manager = None

    def publish_self(self):
        creation_state = self.resource.publish_object(self.body, self)

        # now build what could not be build in __init__.
        client_scope_name = self.body["name"]
        client_scope = self.resource.resource_api.findFirstByKV("name", client_scope_name)
        # self._client_scope_id = client_scope["id"]
        self.scope_mappings_realm_manager = ClientScopeScopeMappingsRealmManager(
            self.keycloak_api,
            self.realm_name,
            self.datadir,
            requested_doc=self.body.get("scopeMappings", {}).get("roles", []),
            client_scope_id=client_scope["id"],
        )
        self.scope_mappings_clients_manager = ClientScopeScopeMappingsAllClientsManager(
            self.keycloak_api,
            self.realm_name,
            self.datadir,
            requested_doc=self.body.get("clientScopeMappings", {}),
            client_scope_id=client_scope["id"],
        )
        self.protocol_mapper_manager = ClientScopeProtocolMapperManager(
            self.keycloak_api,
            self.realm_name,
            self.datadir,
            requested_doc=self.body.get("protocolMappers", []),
            client_scope_id=client_scope["id"],
        )

        return creation_state

    def publish_scope_mappings_realm(self):
        self.scope_mappings_realm_manager.publish()

    def publish_scope_mappings_clients(self):
        self.scope_mappings_clients_manager.publish()

    def publish_protocol_mappers(self):
        self.protocol_mapper_manager.publish()

    def publish(self, body=None, *, include_scope_mappings=True):
        creation_state_all = []
        creation_state_all.append(self.publish_self())
        creation_state_all.append(self.publish_protocol_mappers())
        if include_scope_mappings:
            creation_state_all.append(self.publish_scope_mappings_realm())
            creation_state_all.append(self.publish_scope_mappings_clients())
        return any(creation_state_all)

    def is_equal(self, other):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(other)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            # clientScopeMappings and scopeMappings are added by kcfetcher
            oo.pop("clientScopeMappings", None)
            oo.pop("scopeMappings", None)
            if "protocolMappers" in oo:
                for pm in oo["protocolMappers"]:
                    pm.pop("id", None)
        return obj1 == obj2


class ClientScopeManager(BaseManager):
    _resource_name = "client-scopes"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = [
        "address",
        "email",
        "microprofile-jwt",
        "offline_access",
        "phone",
        "profile",
        "role_list",
        "roles",
        "web-origins",
    ]

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str):
        super().__init__(keycloak_api, realm, datadir)

        # self.client_scopes_api = keycloak_api.build("client-scopes", realm)
        self.resources = []
        object_filepaths = self._object_filepaths()
        self.resources = [
            ClientScopeResource({
                'path': object_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for object_filepath in object_filepaths
        ]

    def _object_filepaths(self):
        object_filepaths = glob(os.path.join(self.datadir, f"{normalize(self.realm)}/client-scopes/*.json"))
        return object_filepaths

    def _object_docs(self):
        object_filepaths = self._object_filepaths()
        object_docs = [read_from_json(fp) for fp in object_filepaths]
        return object_docs
