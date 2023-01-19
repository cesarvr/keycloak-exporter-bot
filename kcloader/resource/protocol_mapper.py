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


class BaseProtocolMapperResource(SingleResource):
    # _resource_name = "client-scopes/{client_scope_id}/protocol-mappers/models"

    def __init__(
            self,
            resource: dict,
            *,
            body: dict,
    ):
        self.keycloak_api = resource["keycloak_api"]
        self.realm_name = resource['realm']
        protocol_mapper_api = self._get_resource_api()
        super().__init__(
            {
                "name": self._resource_name,
                "id": "name",
                **resource,
            },
            body=body,
            resource_api=protocol_mapper_api,
        )
        self.datadir = resource['datadir']

    def publish(self, *, include_composite=True):
        body = copy(self.body)
        creation_state = self.resource.publish_object(body, self)
        return creation_state

    def is_equal(self, obj):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
        return obj1 == obj2

    def get_update_payload(self, obj):
        # PUT {realm}/client-scopes/{id}/protocol-mappers/models/{id} fails if "id" is not also part of payload.
        body = copy(self.body)
        body["id"] = obj["id"]
        return body


class ClientScopeProtocolMapperResource(BaseProtocolMapperResource):
    _resource_name = "client-scopes/{client_scope_id}/protocol-mappers/models"

    def __init__(
            self,
            resource: dict,
            *,
            body: dict,
            client_scope_id,
    ):
        self._client_scope_id = client_scope_id
        super().__init__(resource, body=body)

    def _get_resource_api(self):
        client_scopes_api = self.keycloak_api.build("client-scopes", self.realm_name)
        protocol_mapper_api = client_scopes_api.protocol_mapper_api(client_scope_id=self._client_scope_id)
        return protocol_mapper_api


class ClientScopeProtocolMapperManager(BaseManager):
    # _resource_name = "/{realm}/client-scopes/{id}/protocol-mappers/models"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = []

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *, client_scope_name: str, client_scope_id: str, client_scope_filepath: str):
        self._client_scope_name = client_scope_name
        self._client_scope_id = client_scope_id
        self._client_scope_filepath = client_scope_filepath
        super().__init__(keycloak_api, realm, datadir)

        client_scopes_api = keycloak_api.build("client-scopes", realm)
        client_scope_doc = read_from_json(client_scope_filepath)
        self._protocol_mapper_docs = client_scope_doc.get("protocolMappers", [])

        self.resources = [
            ClientScopeProtocolMapperResource(
                {
                    'path': client_scope_filepath,
                    'keycloak_api': keycloak_api,
                    'realm': realm,
                    'datadir': datadir,
                },
                body=pm_doc,
                client_scope_id=client_scope_id,
            )
            for pm_doc in self._protocol_mapper_docs
        ]

    def _object_docs(self):
        return self._protocol_mapper_docs

    def _get_resource_api(self):
        client_scopes_api = self.keycloak_api.build("client-scopes", self.realm)
        protocol_mapper_api = client_scopes_api.protocol_mapper_api(client_scope_id=self._client_scope_id)
        return protocol_mapper_api
