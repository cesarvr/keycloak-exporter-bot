import json
import logging
import os
from copy import copy
from glob import glob

import kcapi
from kcapi.rest.crud import KeycloakCRUD
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
    # ClientScope ProtocolMapper
    _resource_name = "client-scopes/{client_scope_id}/protocol-mappers/models"

    def __init__(
            self,
            resource: dict,
            *,
            body: dict,
            client_scope_id: str,
    ):
        self._client_scope_id = client_scope_id
        super().__init__(resource, body=body)

    def _get_resource_api(self):
        client_scopes_api = self.keycloak_api.build("client-scopes", self.realm_name)
        protocol_mapper_api = client_scopes_api.protocol_mapper_api(client_scope_id=self._client_scope_id)
        return protocol_mapper_api


class ClientProtocolMapperResource(BaseProtocolMapperResource):
    # Client ProtocolMapper
    _resource_name = "client/{client_id}/protocol-mappers/models"

    def __init__(
            self,
            resource: dict,
            *,
            body: dict,
            client_id: str,
    ):
        self._client_id = client_id
        super().__init__(resource, body=body)

    def _get_resource_api(self):
        clients_api = self.keycloak_api.build("clients", self.realm_name)
        protocol_mapper_api = KeycloakCRUD.get_child(clients_api, self._client_id, "protocol-mappers/models")
        return protocol_mapper_api


class BaseProtocolMapperManager(BaseManager):
    # _resource_name = "/{realm}/client-scopes/{id}/protocol-mappers/models"
    # _resource_name = "/{realm}/clients/{id}/protocol-mappers/models"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = []

    def __init__(
            self,
            keycloak_api: kcapi.sso.Keycloak,
            realm: str,
            datadir: str,
            *,
            requested_doc: dict,
    ):
        assert isinstance(requested_doc, list)
        if requested_doc:
            assert isinstance(requested_doc[0], dict)
            assert "name" in requested_doc[0]
            assert "config" in requested_doc[0]
        self._requested_doc = requested_doc
        super().__init__(keycloak_api, realm, datadir)
        self.resources = []

    def _object_docs(self):
        return self._requested_doc


class ClientScopeProtocolMapperManager(BaseProtocolMapperManager):
    # _resource_name = "/{realm}/client-scopes/{id}/protocol-mappers/models"

    def __init__(
            self,
            keycloak_api: kcapi.sso.Keycloak,
            realm: str,
            datadir: str,
            *,
            requested_doc: dict,
            client_scope_id: str,
    ):
        self._client_scope_id = client_scope_id
        super().__init__(keycloak_api, realm, datadir, requested_doc=requested_doc)

        self.resources = [
            ClientScopeProtocolMapperResource(
                {
                    'path': "client_scope_filepath--todo",
                    'keycloak_api': keycloak_api,
                    'realm': realm,
                    'datadir': datadir,
                },
                body=pm_doc,
                client_scope_id=client_scope_id,
            )
            for pm_doc in self._requested_doc
        ]

    def _get_resource_api(self):
        client_scopes_api = self.keycloak_api.build("client-scopes", self.realm)
        protocol_mapper_api = client_scopes_api.protocol_mapper_api(client_scope_id=self._client_scope_id)
        return protocol_mapper_api


class ClientProtocolMapperManager(BaseProtocolMapperManager):
    # _resource_name = "/{realm}/clients/{id}/protocol-mappers/models"
    def __init__(
            self,
            keycloak_api: kcapi.sso.Keycloak,
            realm: str,
            datadir: str,
            *,
            requested_doc: dict,
            client_id: str,
    ):
        self._client_id = client_id
        super().__init__(keycloak_api, realm, datadir, requested_doc=requested_doc)

        self.resources = [
            ClientProtocolMapperResource(
                {
                    'path': "client_scope_filepath--todo",
                    'keycloak_api': keycloak_api,
                    'realm': realm,
                    'datadir': datadir,
                },
                body=pm_doc,
                client_id=client_id,
            )
            for pm_doc in self._requested_doc
        ]

    def _get_resource_api(self):
        clients_api = self.keycloak_api.build("clients", self.realm)
        protocol_mapper_api = KeycloakCRUD.get_child(clients_api, self._client_id, "protocol-mappers/models")
        return protocol_mapper_api
