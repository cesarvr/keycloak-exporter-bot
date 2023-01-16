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
            requested_doc=self.body.get("scopeMappings", {}),
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
            client_scope_name=client_scope_name,
            client_scope_id=client_scope["id"],
            client_scope_filepath=self.resource_path,
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
        object_filepaths = glob(os.path.join(self.datadir, f"{self.realm}/client-scopes/*.json"))
        return object_filepaths

    def _object_docs(self):
        object_filepaths = self._object_filepaths()
        object_docs = [read_from_json(fp) for fp in object_filepaths]
        return object_docs


class ClientScopeScopeMappingsRealmManager(BaseManager):
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


class ClientScopeScopeMappingsAllClientsManager:
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
            ClientScopeScopeMappingsClientManager(
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


class ClientScopeScopeMappingsClientManager(BaseManager):
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


class ClientScopeProtocolMapperResource(SingleResource):
    def __init__(
            self,
            resource: dict,
            *,
            body: dict,
            client_scope_id,
            client_scopes_api,
    ):
        protocol_mapper_api = client_scopes_api.protocol_mapper_api(client_scope_id=client_scope_id)
        super().__init__(
            {
                "name": "client-scopes/{client_scope_id}/protocol-mappers/models",
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
                client_scopes_api=client_scopes_api,
            )
            for pm_doc in self._protocol_mapper_docs
        ]

    def _object_docs(self):
        return self._protocol_mapper_docs

    def _get_resource_api(self):
        client_scopes_api = self.keycloak_api.build("client-scopes", self.realm)
        protocol_mapper_api = client_scopes_api.protocol_mapper_api(client_scope_id=self._client_scope_id)
        return protocol_mapper_api


class ClientScopeResource___old(SingleResource):
    def publish_scope_mappings(self):
        state = self.publish_scope_mappings_realm()
        state = state and self.publish_scope_mappings_client()

    def publish_scope_mappings_client(self):
        clients_api = self.keycloak_api.build('clients', self.realm_name)
        clients = clients_api.all()

        client_scopes_api = self.keycloak_api.build('client-scopes', self.realm_name)
        this_client_scope = client_scopes_api.findFirstByKV("name", self.body["name"])  # .verify().resp().json()

        for clientId in self.body["clientScopeMappings"]:
            client = find_in_list(clients, clientId=clientId)
            client_roles_api = clients_api.get_child(clients_api, client["id"], "roles")
            client_roles = client_roles_api.all()
            this_client_scope_scope_mappings_client_api = client_scopes_api.get_child(
                client_scopes_api,
                this_client_scope["id"],
                f"scope-mappings/clients/{client['id']}"
            )
            for role_name in self.body["clientScopeMappings"][clientId]:
                role = find_in_list(client_roles, name=role_name)
                if not role:
                    logger.error(f"scopeMappings clientId={clientId} client role {role_name} not found")
                this_client_scope_scope_mappings_client_api.create([role])
        return True

    def publish_scope_mappings_realm(self):
        if "scopeMappings" not in self.body:
            return True

        client_scopes_api = self.keycloak_api.build('client-scopes', self.realm_name)
        this_client_scope = client_scopes_api.findFirstByKV("name", self.body["name"])  # .verify().resp().json()
        this_client_scope_scope_mappings_realm_api = client_scopes_api.get_child(client_scopes_api, this_client_scope["id"], "scope-mappings/realm")

        realm_roles_api = self.keycloak_api.build('roles', self.realm_name)
        realm_roles = realm_roles_api.all()

        for role_name in self.body["scopeMappings"]["roles"]:
            role = find_in_list(realm_roles, name=role_name)
            if not role:
                logger.error(f"scopeMappings realm role {role_name} not found")
            this_client_scope_scope_mappings_realm_api.create([role])
        return True
