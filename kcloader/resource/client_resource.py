import logging
import os
from glob import glob
from copy import copy, deepcopy

from kcfetcher.utils import normalize
from sortedcontainers import SortedDict

import kcapi

from kcloader.resource import SingleResource
from kcloader.resource.default_client_scope_resource import ClientOptionalClientScopeManager, ClientDefaultClientScopeManager
from kcloader.resource.role_resource import find_sub_role, BaseRoleManager, BaseRoleResource
from kcloader.tools import lookup_child_resource, read_from_json, find_in_list, get_path
from kcloader.resource.scope_mappings import ClientScopeMappingsAllClientsManager, ClientScopeMappingsRealmManager
from kcloader.resource.protocol_mapper import ClientProtocolMapperManager

logger = logging.getLogger(__name__)


class ClientRoleResource(BaseRoleResource):
    """
    The ClientRoleResource creates/updates client role.
    It also creates/updates/deletes role composites - that part should be in some Manager class (but is not).
    """
    def __init__(
            self,
            resource: dict,
            *,
            clientId: str,
            client_id: str,
            client_roles_api,
         ):
        """
        client_roles_api needs to be provided in resource dict,
        because SingleResource.resource (type Resource)
        does not know hot to build such CRUD object.
        """
        # or put in whole client object/resource?
        self._client_clientId = clientId
        self._client_id = client_id
        super().__init__({
            # GET https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/<uuid>/roles
            "name": f"clients/TODO-client_id/roles",  # special "reserved" value !!! :/
            "id": "name",
            "client_roles_api": client_roles_api,
            **resource,
        })

    def _get_this_role_obj(self, clients, clients_api, realm_roles):
        this_client = find_in_list(clients, clientId=self._client_clientId)
        this_client_roles_api = clients_api.get_child(clients_api, this_client["id"], "roles")
        this_client_roles = this_client_roles_api.all()
        this_role = find_in_list(this_client_roles, name=self.body["name"])
        return this_role


class ClientRoleManager(BaseRoleManager):
    _resource_name = "clients/TODO-client_id/roles"
    # _resource_name_template = "clients/{client_id}/roles"
    # _resource_name_template will not work - 2 of 4 URLs need to be changed to use "/roles-by-id/<role_id>".
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = []

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *, clientId: str, client_id: str, client_filepath: str):
        self._client_clientId = clientId
        self._client_id = client_id
        self._client_filepath = client_filepath
        super().__init__(keycloak_api, realm, datadir)

    def _get_resource_api(self):
        clients_api = self.keycloak_api.build("clients", self.realm)
        client_query = {'key': 'clientId', 'value': self._client_clientId}
        client_roles_api = clients_api.roles(client_query)
        return client_roles_api

    def _get_resource_instance(self, params):
        return ClientRoleResource(
            params,
            clientId=self._client_clientId,
            client_id=self._client_id,
            client_roles_api=self.resource_api,
        )

    def _object_filepaths(self):
        client_dirname = os.path.dirname(self._client_filepath)
        object_filepaths = glob(os.path.join(client_dirname, "roles/*.json"))
        return object_filepaths


class SingleClientResource(SingleResource):
    _resource_name = "clients"
    _resource_id = "clientId"

    def __init__(self, resource):
        super().__init__({
            'name': self._resource_name,
            'id': self._resource_id,
            **resource,
        })
        self.datadir = resource['datadir']

        # we do not have client id yet, managers cannot be created
        self.client_role_manager = None
        self.client_default_client_scope_manager = None
        self.client_optional_client_scope_manager = None
        self.client__scope_mappings__allclients_manager = None
        self.client__scope_mappings__realm_manager = None
        self.client__protocol_mapper__manager = None

    def publish_scope_mappings(self):
        state_realm_roles = self.client__scope_mappings__realm_manager.publish()
        state_clients_roles = self.client__scope_mappings__allclients_manager.publish()
        return any([state_realm_roles, state_clients_roles])

    def publish_protocol_mappers(self):
        state_protocol_mapper = self.client__protocol_mapper__manager.publish()
        return state_protocol_mapper

    def publish_self(self, *, include_composite=False):
        """
        If client has configured "defaultRoles", then client role with such name will be
        magically created by server. All other role attributes will be wrong.
        We will update such client role a bit later, when client roles are updated.
        """

        # Uncaught server error: java.lang.RuntimeException: Unable to resolve auth flow binding override for: browser
        # TODO support auth flow override
        # For now, just skip this
        body = self.body
        if "authenticationFlowBindingOverrides" in body and \
                body["authenticationFlowBindingOverrides"] != {}:
            logger.error(
                f"Client clientId={body['clientId']}"
                " - authenticationFlowBindingOverrides will not be changed"
                ", current server value=?"
                ", desired value={body['authenticationFlowBindingOverrides']}")
            body.pop("authenticationFlowBindingOverrides")

        state = self.resource.publish_object(self.body, self)
        # Now we have client id, and can get URL to client roles
        client = self.resource.resource_api.findFirstByKV("clientId", self.body["clientId"])
        self.client_role_manager = ClientRoleManager(
            self.keycloak_api, self.realm_name, self.datadir,
            clientId=self.body["clientId"], client_id=client["id"], client_filepath=self.resource_path,
        )
        self.client_default_client_scope_manager = ClientDefaultClientScopeManager(
            self.keycloak_api, self.realm_name, self.datadir,
            client_id=client["id"], client_filepath=self.resource_path,
        )
        self.client_optional_client_scope_manager = ClientOptionalClientScopeManager(
            self.keycloak_api, self.realm_name, self.datadir,
            client_id=client["id"], client_filepath=self.resource_path,
        )
        self.client__protocol_mapper__manager = ClientProtocolMapperManager(
            self.keycloak_api, self.realm_name, self.datadir,
            client_id=client["id"], requested_doc=self.body.get("protocolMappers", []),
        )

        if include_composite:
            # Only in second pass all clients are available, and we can create
            # ClientScopeMappingsRealmManager/ClientScopeMappingsAllClientsManager instances.

            # Here we need to compute requested_doc - we cannot just use part of json file.
            # TODO - kcfethcer should output directly readable json file(s).
            logger.debug(f"client {self.resource_path}")
            client_dirname = os.path.dirname(self.resource_path)
            scope_mappings_filepath = os.path.join(client_dirname, "scope-mappings.json")
            scope_mappings_doc = read_from_json(scope_mappings_filepath)
            requested_doc_realm = [rr["name"] for rr in scope_mappings_doc if rr["clientRole"] is False]
            requested_doc_allclients = {}
            for rr in scope_mappings_doc:
                if rr["clientRole"] is False:
                    continue
                if rr["containerName"] not in requested_doc_allclients:
                    requested_doc_allclients[rr["containerName"]] = []
                requested_doc_allclients[rr["containerName"]].append(rr["name"])
            self.client__scope_mappings__realm_manager = ClientScopeMappingsRealmManager(
                self.keycloak_api, self.realm_name, self.datadir,
                client_id=client["id"], requested_doc=requested_doc_realm,
            )
            self.client__scope_mappings__allclients_manager = ClientScopeMappingsAllClientsManager(
                self.keycloak_api, self.realm_name, self.datadir,
                client_id=client["id"], requested_doc=requested_doc_allclients,
            )

        return state

    def publish(self, *, include_composite=True):
        state_self = self.publish_self(include_composite=include_composite)
        state_roles = self.client_role_manager.publish(include_composite=include_composite)
        if include_composite:
            # Other clients might not be yet created in first pass (new server bootstrap).
            # Setup scope_mappings in second pass.
            # Assigned role can be removed even if it is assigned to some client scope-mappings -
            # we do not need two-stage publish.
            state_scope_mappings = self.publish_scope_mappings()
        else:
            state_scope_mappings = False
        setup_new_links = include_composite
        state_default_client_scopes = self.client_default_client_scope_manager.publish(setup_new_links=setup_new_links)
        state_optional_client_scopes = self.client_optional_client_scope_manager.publish(setup_new_links=setup_new_links)
        state_protocol_mappers = self.publish_protocol_mappers()
        return any([
            state_self,
            state_roles,
            state_scope_mappings,
            state_default_client_scopes,
            state_optional_client_scopes,
            state_protocol_mappers,
        ])

    def is_equal(self, obj):
        """
        :param obj: dict returned by API
        :return: True if content in self.body is same as in obj
        """
        # self.body is already sorted
        obj1 = deepcopy(self.body)
        obj2 = deepcopy(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            # TODO authenticationFlowBindingOverrides is not implemented yet, ignore it
            oo["authenticationFlowBindingOverrides"] = {}
            # defaultClientScopes/optionalClientScopes are intentionally not stored by kcfetcher
            oo.pop("defaultClientScopes", None)
            oo.pop("optionalClientScopes", None)
            if "protocolMappers" in oo:
                # remove id from protocolMappers
                for protocol_mapper in oo["protocolMappers"]:
                    protocol_mapper.pop("id", None)
                # sort protocolMappers by name
                oo["protocolMappers"] = sorted(oo["protocolMappers"], key=lambda pm: pm["name"])
                # TODO - client protocol-mappers are FOR SURE not updated when client is updated
                # GET /{realm}/clients/{id}/protocol-mappers/models

        # sort obj2 - it is return by API
        # obj1 - we added and remove authenticationFlowBindingOverrides, sort is needed too
        obj1 = SortedDict(obj1)
        obj2 = SortedDict(obj2)

        # debug
        # with open("a", "w") as ff:
        #     json.dump(obj1, ff, indent=True)
        # with open("b", "w") as ff:
        #     json.dump(obj2, ff, indent=True)

        return obj1 == obj2


class ClientManager:
    _resource_name = "clients"
    _resource_id = "clientId"
    _resource_delete_id = "id"
    _resource_id_blacklist = [
        "account",
        "account-console",
        "admin-cli",
        "broker",
        "realm-management",
        "security-admin-console",
    ]

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str):
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.datadir = datadir
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)

        object_filepaths = self._object_filepaths()

        self.resources = [
            SingleClientResource({
                'path': object_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for object_filepath in object_filepaths
        ]

    def _object_filepaths(self):
        object_filepaths = glob(os.path.join(self.datadir, f"{normalize(self.realm)}/clients/*/*.json"))
        # remove scope-mappings.json
        object_filepaths = [fp for fp in object_filepaths if not fp.endswith("/scope-mappings.json")]
        return object_filepaths

    def publish(self, *, include_composite=True):
        create_ids, delete_objs = self._difference_ids()
        status_resources = [resource.publish(include_composite=include_composite) for resource in self.resources]
        status_deleted = False
        for delete_obj in delete_objs:
            delete_id = delete_obj[self._resource_delete_id]
            self.resource_api.remove(delete_id).isOk()
            status_deleted = True
        return any(status_resources + [status_deleted])

    def _difference_ids(self):
        """
        If object is present on server but missing in datadir, then it needs to be removed.
        This function will return list of ids (alias-es, clientId-s, etc.) that needs to be removed.
        """
        object_filepaths = self._object_filepaths()

        file_docs = [read_from_json(object_filepath) for object_filepath in object_filepaths]
        file_ids = [doc[self._resource_id] for doc in file_docs]
        server_objs = self.resource_api.all()
        server_ids = [obj[self._resource_id] for obj in server_objs]

        # do not try to create/remove/modify blacklisted objects
        server_ids = [sid for sid in server_ids if sid not in self._resource_id_blacklist]

        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = list(set(file_ids).difference(server_ids))
        delete_objs = [obj for obj in server_objs if obj[self._resource_id] in delete_ids]
        return create_ids, delete_objs
