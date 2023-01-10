import logging
import os
from glob import glob
from copy import copy
from sortedcontainers import SortedDict

import kcapi

from kcloader.resource import SingleResource, ResourcePublisher, UpdatePolicy
from kcloader.resource.role_resource import find_sub_role, BaseRoleManager, BaseRoleResource
from kcloader.tools import lookup_child_resource, read_from_json, find_in_list, get_path

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

        self.client_role_manager = None  # we do not have client id yet...

    def __init_client_role_resources(self):
        assert 0
        # TODO if this works, move it to ClientRoleResourceManager class
        clients_api = self.resource.resource_api
        client = clients_api.findFirstByKV('clientId', self.body["clientId"])
        client_roles_api = self.resource.resource_api.roles({'key': 'id', 'value': client["id"]})
        # clientId = self.body["clientId"]

        # TODO - move to ._object_filepaths()
        # Grrr - clients are in directories like client-0, client-1, etc
        # roles_paths = glob(os.path.join(self.datadir, f"{self.realm_name}/clients/{clientId}/roles/*.json"))
        client_resource_dirname = os.path.dirname(self.resource_path)
        roles_paths = glob(os.path.join(client_resource_dirname, "roles/*.json"))

        self._client_role_resources = [
            ClientRoleResource({
                'path': role_path,
                'keycloak_api': self.keycloak_api,
                'realm': self.realm_name,
                'datadir': self.datadir,
                'client_roles_api': client_roles_api,
            })
            for role_path in roles_paths
        ]

    def RM_publish_roles_old_2(self, include_composite):
        # TODO rm
        state = True
        # [roles_path_exist, roles_path] = lookup_child_resource(self.resource_path, '/roles/roles.json')
        role_filepaths = glob(os.path.join(get_path(self.resource_path), "roles/*.json"))

        if not role_filepaths:
            return state

        clients_api = self.keycloak_api.build('clients', self.realm_name)
        clients = clients_api.all()

        #  roles_by_id_api.get_child(roles_by_id_api, ci0_default_roles['id'], "composites")
        this_client = find_in_list(clients, clientId=self.body["clientId"])
        this_client_roles_api = clients_api.get_child(clients_api, this_client["id"], "roles")
         ###         roles_api = client0_resource.resource.resource_api.roles({'key': 'id', 'value': client_a["id"]})
        this_client_roles = this_client_roles_api.all()

        # master_realm = self.keycloak_api.admin()
        realm_roles_api = self.keycloak_api.build('roles', self.realm_name)
        realm_roles = realm_roles_api.all()
        roles_by_id_api = self.keycloak_api.build('roles-by-id', self.realm_name)

        for role_filepath in role_filepaths:
            # self.resource.resource_api == clients_api (?)
            id, obj = ResourcePublisher(key='clientId', body=self.body).get_id(self.resource.resource_api)
            roles = self.resource.resource_api.roles({'key': 'id', 'value': id})
            role_object = read_from_json(role_filepath)
            if not include_composite:
                # 1st pass, only simple roles
                if "composites" in role_object:
                    logger.error(f"Client composite roles are not implemented yet, role={role_object['name']}")
                    assert role_object["composite"] is True
                    role_object["composite"] = False
                    role_object.pop("composites")
                state = state and ResourcePublisher(key='name', body=role_object).publish(roles, update_policy=UpdatePolicy.DELETE)

                # UpdatePolicy.PUT - RH SSO 7.4 will set .attributes only when updating existing object
                # ResourcePublisher(key='id', body=this_role).publish(roles, update_policy=UpdatePolicy.PUT)
                role = this_client_roles_api.findFirstByKV('name', role_object['name'])
                state = roles_by_id_api.update( role['id'], role_object).isOk()

            else:
                # 2nd pass, setup composites
                if "composites" not in role_object:
                    continue

                this_role = find_in_list(this_client_roles, name=role_object["name"])
                this_role_composites_api = roles_by_id_api.get_child(roles_by_id_api, this_role["id"], "composites")

                for sub_role_object in role_object["composites"]:
                    sub_role = find_sub_role(self, clients, realm_roles, clients_roles=None, sub_role=sub_role_object)
                    if not sub_role:
                        logger.error(f"sub_role {sub_role_object} not found")
                    this_role_composites_api.create([sub_role])

        return state

    def publish_scopes(self):
        state = True
        [scopes_path_exist, scopes_path] = lookup_child_resource(self.resource_path, 'scope-mappings.json')
        if not scopes_path_exist:
            return state
        scopes_objects = read_from_json(scopes_path)
        assert isinstance(scopes_objects, list)
        if not scopes_objects:
            # empty list
            return state
        assert isinstance(scopes_objects[0], dict)

        clients_api = self.resource.resource_api
        clients = clients_api.all()

        #  roles_by_id_api.get_child(roles_by_id_api, ci0_default_roles['id'], "composites")
        this_client = find_in_list(clients, clientId=self.body["clientId"])
        this_client_scope_mappings_realm_api = clients_api.get_child(clients_api, this_client["id"], "scope-mappings/realm")

        # master_realm = self.keycloak_api.admin()
        realm_roles_api = self.keycloak_api.build('roles', self.realm_name)
        realm_roles = realm_roles_api.all()

        # self.keycloak_api.build('clients', self.realm)

        for scopes_object in scopes_objects:
            role = find_sub_role(self, clients, realm_roles, clients_roles=None, sub_role=scopes_object)
            if not role:
                logger.error(f"sub_role {scopes_object} not found")
            this_client_scope_mappings_realm_api.create([role])

        # TODO remove scope mappings that are assigned, but are not in json file
        return state

    def publish_self(self):
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

        return state

    def publish(self, *, include_composite=True):
        state = self.publish_self()
        state_roles = self.client_role_manager.publish(include_composite=include_composite)
        state_scopes = self.publish_scopes()
        return any([state, state_roles, state_scopes])

    def is_equal(self, obj):
        """
        :param obj: dict returned by API
        :return: True if content in self.body is same as in obj
        """
        # self.body is already sorted
        obj1 = copy(self.body)
        obj2 = copy(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            # authenticationFlowBindingOverrides is not implemented yet, ignore it
            oo["authenticationFlowBindingOverrides"] = {}
            # sort scopes
            oo["defaultClientScopes"] = sorted(oo["defaultClientScopes"])
            oo["optionalClientScopes"] = sorted(oo["optionalClientScopes"])
            if "protocolMappers" in oo:
                # remove id from protocolMappers
                for protocol_mapper in oo["protocolMappers"]:
                    protocol_mapper.pop("id", None)
                # sort protocolMappers by name
                oo["protocolMappers"] = sorted(oo["protocolMappers"], key=lambda pm: pm["name"])

        # sort obj2 - it is return by API
        # obj2 = json.loads(json.dumps(obj2, sort_keys=True))
        # obj1 - we added and remove authenticationFlowBindingOverrides, sort is needed too
        # obj1 = json.loads(json.dumps(obj1, sort_keys=True))
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
        object_filepaths = glob(os.path.join(self.datadir, f"{self.realm}/clients/*/*.json"))
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
        # idp_filepaths = glob(os.path.join(self.datadir, f"{self.realm}/identity-provider/*/*.json"))
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
