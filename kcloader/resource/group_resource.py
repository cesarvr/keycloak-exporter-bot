from glob import glob

import logging
import os
from typing import Any, Dict, List, Set

import kcapi
from kcapi.rest.crud import KeycloakCRUD
from kcfetcher.utils import normalize

from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import read_from_json

logger = logging.getLogger(__name__)


class GroupResource(SingleResource):
    _resource_name = 'groups'
    _resource_id = 'name'
    _resource_delete_id = 'id'

    def __init__(self, resource, body=None):
        super().__init__({
            'name': self._resource_name,
            'id': self._resource_id,
            **resource,
        }, body=body)
        self.datadir = resource['datadir']

    def _get_query_params(self, parent):
        params = {
            "briefRepresentation": False
        }
        return params

    def find_created_object(self, parent: dict, body: dict):
        if "id" not in body:
            params = self._get_query_params(parent)
            listed = self.keycloak_api.build(self._resource_name, self.realm_name).all(params)
            match = next((x for x in listed if x[self._resource_id]==body[self._resource_id]), None)
            return match
        return self.keycloak_api.build(self._resource_name, self.realm_name).get(body["id"]).verify().resp().json()

    def publish_self(self):
        return super().publish()

    def publish(self, parent: dict, create_ids: Set[str], update_objs: Dict[str, Any]):
        realm_roles = self.body.pop("realmRoles")
        client_roles = self.body.pop("clientRoles")
        sub_groups = self.body.pop("subGroups")

        name = self.body["name"]
        if parent is not None:
            if name in create_ids:
                children_api = KeycloakCRUD.get_child(self.resource.resource_api, parent["id"], "children")
                response = children_api.create(self.body).verify().resp()
                if "Location" in response.headers:
                    self.body["id"] = response.headers["Location"].split("/")[-1]
                self_state = True
            else:
                item = update_objs[name]
                self.body["id"] = item["id"]
                if not self.is_equal(item):
                    self.resource.resource_api.update(item["id"], self.body).verify()
                    self_state = True
                else:
                    self_state = False
        else:
            self_state = self.resource.publish_object(self.body, self, self._get_query_params(None))

        match = self.find_created_object(parent, self.body)
        realm_roles_objs = [{"name": x} for x in realm_roles]
        group_realm_role_manager = GroupRoleMappingManager(self.keycloak_api, self.realm_name, parent=match, data=realm_roles_objs)
        realm_role_status = group_realm_role_manager.publish()

        group_client_role_manager = SimpleManager(self.keycloak_api, self.realm_name, parent=match, data=client_roles)
        client_role_status = group_client_role_manager.publish()
        
        subgroup_manager = SubGroupManager(self.keycloak_api, self.realm_name, parent=match, data=sub_groups)
        status_subgroups = subgroup_manager.publish()

        return any([self_state, realm_role_status, client_role_status, status_subgroups])

    def is_equal(self, obj):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            oo.pop("subGroups", None)
            oo.pop("realmRoles", None)
            oo.pop("clientRoles", None)
        
            # Temporary
            oo.pop("access", None)
        return obj1 == obj2

##### NEW
class GroupManager:
    _resource_name = GroupResource._resource_name
    _resource_id = GroupResource._resource_id
    _resource_delete_id = GroupResource._resource_delete_id

    @classmethod
    def _get_path(cls, datadir: str, realm: str):
        return glob(os.path.join(datadir, f"{normalize(realm)}/groups/*.json"))

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str):
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.datadir = datadir

        self.parent = None
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)

        idp_filepaths = self._get_path(datadir, realm)
        self.resources = [
            GroupResource({
                'path': idp_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for idp_filepath in idp_filepaths
        ]

    def publish(self):
        create_ids, update_objs, delete_objs = self._difference_ids()
        status_resources = [resource.publish(self.parent, create_ids, update_objs) for resource in self.resources]
        status_deleted = False
        for obj in delete_objs:
            self.resource_api.remove(obj[self._resource_delete_id]).isOk()
            status_deleted = True
        return any(status_resources + [status_deleted])

    def _get_query_params(self):
        return {}

    def _difference_ids(self):
        """
        If item is present on server but missing in datadir, then it needs to be removed.
        This function will return list of items that needs to be removed.
        """
        if self.datadir is not None:
            params = self._get_query_params()
            server_objs = self.resource_api.all(params)

            filepaths = self._get_path(self.datadir, self.realm)
            file_docs = [read_from_json(filepath) for filepath in filepaths]        
        else:
            server_objs = self.parent["subGroups"]
            file_docs = [x.body for x in self.resources]
        file_ids = [doc[self._resource_id] for doc in file_docs]
        
        
        server_ids = [obj[self._resource_id] for obj in server_objs]
        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = set(file_ids).difference(server_ids)
        delete_objs = [obj for obj in server_objs if obj[self._resource_id] in delete_ids]
        update_objs = {obj[self._resource_id]: obj for obj in server_objs if obj[self._resource_id] not in delete_ids}
        return create_ids, update_objs, delete_objs


class SubGroupManager(GroupManager):
    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, parent: Any, data: List[Any]):
        self.parent = parent
        self.datadir = None
        
        self.resources = [
            GroupResource({
                'path': None,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': None,
            }, item)
            for item in data
        ]


class GroupRoleResource(SingleResource):
    _resource_id = "name"
    _resource_delete_id = "id"

    def __init__(self, resource, body=None):
        super().__init__({
            'name': None,
            'id': self._resource_id,
            **resource,
        }, body=body)
        self.datadir = resource['datadir']

class GroupRoleMappingManager:
    _resource_id = 'name'
    _resource_delete_id = 'id'

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, parent: Any, data: List[Any]):
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.parent = parent
        self.datadir = None

        self._resource_name = f"groups/{ parent['id']}/role-mappings/realm"
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)

        self.resources = [
            GroupRoleResource({
                'path': None,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': None,
            }, item)
            for item in data
        ]

    def publish(self):
        create_ids, _, delete_objs = self._difference_ids()
        if create_ids:
            available = self.resource_api.get("available").verify().resp().json()
            to_create = [x for x in available if x["name"] in create_ids]
            self.resource_api.create(to_create).isOk()

        if delete_objs:
            self.resource_api.remove(None, delete_objs).isOk()

        return any(create_ids) or any(delete_objs)

    def _get_query_params(self):
        return {}

    def _difference_ids(self):
        """
        If item is present on server but missing in datadir, then it needs to be removed.
        This function will return list of items that needs to be removed.
        """
        if self.datadir is not None:
            params = self._get_query_params()
            server_objs = self.resource_api.all(params)

            filepaths = self._get_path(self.datadir, self.realm)
            file_docs = [read_from_json(filepath) for filepath in filepaths]        
        else:
            params = self._get_query_params()
            server_objs = self.resource_api.all(params)
            file_docs = [x.body for x in self.resources]
        file_ids = [doc[self._resource_id] for doc in file_docs]

        server_ids = [obj[self._resource_id] for obj in server_objs]
        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = set(file_ids).difference(server_ids)
        delete_objs = [obj for obj in server_objs if obj[self._resource_id] in delete_ids]
        update_objs = {obj[self._resource_id]: obj for obj in server_objs if obj[self._resource_id] not in delete_ids}
        return create_ids, update_objs, delete_objs


class GroupRoleClientMappingManager(GroupRoleMappingManager):
    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, parent: Any, data: List[Any], client: Any):
        super().__init__(keycloak_api, realm, parent, data)
        self._resource_name = f"groups/{ parent['id']}/role-mappings/clients/{client['id']}"
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)


class SimpleManager:
    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, parent: Any, data: Dict[str, Any]) -> None:
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.parent=parent
        self.data=data

        self._resource_name = f"clients"
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)

    def publish(self):
        affected = set(self.data.keys()) | set(self.parent["clientRoles"].keys())
        if not affected:
            return False

        clients = {x["clientId"]: x for x in self.resource_api.all()}
        changed = False
        for item in affected:
            client = clients[item]
            data = [{"name": x} for x in self.data.get(item, [])]
            client_manager = GroupRoleClientMappingManager(self.keycloak_api, self.realm, self.parent, data, client)
            changed |= client_manager.publish()
        return changed
