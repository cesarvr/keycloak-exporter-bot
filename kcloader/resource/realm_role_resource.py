import logging
import os
from glob import glob

from kcfetcher.utils import normalize

from kcloader.resource import SingleResource, ResourcePublisher, UpdatePolicy
from kcloader.resource.role_resource import find_sub_role, BaseRoleManager, BaseRoleResource
from kcloader.tools import lookup_child_resource, read_from_json, find_in_list, get_path

logger = logging.getLogger(__name__)


class RealmRoleResource(BaseRoleResource):
    def __init__(
            self,
            resource: dict,
         ):
        super().__init__({
            "name": "roles",
            "id": "name",
            **resource,
        })

    def _get_this_role_obj(self, clients, clients_api, realm_roles):
        this_role = find_in_list(realm_roles, name=self.body["name"])
        return this_role


class RealmRoleManager(BaseRoleManager):
    _resource_name = "roles"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = [
        "offline_access",
        "uma_authorization",
    ]

    def _get_resource_api(self):
        return self.keycloak_api.build(self._resource_name, self.realm)

    def _get_resource_instance(self, params):
        return RealmRoleResource(params)

    def _object_filepaths(self):
        object_filepaths = glob(os.path.join(self.datadir, normalize(self.realm), "roles/*.json"))
        return object_filepaths
