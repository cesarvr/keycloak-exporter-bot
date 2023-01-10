import logging
import os
from glob import glob

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

    def _link_roles(self):
        # Get required global knowledge - TODO - move this out, and reuse data, to reduce network traffic
        realm_roles_api = self.keycloak_api.build("roles", self.realm_name)
        realm_roles = realm_roles_api.all()
        clients_api = self.keycloak_api.build("clients", self.realm_name)
        clients = clients_api.all()
        roles_by_id_api = self.keycloak_api.build('roles-by-id', self.realm_name)

        if 0:
            this_client = find_in_list(clients, clientId=self._client_clientId)
            this_client_roles_api = clients_api.get_child(clients_api, this_client["id"], "roles")
            this_client_roles = this_client_roles_api.all()
            this_role = find_in_list(this_client_roles, name=self.body["name"])
        else:
            this_role = find_in_list(realm_roles, name=self.body["name"])

        this_role_composites_api = roles_by_id_api.get_child(roles_by_id_api, this_role["id"], "composites")
        # Full role representation will be sent to API (this_role_composites_api) that expects briefRepresentation.
        # Hopefully this will work.

        # role_obj - object returned by API, role_doc - same data but formatted as if read from json doc
        this_role_composite_objs = this_role_composites_api.all()
        this_role_composite_docs = self._get_composites_docs(this_role_composite_objs, clients)

        creation_state = False
        for sub_role_doc in self.body.get("composites", []):
            if sub_role_doc in this_role_composite_docs:
                # link already created
                # There is nothing that could be updated
                continue
            sub_role = find_sub_role(self, clients, realm_roles, clients_roles=None, sub_role=sub_role_doc)
            if not sub_role:
                logger.error(f"sub_role {sub_role_doc} not found")
                # Either ignore or crash
                # For now, ignore.
                # TODO - code should crash - on second pass, all subroles should be present.
                continue
            this_role_composites_api.create([sub_role]).isOk()
            creation_state = True

        # remove composites that should not be there
        for role_obj, role_doc in zip(this_role_composite_objs, this_role_composite_docs):
            if role_doc not in self.body.get("composites", []):
                # must be removed
                this_role_composites_api.remove(None, [role_obj]).isOk()
                creation_state = True

        return creation_state


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
        object_filepaths = glob(os.path.join(self.datadir, self.realm, "roles/*.json"))
        return object_filepaths

