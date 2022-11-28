import logging
import kcapi

from kcloader.resource import SingleResource
from kcloader.resource.client_resource import find_sub_role
from kcloader.tools import find_in_list

logger = logging.getLogger(__name__)


class RoleResource(SingleResource):
    def __init__(self, resource):
        super().__init__({'name': 'role', 'id':'name', **resource})
        if "composites" in self.body:
            logger.error(f"Composite roles are not implemented yet, role={self.body['name']}")
            # self.body.pop("composites")

    def publish_simple(self):
        # TODO corner cases - role changes to/from simple and composite
        body_orig = None
        if "composites" in self.body:
            assert self.body["composite"] is True
            self.body["composite"] = False
            body_orig = self.body.pop("composites")

        super().publish()

        if body_orig:
                self.body["composites"] = body_orig
                self.body["composite"] = True

    def publish_composite(self):
        if "composites" not in self.body:
            return
        clients_api = self.keycloak_api.build('clients', self.realm_name)
        clients = clients_api.all()

        #  roles_by_id_api.get_child(roles_by_id_api, ci0_default_roles['id'], "composites")
        # this_client = find_in_list(clients, clientId=self.body["clientId"])
        # this_client_scope_mappings_realm_api = clients_api.get_child(clients_api, this_client["id"], "scope-mappings/realm")

        # master_realm = self.keycloak_api.admin()
        realm_roles_api = self.keycloak_api.build('roles', self.realm_name)
        realm_roles = realm_roles_api.all()
        roles_by_id_api = self.keycloak_api.build('roles-by-id', self.realm_name)

        this_role = find_in_list(realm_roles, name=self.body["name"])
        this_role_composites_api = roles_by_id_api.get_child(roles_by_id_api, this_role["id"], "composites")

        for role_object in self.body["composites"]:
            role = find_sub_role(self, clients, realm_roles, clients_roles=None, sub_role=role_object)
            if not role:
                logger.error(f"sub_role {role_object} not found")
            this_role_composites_api.create([role])
