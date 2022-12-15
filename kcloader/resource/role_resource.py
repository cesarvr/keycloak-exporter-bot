import logging
import kcapi

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list

logger = logging.getLogger(__name__)


# This can be used to find role assigned to client scope-mappings,
# or a role assigned to be sub-role (of composite role).
def find_sub_role(self, clients, realm_roles, clients_roles, sub_role):
    clients_api = self.keycloak_api.build("clients", self.realm_name)
    if sub_role["clientRole"]:
        # client role
        some_client = find_in_list(clients, clientId=sub_role["containerName"])
        if not some_client:
            # https://github.com/justinc1/keycloak-exporter-bot/actions/runs/3699240874/jobs/6266392682
            # I'm not able to reproduce locally.
            logger.error(f"client clientId={sub_role['containerName']} not found")
            return None
        some_client_roles_api = clients_api.get_child(clients_api, some_client["id"], "roles")
        some_client_roles = some_client_roles_api.all()  # TODO cache this response
        role = find_in_list(some_client_roles, name=sub_role["name"])
        # TODO create those roles first
    else:
        # realm role
        assert self.realm_name == sub_role["containerName"]
        role = find_in_list(realm_roles, name=sub_role["name"])
    return role


class RoleResource(SingleResource):
    def __init__(self, resource):
        super().__init__({'name': 'role', 'id':'name', **resource})
        if "composites" in self.body:
            logger.error(f"Realm composite roles are not implemented yet, role={self.body['name']}")
            # self.body.pop("composites")

    def publish_simple(self):
        # TODO corner cases - role changes to/from simple and composite
        body_orig = None
        if "composites" in self.body:
            assert self.body["composite"] is True
            self.body["composite"] = False
            body_orig = self.body.pop("composites")

        super().publish()
        # second publish for RTH SSO 7.4 to load also .attributes
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
