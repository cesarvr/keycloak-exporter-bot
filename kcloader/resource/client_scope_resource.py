import logging
import kcapi
from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list

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

    def publish_self(self):
        creation_state = self.resource.publish_object(self.body, self)
        return creation_state

    def publish(self, body=None, *, include_scope_mappings=True):
        # return super().publish(body=body)
        creation_state = self.publish_self()
        return creation_state

    def is_equal(self, other):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(other)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            # clientScopeMappings and scopeMappings are added by kcfetcher
            oo.pop("clientScopeMappings", None)
            oo.pop("scopeMappings", None)
        return obj1 == obj2


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
