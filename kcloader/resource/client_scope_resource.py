import logging
import kcapi

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list

logger = logging.getLogger(__name__)


class ClientScopeResource(SingleResource):
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
