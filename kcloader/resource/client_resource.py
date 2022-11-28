import logging
import kcapi

from kcloader.resource import SingleResource, ResourcePublisher, UpdatePolicy
from kcloader.tools import lookup_child_resource, read_from_json, find_in_list

logger = logging.getLogger(__name__)


# This can be used to find role assigned to client scope-mappings,
# or a role assigned to be sub-role (of composite role).
def find_sub_role(self, clients, realm_roles, clients_roles, sub_role):
    clients_api = self.keycloak_api.build("clients", self.realm_name)
    if sub_role["clientRole"]:
        # client role
        some_client = find_in_list(clients, clientId=sub_role["containerName"])
        some_client_roles_api = clients_api.get_child(clients_api, some_client["id"], "roles")
        some_client_roles = some_client_roles_api.all()  # TODO cache this response
        role = find_in_list(some_client_roles, name=sub_role["name"])
        # TODO create those roles first
    else:
        # realm role
        assert self.realm_name == sub_role["containerName"]
        role = find_in_list(realm_roles, name=sub_role["name"])
    return role


class SingleClientResource(SingleResource):
    def publish_roles(self):
        state = True
        [roles_path_exist, roles_path] = lookup_child_resource(self.resource_path, '/roles/roles.json')
        if roles_path_exist:
            id = ResourcePublisher(key='clientId', body=self.body).get_id(self.resource.api())
            roles = self.resource.api().roles({'key': 'id', 'value': id})
            roles_objects = read_from_json(roles_path)
            for object in roles_objects:
                state = state and ResourcePublisher(key='name', body=object).publish(roles, update_policy=UpdatePolicy.DELETE)

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

        clients_api = self.resource.api()
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

    def publish(self):
        # Uncaught server error: java.lang.RuntimeException: Unable to resolve auth flow binding override for: browser
        # TODO support auth flow override
        # For now, just skip this
        body = self.body
        if body["authenticationFlowBindingOverrides"] != {}:
            logger.error(f"Client clientId={body['clientId']} - authenticationFlowBindingOverrides will not be changed, current server value=?, desired value={body['authenticationFlowBindingOverrides']}")
            body.pop("authenticationFlowBindingOverrides")

        state = self.resource.publish(self.body)
        return state and self.publish_roles() and self.publish_scopes()
