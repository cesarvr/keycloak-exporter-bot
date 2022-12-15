import logging
import os
from glob import glob

import kcapi

from kcloader.resource import SingleResource, ResourcePublisher, UpdatePolicy
from kcloader.resource.role_resource import find_sub_role
from kcloader.tools import lookup_child_resource, read_from_json, find_in_list, get_path

logger = logging.getLogger(__name__)


class SingleClientResource(SingleResource):
    def _publish_roles_old(self):
        state = True
        [roles_path_exist, roles_path] = lookup_child_resource(self.resource_path, '/roles/roles.json')
        if roles_path_exist:
            id = ResourcePublisher(key='clientId', body=self.body).get_id(self.resource.api())
            roles = self.resource.api().roles({'key': 'id', 'value': id})
            roles_objects = read_from_json(roles_path)
            for object in roles_objects:
                state = state and ResourcePublisher(key='name', body=object).publish(roles, update_policy=UpdatePolicy.DELETE)

        return state

    def publish_roles(self, include_composite):
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
        this_client_roles = this_client_roles_api.all()

        # master_realm = self.keycloak_api.admin()
        realm_roles_api = self.keycloak_api.build('roles', self.realm_name)
        realm_roles = realm_roles_api.all()
        roles_by_id_api = self.keycloak_api.build('roles-by-id', self.realm_name)

        for role_filepath in role_filepaths:
            # self.resource.resource_api == clients_api (?)
            id = ResourcePublisher(key='clientId', body=self.body).get_id(self.resource.resource_api)
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
                if not "composites" in role_object:
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
        # Uncaught server error: java.lang.RuntimeException: Unable to resolve auth flow binding override for: browser
        # TODO support auth flow override
        # For now, just skip this
        body = self.body
        if body["authenticationFlowBindingOverrides"] != {}:
            logger.error(f"Client clientId={body['clientId']} - authenticationFlowBindingOverrides will not be changed, current server value=?, desired value={body['authenticationFlowBindingOverrides']}")
            body.pop("authenticationFlowBindingOverrides")

        return self.resource.publish(self.body)

    def publish(self):
        state = self.publish_self()
        return state and self.publish_roles(include_composite=False) and self.publish_scopes()
