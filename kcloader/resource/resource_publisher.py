import logging
import kcapi

logger = logging.getLogger(__name__)


class UpdatePolicy:
    PUT=0
    DELETE=1


class ResourcePublisher:
    def __init__(self, key='key', body='', single_resource=None, params=None):
        # assert isinstance(single_resource, (SingleResource, None))
        self.key = key
        self.body = body
        self.single_resource = single_resource
        self.params = params

    def get_id(self, resource_api):
        # TODO resource should know what is the 'key'
        # Return server-side unique id of the resource
        # For authentication flow has unique alias (string), this function returns corresponding id (uuid).
        assert self.body
        obj = resource_api.findFirstByKV(self.key, self.body[self.key], self.params)
        if not obj:
            return None, None
        key = self.key
        if "realm" in obj:
            key = "realm"
        elif isinstance(resource_api, kcapi.rest.auth_flows.AuthenticationFlows):
            key = "id"
        elif isinstance(resource_api, kcapi.rest.clients.Clients):
            key = "id"
        elif isinstance(resource_api, kcapi.rest.clients.ClientRoleCRUD):
            # this can be client or realm role
            key = "id"
            # In .publish() .is_equal() will be called, and ClientRoleCRUD.is_equal() will compare also "composites"
            # Add them into obj.
            # TODO - code would be cleaner if "composites" would be moved out into one file for realm sub-roles,
            # and one file for each client sub-role. Downside - explosion of small files.
            # Do this.
            # Old layout:
            #     ci0-realm/clients/client-0/roles/ci0-client0-role1.json
            # New layout:
            #     ci0-realm/clients/client-0/roles/ci0-client0-role1/ci0-client0-role1.json
            #     ci0-realm/clients/client-0/roles/ci0-client0-role1/composites/realm/ci0-role-1a.json
            #     ci0-realm/clients/client-0/roles/ci0-client0-role1/composites/clients/ci0-client-0/ci0-client0-role1a.json
            #     ci0-realm/clients/client-0/roles/ci0-client0-role1/composites/clients/ci0-client-0/ci0-client0-role1b.json
            # Need to add SubroleResource, SubroleResourceManager
            # SubroleResource - will need to know about parent client, role. Will it be easy enough to implement?
            # Can we have SubroleResource, SubroleResourceManager without changing directory layout?
            # I guess yes.
            #
            # Better refactoring (might be) - A client role class to provide a "fake" CRUD api?
            if obj["composite"]:
                # GET /{realm}/clients/{id}/roles/{role-name}/composites
                this_role_composites_api = resource_api.get_child(resource_api, obj["name"], "composites")
                composites = this_role_composites_api.all()
                # keep only fields kcfetcher puts into json file
                composites = [
                    dict(
                        name=role["name"],
                        clientRole=role["clientRole"],
                        containerId=role["containerId"],
                    )
                    for role in composites
                ]
                obj["composites"] = composites
            return obj[key], obj

        elif isinstance(resource_api, kcapi.rest.clients.Role):
            # this can be client or realm role
            key = "id"
        elif isinstance(resource_api, kcapi.rest.crud.KeycloakCRUD):
            # this should pickup realm roles
            # But KeycloakCRUD is for everyting, so be careful
            if "id" not in obj and "internalId" in obj:
                # must be an identity-provider
                assert "alias" in obj
                key = "internalId"
            else:
                key = "id"
        return obj[key], obj

    def publish(self, resource_api, update_policy=UpdatePolicy.PUT):
        # return value: state==creation_state - True if object was created or updated.
        resource_id, old_data = self.get_id(resource_api)
        logger.debug(f"Publishing id={resource_id}  type=X {self.key}={self.body[self.key]}")
        if resource_id:
            if update_policy == UpdatePolicy.PUT:
                # update_rmw - would include 'id' for auth flow PUT
                # old_data = resource_api.get_one(resource_id)
                # TODO implement is_equal() for all classes - IdentityProviderResource is missing it.
                # Then blacklisted_attr will not be needed anymore.
                for blacklisted_attr in [
                    "internalId",  # identity-provider
                    # "id",  # clients, and others
                    # "id" - no need to remove, .is_equal() will ignore id, internalId and other attributes
                    # "authenticationFlowBindingOverrides",  # clients - this is not implemented yet
                ]:
                    old_data.pop(blacklisted_attr, None)
                # Is in new data anything different from old_data?
                # Corner case: whole attributes added/removed in new_data - what behaviour do we want in this case?
                if self.single_resource:
                    # assert self.body == self.single_resource.body  # for roles "composites" is removed
                    if self.single_resource.is_equal(old_data):
                        # no change needed
                        return False
                    else:
                        # TODO - pass in self.body, SingleResource derived classes modify it before calling publish -
                        # e.g. RealmResource.publish(minimal_representation=True)
                        update_body = self.single_resource.get_update_payload(old_data)
                else:
                    # old code, when there was no self.single_resource.
                    # TODO remove when it is not used anymore
                    if self.body == old_data:
                        # Nothing to change
                        return False
                    update_body = self.body

                http_ok = resource_api.update(resource_id, update_body).isOk()

                return True
            if update_policy == UpdatePolicy.DELETE:
                http_ok = resource_api.remove(resource_id).isOk()
                assert http_ok  # if not True, exception should be raised by .isOk()
                http_ok = resource_api.create(self.body).isOk()
                return True
        else:
            if self.single_resource:
                create_payload = self.single_resource.get_create_payload()
            else:
                # old code, when there was no self.single_resource.
                # TODO remove when it is not used anymore
                create_payload = self.body
            http_ok = resource_api.create(create_payload).isOk()
            if self.single_resource and self.single_resource.is_update_after_create_needed():
                # authentication flows - they need to be updated just after create.
                # create payload is diffrent from update payload, kcapi AuthenticationExecutionsBaseCRUD.create()
                # cannot do this.
                assert update_policy == UpdatePolicy.PUT
                resource_id, old_data = self.get_id(resource_api)
                if not self.single_resource.is_equal(old_data):
                    update_body = self.single_resource.get_update_payload(old_data)
                    http_ok = resource_api.update(resource_id, update_body).isOk()
            return True
