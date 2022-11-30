import logging
import kcapi

logger = logging.getLogger(__name__)


class UpdatePolicy:
    PUT=0
    DELETE=1


class ResourcePublisher:
    def __init__(self, key='key', body=''):
        self.key = key
        self.body = body

    def get_id(self, resource_api):
        # TODO resource should know what is the 'key'
        # Return server-side unique id of the resource
        # For authentication flow has unique alias (string), this function returns corresponding id (uuid).
        assert self.body
        obj = resource_api.findFirstByKV(self.key, self.body[self.key])
        if not obj:
            return None
        key = self.key
        if "realm" in obj:
            key = "realm"
        elif isinstance(resource_api, kcapi.rest.auth_flows.AuthenticationFlows):
            key = "id"
        elif isinstance(resource_api, kcapi.rest.clients.Clients):
            key = "id"
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
        return obj[key]

    def publish(self, resource_api, update_policy=UpdatePolicy.PUT):
        resource_id = self.get_id(resource_api)
        logger.debug(f"Publishing id={resource_id}  type=X {self.key}={self.body[self.key]}")
        state = False
        if resource_id:
            if update_policy == UpdatePolicy.PUT:
                state = resource_api.update(resource_id, self.body).isOk()

            if update_policy == UpdatePolicy.DELETE:
                state = resource_api.remove(resource_id).isOk()
                state = state and resource_api.create(self.body).isOk()

        else:
            state = resource_api.create(self.body).isOk()

        return state
