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

    def get_id(self, resource):
        # TODO resource should know what is the 'key'
        # Return server-side unique id of the resource
        # For authentication flow has unique alias (string), this function returns corresponding id (uuid).
        assert self.body
        obj = resource.findFirstByKV(self.key, self.body[self.key])
        if not obj:
            return None
        key = self.key
        if "realm" in obj:
            key = "realm"
        elif isinstance(resource, kcapi.rest.auth_flows.AuthenticationFlows):
            key = "id"
        elif isinstance(resource, kcapi.rest.clients.Clients):
            key = "id"
        elif isinstance(resource, kcapi.rest.clients.Role):
            # this can be client or realm role
            key = "id"
        elif isinstance(resource, kcapi.rest.crud.KeycloakCRUD):
            # this should pickup realm roles
            # But KeycloakCRUD is for everyting, so be careful
            key = "id"
        return obj[key]

    def publish(self, resource = {}, update_policy=UpdatePolicy.PUT):
        self.resource_id = self.get_id(resource)
        logger.debug(f"Publishing id={self.resource_id}  type=X {self.key}={self.body[self.key]}")
        state = False
        if self.resource_id:
            if update_policy == UpdatePolicy.PUT:
                state = resource.update(self.resource_id, self.body).isOk()

            if update_policy == UpdatePolicy.DELETE:
                state = resource.remove(self.resource_id).isOk()
                state = state and resource.create(self.body).isOk()

        else:
            state = resource.create(self.body).isOk()

        return state
