import logging
import kcapi

from kcloader.resource import SingleResource, ResourcePublisher, UpdatePolicy
from kcloader.tools import lookup_child_resource, read_from_json

logger = logging.getLogger(__name__)


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

    def publish(self):
        # Uncaught server error: java.lang.RuntimeException: Unable to resolve auth flow binding override for: browser
        # TODO support auth flow override
        # For now, just skip this
        body = self.body
        if body["authenticationFlowBindingOverrides"] != {}:
            logger.error(f"Client clientId={body['clientId']} - authenticationFlowBindingOverrides will not be changed, current server value=?, desired value={body['authenticationFlowBindingOverrides']}")
            body.pop("authenticationFlowBindingOverrides")

        state = self.resource.publish(self.body)
        return state and self.publish_roles()
