import logging
import kcapi
from kcapi.ie import AuthenticationFlowsImporter

from kcloader.resource import SingleResource
from kcloader.tools import lookup_child_resource, read_from_json

logger = logging.getLogger(__name__)


class SingleCustomAuthenticationResource(SingleResource):
    def __init__(self, resource):
        super().__init__({'name': 'authentication', 'id':'alias', **resource})

    def publish_executors(self):
        [exists, executors] = lookup_child_resource(self.resource_path, '/executors/executors.json')

        if exists:
            parent = self.resource.api()
            auth_import_api = AuthenticationFlowsImporter(parent)
            children_nodes = read_from_json(executors)
            state = auth_import_api.update(self.body, children_nodes)
            return state

    def publish(self):
        if self.body["builtIn"]:
            # builtin flows cannot be updated
            logger.info(f"Authentication flow {self.body['alias']} is builtIn, we will not update it.")
        else:
            state = self.resource.publish(self.body)
        # state is true, but publish_executors returns None
        # Likely, code switched to use Exceptions instead of return True/False.
        # return state and self.publish_executors()
        self.publish_executors()
