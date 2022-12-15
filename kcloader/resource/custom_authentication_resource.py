import logging

from kcapi.ie import AuthenticationFlowsImporter

from kcloader.resource import SingleResource
from kcloader.tools import lookup_child_resource, read_from_json

logger = logging.getLogger(__name__)


class SingleCustomAuthenticationResource(SingleResource):
    def __init__(self, resource):
        super().__init__({'name': 'authentication', 'id':'alias', **resource})

    def publish(self):
        [exists, executors_filepath] = lookup_child_resource(self.resource_path, 'executors/executors.json')
        assert exists
        executors_doc = read_from_json(executors_filepath)

        authentication_api = self.resource.resource_api
        auth_flow_importer = AuthenticationFlowsImporter(authentication_api)
        auth_flow_importer.update(root_node=self.body, flows=executors_doc)
        return True
