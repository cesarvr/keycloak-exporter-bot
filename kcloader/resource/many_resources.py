import logging
import kcapi

from kcloader.resource import SingleResource
from kcloader.tools import add_trailing_slash, get_json_docs_from_folder, bfs_folder

logger = logging.getLogger(__name__)


'''
Read all resource files in a folder and apply SingleResource
'''
class ManyResources:
    def __init__(self, params, ResourceClass=SingleResource):
        path = add_trailing_slash(params['folder'])
        self.resources = map(lambda file_path: ResourceClass({'path': file_path, **params}),
                             get_json_docs_from_folder(path))

    def publish(self):
        for resource in self.resources:
            resource.publish()

