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


'''
    Given the following folder structure:
folder_0/
    folder_a/resource.json
    folder_b/folder_c/res.json
    folder_d/
    folder_e/folder_f/

    This class will do a bread first search to find the first root json file in a group of folder.
    In this example it instantiate a two SingleResource Class against each resource file [resource.json, res.json].
'''


class MultipleResourceInFolders:
    def __init__(self, params={}, path="", ResourceClass=SingleResource):
        files = bfs_folder(path)

        if not params:
            raise Exception("MultipleFolders: params arguments are required.")

        if not path:
            raise Exception("MultipleFolders: path arguments are required.")

        self.resources = list(map(lambda path: ResourceClass({'path': path, **params}), files))

    def publish(self):
        res = []
        for resource in self.resources:
            res.append(resource.publish())

        return res
