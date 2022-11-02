from kcapi.ie import AuthenticationFlowsImporter

from lib.tools import read_from_json, get_json_docs_from_folder, add_trailing_slash, traverse_and_remove_field, get_path, \
    bfs_folder
import os


class UpdatePolicy:
    PUT=0
    DELETE=1


class ResourcePublisher:
    def __init__(self, key='key', body=''):
        self.key = key
        self.body = body

    def get_id(self, resource):
        found = resource.findFirstByKV(self.key, self.body[self.key])
        if found:
            return found['id'] if not "realm" in found else found['realm']
        else:
            return None

    def publish(self, resource = {}, update_policy=UpdatePolicy.PUT):
        self.resource_id = self.get_id(resource)
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


class Resource:
    def __init__(self, params={}):
        self.name = params['name']
        self.resource = self.instantiate_api(params)
        self.key = params['id']

    def instantiate_api(self, params):
        kc = params['keycloak_api']
        realm = params['realm']

        if self.name == 'realm':
            return kc.admin()
        else:
            return kc.build(realm=realm, resource_name=self.name)

    def api(self):
        return self.resource

    def publish(self, body):
        return ResourcePublisher(self.key, body).publish(self.resource)

    def remove(self, body):
        id = self.get_resource_id(body)
        if id:
            return self.resource.remove(id).isOk()
        return False


def remove_unnecessary_fields(resource):
    updated_resource = traverse_and_remove_field(resource, 'id')

    return updated_resource


def lookup_child_resource(resource_path, child_path):
    new_path = get_path(resource_path) + child_path
    return [os.path.exists(new_path), new_path]

'''
params = {
    'path': <string> path to the JSON template, // see the sample_payloads folder
    'name': <string> name of the RH-SSO resource,  // for example clients, realms, roles, etc..
    'id': 'Unique identifier field of the target resource',   // 'Every resource has its own id field for example => clients => clientId, roles => id, realms => realm'
    'keycloak_api': Keycloak API instance, 
    'realm': 'realm where we want to operate, use None for master',
}
'''


class SingleResource:
    def __init__(self, resource):
        self.resource = Resource(resource)
        self.resource_path = resource['path']
        self.body = read_from_json(self.resource_path)
        self.body = remove_unnecessary_fields(self.body)

    def publish(self):
        return self.resource.publish(self.body)

    def name(self):
        return self.resource.name


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
        state = self.resource.publish(self.body)
        return state and self.publish_roles()


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
        state = self.resource.publish(self.body)
        # state is true, but publish_executors returns None
        # Likely, code switched to use Exceptions instead of return True/False.
        # return state and self.publish_executors()
        self.publish_executors()


'''
Read all resource files in a folder and apply SingleResource
'''
class ManyResources:
    def __init__(self, params, ResourceClass=SingleResource):
        path = add_trailing_slash(params['folder'])
        self.resources = map(lambda file_path: ResourceClass({'path': file_path, **params}), get_json_docs_from_folder(path))

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

        self.resources = list( map(lambda path: ResourceClass({'path': path, **params}), files) )


    def publish(self):
        res = []
        for resource in self.resources:
            res.append(resource.publish())

        return res