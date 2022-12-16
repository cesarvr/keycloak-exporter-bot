from kcloader.resource import ResourcePublisher


class Resource:
    '''
    params = {
        'path': <string> path to the JSON template, // see the sample_payloads folder
        'name': <string> name of the RH-SSO resource,  // for example clients, realms, roles, etc..
        'id': 'Unique identifier field of the target resource',   // 'Every resource has its own id field for example => clients => clientId, roles => id, realms => realm'
        'keycloak_api': Keycloak API instance,
        'realm': 'realm where we want to operate, use None for master',
    }
    '''
    def __init__(self, params={}):
        self.name = params['name']
        self._resource_api = self.instantiate_api(params)
        self.key = params['id']

    def instantiate_api(self, params):
        kc = params['keycloak_api']
        realm = params['realm']

        if self.name == 'realm':
            return kc.admin()
        else:
            return kc.build(realm=realm, resource_name=self.name)

    # def api(self):
    #     return self._resource_api
    @property
    def resource_api(self):
        return self._resource_api

    def publish(self, body):
        return ResourcePublisher(self.key, body).publish(self._resource_api)

    def remove(self, body):
        id = self.get_resource_id(body)
        if id:
            return self.resource.remove(id).isOk()
        return False
