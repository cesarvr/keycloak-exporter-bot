from kcloader.resource import ResourcePublisher


class Resource:
    '''
    params = {
        'path': <string> path to the JSON template, // see the sample_payloads folder
        'name': <string> name of the RH-SSO resource,  // for example clients, realms, roles, etc..
        'id': 'Unique identifier field of the target resource',   // 'Every resource has its own id field for example => clients => clientId, roles => name, realms => realm'
        'keycloak_api': Keycloak API instance,
        'realm': 'realm where we want to operate, use None for master',
    }
    '''
    def __init__(self, params={}, *, resource_api=None):
        self.name = params['name']
        if resource_api is None:
            resource_api = self.instantiate_api(params)
        self._resource_api = resource_api
        self.key = params['id']

    def instantiate_api(self, params):
        kc = params['keycloak_api']
        realm = params['realm']

        if self.name == 'realm':
            return kc.admin()
        elif self.name == 'clients/TODO-client_id/roles':
            # TODO kcapi should be able to .build() same api as returned by client.roles()...
            # This looks like URL routing logic is needed in kc.build()
            # The "if self.name == 'realm'" - this is URL routing logic.
            # We continue with this logic.
            return params["client_roles_api"]
        else:
            return kc.build(realm=realm, resource_name=self.name)

    # def api(self):
    #     return self._resource_api
    @property
    def resource_api(self):
        return self._resource_api

    def publish(self, body):
        return ResourcePublisher(self.key, body).publish(self._resource_api)

    def publish_object(self, body, single_resource, params=None):
        return ResourcePublisher(self.key, body, single_resource, params).publish(self._resource_api)

    def remove(self, body):
        id = self.get_resource_id(body)
        if id:
            return self.resource.remove(id).isOk()
        return False
