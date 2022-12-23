from kcloader.tools import read_from_json, remove_unnecessary_fields
from kcloader.resource import Resource


class SingleResource:
    def __init__(self, resource):
        self.resource = Resource(resource)
        self.resource_path = resource['path']
        body = read_from_json(self.resource_path)
        self.body = remove_unnecessary_fields(body)

        self.keycloak_api = resource['keycloak_api']
        self.realm_name = resource['realm']

    def publish(self, body=None):
        if body is None:
            body = self.body
        # create or update
        return self.resource.publish(body)

    def name(self):
        return self.resource.name
