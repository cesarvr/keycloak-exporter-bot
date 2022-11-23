from kcloader.tools import read_from_json, remove_unnecessary_fields
from kcloader.resource import Resource


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
