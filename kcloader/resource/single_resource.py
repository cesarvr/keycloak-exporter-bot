from copy import copy

from kcloader.tools import read_from_json, remove_unnecessary_fields
from kcloader.resource import Resource


class SingleResource:
    def __init__(self, resource, *, body=None, resource_api=None):
        self.resource = Resource(resource, resource_api=resource_api)
        self.resource_path = resource['path']
        # In some cases (client-scope mappers, and others), we have more than one object in a single .json file.
        # For childs, we want to store only part of json file into body
        if body is None:
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

    def get_update_payload(self, obj):
        """
        Modify body if content is not sufficient to update existing object on server.
        Client-scope protocol mapper requires "id" both in URL and payload.

        :param obj: dict as returned by GET HTTP API
        :return: dict ready to be PUT-ed to HTTP API
        """
        body = copy(self.body)
        return body

    def get_create_payload(self):
        return self.body

    def is_update_after_create_needed(self):
        # Authentication flows and some roles cannot be created with required state
        # We need to first create object with some default configuration,
        # then object can be reconfigured.
        return False
