import logging
from copy import deepcopy, copy

from kcapi.ie import AuthenticationFlowsImporter
from kcapi.rest.auth_flows import AuthenticationExecutionsExecutionCRUD
from kcapi.rest.crud import KeycloakCRUD
from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import lookup_child_resource, read_from_json

logger = logging.getLogger(__name__)


class SingleCustomAuthenticationResource(SingleResource):
    # TODO stop using this
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


class AuthenticationFlowResource(SingleResource):
    def __init__(self, resource):
        super().__init__({'name': 'authentication', 'id':'alias', **resource})

    def publish(self):
        state_self = self.publish_self()
        return any([state_self])

    def publish_self(self):
        # body = self.body
        state = self.resource.publish_object(self.body, self)

        # Now we have client id, and can get URL to client roles
        flow = self.resource.resource_api.findFirstByKV("alias", self.body["alias"])

        return state

        # return
        # [exists, executors_filepath] = lookup_child_resource(self.resource_path, 'executors/executors.json')
        # assert exists
        # executors_doc = read_from_json(executors_filepath)
        #
        # authentication_api = self.resource.resource_api
        # auth_flow_importer = AuthenticationFlowsImporter(authentication_api)
        # auth_flow_importer.update(root_node=self.body, flows=executors_doc)
        # return True

    def is_equal(self, obj):
        obj1 = deepcopy(self.body)
        obj2 = deepcopy(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            # authenticationExecutions - are not setup by publish_self
            logger.error("auth flow authenticationExecutions is ignored in is_equal")
            oo.pop("authenticationExecutions", None)

        # sort obj2 - it is return by API
        obj1 = SortedDict(obj1)
        obj2 = SortedDict(obj2)

        return obj1 == obj2


class AuthenticationExecutionsExecutionResource(SingleResource):
    _resource_name = "authentication/executions/{execution_id}"
    # POST /{realm}/authentication/executions
    # POST /{realm}/authentication/flows/{flowAlias}/executions/execution  <- this one
    # POST /{realm}/authentication/flows/{flowAlias}/executions/flow
    # PUT /{realm}/authentication/config/{id}

    def __init__(
            self,
            resource: dict,
            *,
            body: dict,
            flow_alias
    ):
        self.keycloak_api = resource["keycloak_api"]
        self.realm_name = resource['realm']

        # protocol_mapper_api = self._get_resource_api()
        # clients_api = self.keycloak_api.build("clients", self.realm_name)
        # protocol_mapper_api = KeycloakCRUD.get_child(clients_api, self._client_id, "protocol-mappers/models")
        execution_doc = body
        auth_api = self.keycloak_api.build("authentication", self.realm_name)
        auth_flow_obj = dict(alias=flow_alias)
        resource_api = auth_api.executions(auth_flow_obj)
        assert isinstance(resource_api, AuthenticationExecutionsExecutionCRUD)  # unusual .update()
        super().__init__(
            {
                "name": self._resource_name,
                "id": "displayName",  # displayName ? and/or alias - but alias is there only if config is added.
                **resource,
            },
            body=body,
            resource_api=resource_api,
        )
        self.datadir = resource['datadir']

    def publish_self(self):
        body = copy(self.body)
        creation_state = self.resource.publish_object(body, self)
        return creation_state

    def is_equal(self, obj):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
        return obj1 == obj2

    def get_update_payload(self, obj):
        # PUT /{realm}/authentication/flows/{flowAlias}/executions fails if "id" is not also part of payload.
        body = copy(self.body)
        body["id"] = obj["id"]
        return body

    def get_create_payload(self):
        payload = {
            "provider": self.body["providerId"],
        }
        return payload
