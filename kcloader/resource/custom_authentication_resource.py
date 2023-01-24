import logging
import os
from copy import deepcopy, copy
from glob import glob
from typing import List

from kcapi.ie import AuthenticationFlowsImporter
from kcapi.ie.auth_flows import create_child_flow_data
from kcapi.rest.auth_flows import AuthenticationExecutionsBaseCRUD
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
        super().__init__({'name': 'authentication', 'id': 'alias', **resource})
        self._create_child_executors(resource)

    def _create_child_executors(self, resource):
        auth_flow_filepath = resource["path"]
        auth_flow_dirname = os.path.dirname(auth_flow_filepath)
        executors_filepath = os.path.join(auth_flow_dirname, "executors/executors.json")
        executor_docs = read_from_json(executors_filepath)
        self.resources = []
        for ii in range(len(executor_docs)):
            child_obj = self._create_child_executor(resource, executor_docs, ii)
            self.resources.append(child_obj)

    def _create_child_executor(self, resource, executor_docs: List[dict], executor_pos: int):
        executor_doc = executor_docs[executor_pos]
        if executor_doc.get("authenticationFlow") is True:
            authentication_executions_x_resource_class = AuthenticationExecutionsFlowResource
        else:
            authentication_executions_x_resource_class = AuthenticationExecutionsExecutionResource
        # parent_flow_alias is the intermediate parant flow - the node directly above in tree.
        # It might not be the top-level flow
        parent_flow_alias = self._find_parent_flow_alias(self.body["alias"], executor_docs, executor_pos)
        child_obj = authentication_executions_x_resource_class(resource, body=executor_doc, flow_alias=parent_flow_alias)
        return child_obj

    @staticmethod
    def _find_parent_flow_alias(top_level_flow_alias:str, executor_docs: List[dict], executor_pos: int):
        """
        Input data in executors.json is like:
        pos     level   index   note
        0       0       0       direct child of top-level flow, level==0
        1       0       1
        2       0       2
        3       1       0       child of flow at pos=2
        4       0       3
        5       1       0       child of flow at pos=4
        6       1       1
        7       1       2
        8       1       3
        9       2       0       child of flow at pos=8
        10      2       1
        11      1       4       child of flow at pos=4
        """
        executor_doc = executor_docs[executor_pos]
        executor_level = executor_doc["level"]
        if executor_level == 0:
            return top_level_flow_alias
        parent_level = executor_level - 1
        for parent_candidate in reversed(executor_docs[:executor_pos]):
            if parent_candidate["level"] == parent_level:
                # executor_docs is a list of executors (executions?)
                # It is not a list of flows (maybe kcfetcher should be refactored).
                # The displayName is same as corresponding flow alias.
                return parent_candidate["displayName"]
            # between this child and parent should be only child flows with same level,
            # or their childs.
            assert parent_candidate["level"] >= executor_level

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

    def publish_executions(self):
        state_all = [resource.publish_self() for resource in self.resources]
        return any(state_all)

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
        assert isinstance(resource_api, AuthenticationExecutionsBaseCRUD)  # unusual .update()
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


class AuthenticationExecutionsFlowResource(SingleResource):
    _resource_name = "authentication/executions/{execution_id}"
    # POST /{realm}/authentication/flows/{flowAlias}/executions/flow  <- this one

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
        resource_api = auth_api.flows(auth_flow_obj)
        assert isinstance(resource_api, AuthenticationExecutionsBaseCRUD)  # unusual .update()
        super().__init__(
            {
                "name": self._resource_name,
                "id": "displayName",
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
            oo.pop("flowId", None)
            # To create a child flow, POST to {realm}/authentication/flows/{parent_flow_alias}/executions is done.
            # parent_flow_alias is intermediate parent (might not be topLevel flow).
            # The GET URL in resource_api is also relative to intermediate parent.
            # This means index and level in obj are not same is in self.body.
            # Ignore them here, and reorder object in separate step.
            oo.pop("index", None)
            oo.pop("level", None)
        return obj1 == obj2

    def get_update_payload(self, obj):
        # PUT /{realm}/authentication/flows/{flowAlias}/executions fails if "id" is not also part of payload.
        body = copy(self.body)
        body["id"] = obj["id"]
        return body

    def get_create_payload(self):
        payload = create_child_flow_data(self.body)
        return payload

    def is_update_after_create_needed(self):
        return True
