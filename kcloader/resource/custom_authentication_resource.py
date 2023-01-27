import logging
import os
from copy import deepcopy, copy
from glob import glob
from typing import List

import kcapi
from kcapi.ie import AuthenticationFlowsImporter
from kcapi.ie.auth_flows import create_child_flow_data
from kcapi.rest.auth_flows import AuthenticationExecutionsBaseCRUD
from kcapi.rest.crud import KeycloakCRUD
from kcfetcher.utils import normalize
from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import lookup_child_resource, read_from_json
from kcloader.resource.base_manager import BaseManager

logger = logging.getLogger(__name__)


class SingleCustomAuthenticationResource(SingleResource):
    # TODO stop using this
    def __init__(self, resource):
        # assert 0
        super().__init__({'name': 'authentication', 'id':'alias', **resource})

    def publish(self):
        [exists, executors_filepath] = lookup_child_resource(self.resource_path, 'executors/executors.json')
        assert exists
        executors_doc = read_from_json(executors_filepath)

        authentication_api = self.resource.resource_api
        auth_flow_importer = AuthenticationFlowsImporter(authentication_api)
        auth_flow_importer.update(root_node=self.body, flows=executors_doc)
        return True


class AuthenticationFlowManager(BaseManager):
    _resource_name = "authentication"  # kcapi will extend this to "authentication/flows"
    # TODO kcapi should not auto-extend to "authentication/flows" - we need also "authentication/config" etc.
    _resource_id = "alias"
    _resource_delete_id = "id"

    def __init__(
            self,
            keycloak_api: kcapi.sso.Keycloak,
            realm: str,
            datadir: str,
    ):
        super().__init__(keycloak_api, realm, datadir)

        object_filepaths = self._object_filepaths(datadir, realm)
        self.resources = [
            AuthenticationFlowResource({
                'path': object_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for object_filepath in object_filepaths
        ]

    @classmethod
    def _object_filepaths(cls, datadir: str, realm: str):
        return glob(os.path.join(datadir, f"{normalize(realm)}/authentication/flows/*/*.json"))

    def _object_docs(self):
        object_filepaths = self._object_filepaths(self.datadir, self.realm)
        file_docs = [read_from_json(object_filepath) for object_filepath in object_filepaths]
        return file_docs


class AuthenticationFlowResource(SingleResource):
    def __init__(self, resource):
        super().__init__({'name': 'authentication', 'id': 'alias', **resource})
        self.executions_manager = AuthenticationFlowExecutionsManager(
            resource["keycloak_api"],
            resource["realm"],
            resource["datadir"],
            flow_alias=self.body["alias"],
            flow_filepath=resource["path"],
        )

    def publish(self):
        state_self = self.publish_self()
        state_executions = self.publish_executions()
        return any([state_self, state_executions])

    def publish_self(self):
        # body = self.body
        state = self.resource.publish_object(self.body, self)
        return state

    def publish_executions(self):
        state = self.executions_manager.publish()
        return state

    def is_equal(self, obj):
        obj1 = deepcopy(self.body)
        obj2 = deepcopy(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            # authenticationExecutions - are not setup by publish_self, so do not compare them.
            logger.error("auth flow authenticationExecutions is ignored in is_equal")
            oo.pop("authenticationExecutions", None)

        # sort obj2 - it is return by API
        obj1 = SortedDict(obj1)
        obj2 = SortedDict(obj2)

        return obj1 == obj2

    def __kc_90_payload_cleanup(self, payload):
        server_info = self.keycloak_api.server_info
        server_version_major = int(server_info.version.split('.')[0])
        if server_info.profile_name == "community" and server_version_major <= 9:
            # we need to drop "authenticatorFlow" attribute on KC 9.0
            for oo in payload["authenticationExecutions"]:
                oo.pop("authenticatorFlow", None)

    def get_update_payload(self, obj):
        body = deepcopy(self.body)
        # self.__kc_90_payload_cleanup(body)
        return body

    def get_create_payload(self):
        body = deepcopy(self.body)
        self.__kc_90_payload_cleanup(body)
        return body


class FlowExecutorsFactory:
    def __init__(self, top_level_flow_alias):
        self.top_level_flow_alias = top_level_flow_alias

    def create_child_executors(self, resource):
        auth_flow_filepath = resource["path"]
        auth_flow_dirname = os.path.dirname(auth_flow_filepath)
        executors_filepath = os.path.join(auth_flow_dirname, "executors/executors.json")
        executor_docs = read_from_json(executors_filepath)
        resources = []
        for ii in range(len(executor_docs)):
            child_obj = self._create_child_executor(resource, executor_docs, ii)
            resources.append(child_obj)
        return resources

    def _create_child_executor(self, resource, executor_docs: List[dict], executor_pos: int):
        executor_doc = executor_docs[executor_pos]
        if executor_doc.get("authenticationFlow") is True:
            authentication_executions_x_resource_class = AuthenticationExecutionsFlowResource
        else:
            authentication_executions_x_resource_class = AuthenticationExecutionsExecutionResource
        # parent_flow_alias is the intermediate parant flow - the node directly above in tree.
        # It might not be the top-level flow
        parent_flow_alias = self._find_parent_flow_alias(self.top_level_flow_alias, executor_docs, executor_pos)
        child_obj = authentication_executions_x_resource_class(resource, body=executor_doc, flow_alias=parent_flow_alias)
        return child_obj

    @staticmethod
    def _find_parent_flow_alias(top_level_flow_alias: str, executor_docs: List[dict], executor_pos: int):
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


class AuthenticationFlowExecutionsManager(BaseManager):
    # GET /{realm}/authentication/flows/{flowAlias}/executions
    # DELETE /{realm}/authentication/executions/{executionId}
    # _resource_name = ...
    _resource_id = "displayName"
    _resource_delete_id = "id"

    def __init__(
            self,
            keycloak_api: kcapi.sso.Keycloak,
            realm: str,
            datadir: str,
            *,
            flow_alias: str,
            flow_filepath: str,
    ):
        # TODO kcapi should provide XyzCRUD class to merge those two API URLs.
        self._auth_executions_api = keycloak_api.build("authentication/executions", realm)
        self._this_flow_executions_api = keycloak_api.build(f"authentication/flows/{flow_alias}/executions", realm)
        super().__init__(keycloak_api, realm, datadir)

        flow_doc = read_from_json(flow_filepath)
        self._builtin_flow = flow_doc["builtIn"]
        self.flow_alias = flow_alias

        flow_executors_factory = FlowExecutorsFactory(flow_alias)
        resource = {
            'path': flow_filepath,
            'keycloak_api': keycloak_api,
            'realm': realm,
            'datadir': datadir,
        }
        self.resources = flow_executors_factory.create_child_executors(resource)

    def publish(self, **publish_kwargs):
        if self._builtin_flow:
            # TODO if _builtin_flow, then execution.requirement value can be changed,
            # but new executions/subflows cannot be added/removed.
            # Hack - just ignore executions if _builtin_flow.
            logger.warning(f"realm={self.realm} flow_alias={self.flow_alias} is built-in, executions will not be updated.")
            return False
        return super().publish(**publish_kwargs)

    def _object_docs_ids(self):
        return [resource.body["displayName"] for resource in self.resources]

    def _get_server_objects(self):
        executions = self._this_flow_executions_api.all()
        return executions

    def _get_resource_api(self):
        # this one is used to list all objects on server => _get_server_objects() does this,
        # and it cannot use a single resource_api.
        # It is used also to .remove() objects on server.
        return self._auth_executions_api  # will work only for object remove, not for object list

    def remove_server_object(self, delete_obj: dict):
        if self._builtin_flow:
            logger.error(f"Cannot remove execution from a builtin flow. Flow alias={self.flow_alias}, execution displayName={delete_obj['displayName']} id={delete_obj['id']}.")
            return False
        return super().remove_server_object(delete_obj)


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
        # config resource creation is delayed until we get execution_id
        self.config_manager = None

    def publish(self):
        state_self = self.publish_self()
        state_config = self.publish_config()
        return any([state_self, state_config])

    def publish_self(self):
        body = copy(self.body)
        creation_state = self.resource.publish_object(body, self)

        # Create config_manager
        resource_api = self.resource.resource_api
        execution_obj = resource_api.findFirstByKV("displayName", self.body["displayName"])
        self.config_manager = AuthenticationConfigManager(
            self.keycloak_api, self.realm_name, self.datadir,
            requested_doc=self.body.get("authenticationConfigData", {}),
            execution_id=execution_obj["id"],
        )

        return creation_state

    def publish_config(self):
        creation_state = self.config_manager.publish()
        return creation_state

    def is_equal(self, obj):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            # authenticationConfigData, authenticationConfig and alias are created by creating a config sub-object.
            # AuthenticationConfigManager will handle them.
            oo.pop("alias", None)
            oo.pop("authenticationConfig", None)
            oo.pop("authenticationConfigData", None)
            # index and level - we ignore them here
            # resource_api used to get obj is relative to direct parent flow, while
            # data in json file are relative to top-level-flow.
            # We just cannot directly compare numbers.
            # Order will be handled separately.
            oo.pop("index")
            oo.pop("level")
        return obj1 == obj2

    def get_update_payload(self, obj):
        # PUT /{realm}/authentication/flows/{flowAlias}/executions fails if "id" is not also part of payload.
        body = copy(self.body)
        body["id"] = obj["id"]
        body.pop("authenticationConfigData", None)  # alias
        return body

    def get_create_payload(self):
        payload = {
            "provider": self.body["providerId"],
        }
        return payload

    def is_update_after_create_needed(self):
        return True


class AuthenticationExecutionsFlowResource(SingleResource):
    # TODO try to merge this class with AuthenticationFlowResource;
    # they are the same thing, difference is only that AuthenticationFlowResource
    # is for topLevel=True flows.
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

    def publish(self):
        state_self = self.publish_self()
        return state_self

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


class AuthenticationConfigManager(BaseManager):
    # _resource_name = "authentication/executions/{execution_id}/config"
    # _resource_name = "authentication/config/{id}"
    _resource_id = "alias"
    _resource_delete_id = "id"

    def __init__(
            self,
            keycloak_api: kcapi.sso.Keycloak,
            realm: str,
            datadir: str,
            *,
            requested_doc: dict,
            execution_id: str,
    ):
        self._auth_config_api = keycloak_api.build("authentication/config", realm)
        super().__init__(keycloak_api, realm, datadir)
        self._requested_doc = requested_doc
        self._execution_id = execution_id
        #
        self._auth_executions_api = self.keycloak_api.build("authentication/executions", self.realm)
        # self._auth_executions_api.get_one(execution_id)
        # self._execution_config__create_api = KeycloakCRUD.get_child(self._auth_executions_api, execution_id, "config")  # POST {realm}/authentication/executions/{executionId}/config

        self.resources = []
        if self._requested_doc:
            config_resource = AuthenticationConfigResource(
                {
                    'path': "flow0_filepath---ignore",
                    'keycloak_api': self.keycloak_api,
                    'realm': self.realm,
                    'datadir': self.datadir,
                },
                body=self._requested_doc,
                execution_id=execution_id,
            )
            self.resources = [config_resource]

    def _object_docs_ids(self):
        if self._requested_doc:
            return [self._requested_doc["alias"]]
        else:
            return []

    def _get_server_objects(self):
        execution = self._auth_executions_api.get_one(self._execution_id)
        config_id = execution.get("authenticatorConfig", None)
        if not config_id:
            return []
        config = self._auth_config_api.get_one(config_id)
        return [config]

    def _get_resource_api(self):
        # this one is used to list all objects on server => _get_server_objects() does this,
        # and it cannot use a single resource_api.
        # It is used also to .remove() objects on server.
        return self._auth_config_api


class AuthenticationConfigResource(SingleResource):
    # POST {realm}/authentication/executions/{execution_id}/config
    # GET {realm}/authentication/config/{config_id}
    #
    # NB: KeycloakCRUD.all() and related functions cannot work with those URLS -
    # there is not GET for {realm}/authentication/config.
    # Maybe: do not use this class with ResourcePublisher.
    _resource_name = "authentication/config/{config_id}"
    def __init__(
            self,
            resource: dict,
            *,
            body: dict,
            execution_id: int,
    ):
        self.keycloak_api = resource["keycloak_api"]
        self.realm_name = resource['realm']

        self._parent_execution_id = execution_id
        self._auth_executions_api = self.keycloak_api.build("authentication/executions", self.realm_name)
        # self._auth_executions_api.get_one(execution_id)
        self._parent_execution_config__create_api = KeycloakCRUD.get_child(self._auth_executions_api, execution_id, "config")  # POST {realm}/authentication/executions/{executionId}/config
        self._auth_config_api = self.keycloak_api.build("authentication/config", self.realm_name)

        super().__init__(
            {
                "name": self._resource_name,
                "id": "alias",
                **resource,
            },
            body=body,
            resource_api=None,  # this SHOULD BE a reason why to not derive from SingleResource
        )
        self.body = body
        self.datadir = resource['datadir']

    def publish(self):
        server_id, server_obj = self._find_server_object()
        if server_id:
            if self.is_equal(server_obj):
                return False
            payload = self.get_update_payload(server_obj)
            self._auth_config_api.update(server_id, payload).isOk()
            return True
        else:
            payload = self.get_create_payload()
            self._parent_execution_config__create_api.create(payload).isOk()
            return True

    def is_equal(self, obj):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
        return obj1 == obj2

    def _find_server_object(self):
        # equivalent of ResourcePublisher.get_id()
        execution_obj = self._auth_executions_api.get_one(self._parent_execution_id)
        # field has name 'authenticationConfig' or 'authenticatorConfig' - depends on used API endpoint
        if "authenticatorConfig" not in execution_obj:
            return None, None
        config_id = execution_obj["authenticatorConfig"]
        config_obj = self._auth_config_api.get_one(config_id)
        assert config_id == config_obj["id"]
        return config_id, config_obj
