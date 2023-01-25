import logging
import json
import os
import unittest
from glob import glob
from copy import copy, deepcopy
from unittest import TestCase

from kcapi.ie.auth_flows import create_child_flow_data
from kcapi.rest.crud import KeycloakCRUD

from kcloader.resource import RealmResource, RealmRoleResource
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase

from kcloader.resource import ClientRoleManager, ClientRoleResource, SingleClientResource
from kcloader.resource.custom_authentication_resource import AuthenticationFlowResource, \
    AuthenticationExecutionsExecutionResource, AuthenticationExecutionsFlowResource, \
    AuthenticationConfigResource, AuthenticationConfigManager, \
    AuthenticationFlowManager, FlowExecutorsFactory

logger = logging.getLogger(__name__)

"""
objects
realm has 0:N auth_flows
auth_flow has 0:N executions
executions has 0:1 configs

relevant APIs
auth_flow:
GET    /{realm}/authentication/flows
GET    /{realm}/authentication/flows/{id}
POST   /{realm}/authentication/flows
PUT    /{realm}/authentication/flows/{id}
DELETE /{realm}/authentication/flows/{id}
#
GET /{realm}/authentication/flows/{flowAlias}/executions
PUT /{realm}/authentication/flows/{flowAlias}/executions
POST /{realm}/authentication/flows/{flowAlias}/executions/execution
#
POST /{realm}/authentication/flows/{flowAlias}/executions/flow

execution:
GET /{realm}/authentication/executions/{executionId}
POST /{realm}/authentication/executions
DELETE /{realm}/authentication/executions/{executionId}
# 
POST /{realm}/authentication/executions/{executionId}/lower-priority
POST /{realm}/authentication/executions/{executionId}/raise-priority
#
POST /{realm}/authentication/executions/{executionId}/config


execution_config:
GET /{realm}/authentication/config/{id}
POST
PUT /{realm}/authentication/config/{id}
DELETE /{realm}/authentication/config/{id}




new required action??
POST /{realm}/authentication/register-required-action
GET /{realm}/authentication/unregistered-required-actions
#
GET /{realm}/authentication/required-actions
GET /{realm}/authentication/required-actions/{alias}
PUT /{realm}/authentication/required-actions/{alias}
DELETE /{realm}/authentication/required-actions/{alias}
#
POST /{realm}/authentication/required-actions/{alias}/lower-priority
POST /{realm}/authentication/required-actions/{alias}/raise-priority
"""

class TestAuthenticationFlowManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.authentication_flows_api = testbed.kc.build("authentication", testbed.REALM)
        # self.authentication_config_api = testbed.kc.build("authentication/config", testbed.REALM)
        # self.authentication_executions_api = testbed.kc.build("authentication/executions", testbed.REALM)
        self.flow0_alias = "ci0-auth-flow-generic"
        self.extra_flow_alias = "ci0-flow-EXTRA"

    def test_publish(self):
        def _check_state():
            flows_b = self.authentication_flows_api.all()
            self.assertEqual(9, len(flows_b))
            self.assertEqual(flows_a, flows_b)
            # ---------------------------------------------------------------

        testbed = self.testbed
        authentication_flows_api = self.authentication_flows_api
        flows_x = authentication_flows_api.all()
        self.assertEqual(8, len(flows_x))

        manager = AuthenticationFlowManager(self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR)

        # publish data - 1st time
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        flows_a = self.authentication_flows_api.all()
        _check_state()
        # publish same data again - idempotence
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something - add extra top-level flow
        self.assertEqual(9, len(authentication_flows_api.all()))
        authentication_flows_api.create({
            "alias": self.extra_flow_alias,
            "authenticationExecutions": [],
            "builtIn": False,
            "description": self.extra_flow_alias + "-desc",
            "providerId": "basic-flow",
            "topLevel": True,
        }).isOk()
        self.assertEqual(10, len(authentication_flows_api.all()))
        #
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # remove the flow0_alias server. Manager needs to recreate it.
        flow0 = authentication_flows_api.findFirstByKV("alias", self.flow0_alias)
        self.assertEqual(9, len(authentication_flows_api.all()))
        authentication_flows_api.remove(flow0["id"], None)
        self.assertEqual(8, len(authentication_flows_api.all()))
        #
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        # new flow has new id, update it in expected data
        flow0_new = authentication_flows_api.findFirstByKV("alias", self.flow0_alias)
        flow0_new_id = flow0_new["id"]
        flow0_a = find_in_list(flows_a, alias=self.flow0_alias)
        flow0_a["id"] = flow0_new_id
        _check_state()
        # publish same data again - idempotence
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify some existing flow.
        # intentionally, modify a builtin flow.
        flow1_alias = "browser"
        flow1_executions_api = self.testbed.kc.build(f"authentication/flows/{flow1_alias}/executions", self.testbed.realm)
        flow1_execution0_a = flow1_executions_api.all()[0]
        self.assertNotEqual(flow1_execution0_a["requirement"], "REQUIRED")
        flow1_execution0_a["requirement"] = "REQUIRED"
        flow1_executions_api.update(None, flow1_execution0_a).isOk()
        flow1_execution0_b = flow1_executions_api.all()[0]
        self.assertEqual(flow1_execution0_a, flow1_execution0_b)
        #
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()


class TestAuthenticationFlowResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        # '/flows' is magically added to "authentication"
        self.authentication_flows_api = testbed.kc.build("authentication", testbed.REALM)

        self.flow0_alias = "ci0-auth-flow-generic"
        flow0_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/authentication/flows/ci0-auth-flow-generic/ci0-auth-flow-generic.json")
        self.flow0_resource = AuthenticationFlowResource({
            'path': flow0_filepath,
            'keycloak_api': testbed.kc,
            'realm': testbed.REALM,
            'datadir': testbed.DATADIR,
        })
        self.flow0_executions_api = self.testbed.kc.build(f"authentication/flows/{self.flow0_alias}/executions", self.testbed.realm)

    def test_publish_self(self):
        def _check_state():
            flow0_b = self.authentication_flows_api.findFirstByKV("alias", self.flow0_alias)
            flow0_noid = deepcopy(flow0_b)
            flow0_noid.pop("id")
            self.assertEqual(expected_flow0, flow0_noid)
            self.assertEqual(flow0_a, flow0_b)

            # -----------------------------------------
        testbed = self.testbed
        flow0_resource = self.flow0_resource
        expected_flow0 = deepcopy(flow0_resource.body)
        expected_flow0["authenticationExecutions"] = []

        # publish data - 1st time
        creation_state = flow0_resource.publish_self()
        self.assertTrue(creation_state)
        flow_objs_a = self.authentication_flows_api.all()
        flow0_a = find_in_list(flow_objs_a, alias=self.flow0_alias)
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_resource.publish_self()
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        return
        data1 = self.authentication_flows_api.findFirstByKV("alias", self.flow0_alias)
        data1.update({
            "description": "ci0-auth-flow-generic-desc---NEW",
        })
        # This DOES update description, but with 500 error on RH SSO 7.4.
        # No need to support this. Description is the only field that could be edited anyway.
        self.authentication_flows_api.update(data1["id"], data1).isOk()
        data2 = self.authentication_flows_api.findFirstByKV("alias", self.flow0_alias)
        self.assertEqual(data1, data2)
        #

    def test_publish_child_executions_flows(self):
        # Test .publish_executions()
        def _check_state():
            flow0_b = self.authentication_flows_api.findFirstByKV("alias", self.flow0_alias)
            flow0_noid = deepcopy(flow0_b)
            flow0_noid.pop("id")
            self.assertEqual(expected_flow0, flow0_noid)
            self.assertEqual(flow0_a, flow0_b)
            executions_b = self.flow0_executions_api.all()
            self.assertEqual(6, len(executions_b))
            self.assertEqual(executions_a, executions_b)

            # -----------------------------------------
        self.maxDiff = None
        testbed = self.testbed
        flow0_resource = self.flow0_resource
        expected_flow0 = deepcopy(flow0_resource.body)
        if self.testbed.kc.server_info.profile_name == "community":
            # keycloak (9.0), it will not include "authenticatorFlow" in API response.
            # Testdata was generated with RH SSO 7.4.
            for execution in expected_flow0["authenticationExecutions"]:
                execution.pop("authenticatorFlow")
            # TODO implement
            # execution.pop("authenticatorConfig", None)
            # if execution["authenticator"] == "auth-conditional-otp-form":
            #    execution["requirement"] = "DISABLED"

        # prepare parent top-level flow
        creation_state = flow0_resource.publish_self()
        self.assertTrue(creation_state)

        # publish data - 1st time
        creation_state = flow0_resource.publish_executions()
        self.assertTrue(creation_state)
        flow_objs_a = self.authentication_flows_api.all()
        flow0_a = find_in_list(flow_objs_a, alias=self.flow0_alias)
        executions_a = self.flow0_executions_api.all()
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_resource.publish_executions()
        self.assertFalse(creation_state)
        _check_state()

        # modify flow - add extra executions/execution
        self.assertEqual(6, len(self.flow0_executions_api.all()))
        flow0_executions_api = self.flow0_resource.resource.resource_api.executions(dict(alias=self.flow0_alias))
        # will trigger bug - non-unique displayName
        extra_flow_payload = {"provider": "auth-conditional-otp-form"}
        extra_flow_payload = {"provider":"auth-otp-form"}
        flow0_executions_api.create(extra_flow_payload).isOk()
        self.assertEqual(7, len(self.flow0_executions_api.all()))
        #
        # publish data - 1st time
        creation_state = flow0_resource.publish_executions()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_resource.publish_executions()
        self.assertFalse(creation_state)
        _check_state()

        # modify flow - add extra executions/flow
        # click 'add flow', flow type = generic, provider = registration-page-form
        # POST payload, {"alias":"aa1","type":"basic-flow","description":"aa2","provider":"registration-page-form"}
        extra_flow_payload = {
            "alias": "aa1",
            "type": "basic-flow",
            "description": "aa2",
            "provider": "registration-page-form",
        }
        flow0_flows_api = self.flow0_resource.resource.resource_api.flows(dict(alias=self.flow0_alias))
        flow0_flows_api.create(extra_flow_payload).isOk()
        self.assertEqual(7, len(self.flow0_executions_api.all()))
        #
        # publish data - 1st time
        creation_state = flow0_resource.publish_executions()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_resource.publish_executions()
        self.assertFalse(creation_state)
        _check_state()

        # modify flow - remove one child execution
        ind = 1
        self.assertEqual("Conditional OTP Form", executions_a[ind]["displayName"])
        self.assertEqual(6, len(self.flow0_executions_api.all()))
        flow0_executions_api.remove(executions_a[ind]["id"]).isOk()
        self.assertEqual(5, len(self.flow0_executions_api.all()))
        #
        # publish data - 1st time
        creation_state = flow0_resource.publish_executions()
        self.assertTrue(creation_state)
        # update expected execution_id
        executions_new = self.flow0_executions_api.all()
        if 0:
            logger.error("This test would fail, the execution order is not managed.")
            return
        executions_a[ind]["id"] = executions_new[ind]["id"]
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_resource.publish_executions()
        self.assertFalse(creation_state)
        _check_state()

        # modify flow - remove one child sub-flow
        #
        # publish data - 1st time
        creation_state = flow0_resource.publish_executions()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_resource.publish_executions()
        self.assertFalse(creation_state)
        _check_state()


class TestFlowExecutorsFactory(TestCase):
    def test_find_parent_flow_alias(self):
        # , top_level_flow_alias:str, executor_docs: List[dict], executor_pos: int):
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
        executor_docs = [
            dict(displayName="p0",  level=0, index=0, expected_parent="top"),
            dict(displayName="p1",  level=0, index=1, expected_parent="top"),
            dict(displayName="p2",  level=0, index=2, expected_parent="top"),
            dict(displayName="p3",  level=1, index=0, expected_parent="p2"),
            dict(displayName="p4",  level=0, index=3, expected_parent="top"),
            dict(displayName="p5",  level=1, index=0, expected_parent="p4"),
            dict(displayName="p6",  level=1, index=1, expected_parent="p4"),
            dict(displayName="p7",  level=1, index=2, expected_parent="p4"),
            dict(displayName="p8",  level=1, index=3, expected_parent="p4"),
            dict(displayName="p9",  level=2, index=0, expected_parent="p8"),
            dict(displayName="p10", level=2, index=1, expected_parent="p8"),
            dict(displayName="p11", level=1, index=4, expected_parent="p4"),
            dict(displayName="p12", level=0, index=4, expected_parent="top"),
        ]
        factory = FlowExecutorsFactory("top")
        for ii in range(len(executor_docs)):
            expected_parent_flow_alias = executor_docs[ii]["expected_parent"]
            parent_flow_alias = factory._find_parent_flow_alias("top", executor_docs, ii)
            self.assertEqual(expected_parent_flow_alias, parent_flow_alias)


class TestAuthenticationExecutionsFlowResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.authentication_flows_api = testbed.kc.build("authentication", testbed.REALM)
        self.flow0_alias = "ci0-auth-flow-generic"
        self.authentication_flows_api.create({
            "alias": self.flow0_alias,
            "authenticationExecutions": [],
            "builtIn": False,
            "description": self.flow0_alias + "-desc",
            "providerId": "basic-flow",
            "topLevel": True,
        }).isOk()

        self.flow0 = self.authentication_flows_api.findFirstByKV("alias", "ci0-auth-flow-generic")
        self.flow0_executions_api = KeycloakCRUD.get_child(self.authentication_flows_api, self.flow0_alias, "executions")
        self.flow0_executions_execution_api = self.authentication_flows_api.executions(self.flow0)
        self.flow0_executions_flow_api = self.authentication_flows_api.flows(self.flow0)

    def test_publish_self_a(self):
        # click 'add flow', flow type = generic, provider = registration-page-form
        # POST payload, {"alias":"aa1","type":"basic-flow","description":"aa2","provider":"registration-page-form"}
        # Returned data at ci0-realm/authentication/flows/ci0-auth-flow-generic/executions
        flow0_a_doc = {
            # "id": "62cd0d9f-83da-41a8-80b2-7ec42f1999d0",
            "requirement": "DISABLED",
            "displayName": "aa1",
            "requirementChoices": [
                "REQUIRED",
                "ALTERNATIVE",
                "DISABLED",
                "CONDITIONAL"
            ],
            "configurable": False,
            "authenticationFlow": True,
            # "flowId": "97cb1b49-4187-47ec-82b3-ad2a6bdffd90",
            "level": 0,
            "index": 0
        }
        flow0_a_doc_inline = {
            "authenticator": "registration-page-form",
            "authenticatorFlow": True,
            "requirement": "DISABLED",
            "priority": 0,
            "flowAlias": "aa1",
            "userSetupAllowed": False,
            "autheticatorFlow": True
        }
        self.do_test_publish_self(flow0_a_doc)

    def test_publish_self_b(self):
        # click 'add flow', flow type = form, provider = registration-page-form
        # POST paylaod {"alias":"bb1","type":"form-flow","description":"bb2","provider":"registration-page-form"}
        # Returned data at ci0-realm/authentication/flows/ci0-auth-flow-generic/executions
        flow0_b_doc = {
            # "id": "e3dc18e5-ece6-4b16-9d8a-549145b4ce6f",
            "requirement": "DISABLED",
            "displayName": "bb1",
            "requirementChoices": [
                "REQUIRED",
                "DISABLED"
            ],
            "configurable": False,
            "authenticationFlow": True,
            "providerId": "registration-page-form",
            # "flowId": "97930c79-78ec-42e9-a4c5-ed32f8d34f6f",
            "level": 0,
            "index": 0
        }
        flow0_b_doc_inline = {
            "authenticator": "registration-page-form",
            "authenticatorFlow": True,
            "requirement": "DISABLED",
            "priority": 0,
            "flowAlias": "bb1",
            "userSetupAllowed": False,
            "autheticatorFlow": True
        }
        #
        # "type":"form-flow" or "type":"basic-flow" - use create_child_flow_data() from kcapi.
        self.do_test_publish_self(flow0_b_doc)

    def do_test_publish_self(self, flow0_a_doc):
        def _check_state():
            flow0_executions_b = flow0_executions_api.all()
            self.assertEqual(1, len(flow0_executions_b))
            execution_b_noid = copy(flow0_executions_b[0])
            execution_b_noid.pop("id")
            execution_b_noid.pop("flowId")  # flowId points back to self; I think.
            self.assertEqual(flow0_a_doc, execution_b_noid)
            self.assertEqual(flow0_executions_a, flow0_executions_b)

        testbed = self.testbed
        flow0_executions_api = self.flow0_executions_api
        flow0_executions_flow_api = self.flow0_executions_flow_api

        # initial state
        self.assertEqual(0, len(flow0_executions_api.all()))

        if 0:
            # TEMP
            payload = create_child_flow_data(flow0_a_doc)
            flow0_executions_flow_api.create(payload).isOk()
            flow0_executions_a = flow0_executions_api.all()
            _check_state()

        flow0_a_resource = AuthenticationExecutionsFlowResource(
            {
                'path': "flow0_filepath---ignore",
                'keycloak_api': testbed.kc,
                'realm': testbed.REALM,
                'datadir': testbed.DATADIR,
            },
            body=flow0_a_doc,
            flow_alias=self.flow0_alias,
        )

        # publish data - 1st time
        creation_state = flow0_a_resource.publish_self()
        self.assertTrue(creation_state)
        flow0_executions_a = flow0_executions_api.all()
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_a_resource.publish_self()
        self.assertFalse(creation_state)
        _check_state()

        # modify something - cannot be done in UI

    # flow can have sub-flows
    def test_publish_self__child_flow(self):
        def _check_state():
            flow0_executions_b = flow0_executions_api.all()
            self.assertEqual(2, len(flow0_executions_b))
            flow0_executions_b_noid = deepcopy(flow0_executions_b)
            for oo in flow0_executions_b_noid:
                oo.pop("id")
                oo.pop("flowId")  # flowId points back to self; I think.
                # oo.pop("requirement")  # TEMP
            # self.assertEqual(flow0_3_doc, flow0_executions_b_noid[0])
            self.assertEqual(flow0_3_1_doc, flow0_executions_b_noid[1])
            self.assertEqual(flow0_executions_a, flow0_executions_b)

        self.maxDiff = None
        testbed = self.testbed
        flow0_executions_api = self.flow0_executions_api
        flow0_executions_flow_api = self.flow0_executions_flow_api


        flow0_3_doc = {
            "authenticationFlow": True,
            "configurable": False,
            "displayName": "ci0-auth-flow-generic-exec-3-generic-alias",
            "index": 0,
            "level": 0,
            "requirement": "CONDITIONAL",
            "requirementChoices": [
                "REQUIRED",
                "ALTERNATIVE",
                "DISABLED",
                "CONDITIONAL"
            ]
        }
        flow0_3_1_doc = {
            "authenticationFlow": True,
            "configurable": False,
            "displayName": "ci0-auth-flow-generic-exec-3-1-flow-alias",
            "index": 0,
            "level": 1,
            "requirement": "ALTERNATIVE",
            "requirementChoices": [
                "REQUIRED",
                "ALTERNATIVE",
                "DISABLED",
                "CONDITIONAL"
            ]
        }

        # initial state
        self.assertEqual(0, len(flow0_executions_api.all()))

        # inject parent flow
        payload = create_child_flow_data(flow0_3_doc)
        flow0_executions_flow_api.create(payload).isOk()
        flow0_executions_a = flow0_executions_api.all()
        self.assertEqual(1, len(flow0_executions_api.all()))

        flow0_3_1__parent_alias = flow0_3_doc["displayName"] # TODO compute from index/level and all docs.
        flow0_3_1_resource = AuthenticationExecutionsFlowResource(
            {
                'path': "flow0_filepath---ignore",
                'keycloak_api': testbed.kc,
                'realm': testbed.REALM,
                'datadir': testbed.DATADIR,
            },
            body=flow0_3_1_doc,
            flow_alias=flow0_3_1__parent_alias,
        )

        # publish data - 1st time
        creation_state = flow0_3_1_resource.publish_self()
        self.assertTrue(creation_state)
        flow0_executions_a = flow0_executions_api.all()
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_3_1_resource.publish_self()
        self.assertFalse(creation_state)
        _check_state()


# TODO test also with configurable execution
class TestAuthenticationExecutionsExecutionResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.authentication_flows_api = testbed.kc.build("authentication", testbed.REALM)
        self.authentication_config_api = testbed.kc.build("authentication/config", testbed.REALM)
        self.authentication_executions_api = testbed.kc.build("authentication/executions", testbed.REALM)
        self.flow0_alias = "ci0-auth-flow-generic"
        self.authentication_flows_api.create({
            "alias": self.flow0_alias,
            "authenticationExecutions": [],
            "builtIn": False,
            "description": self.flow0_alias + "-desc",
            "providerId": "basic-flow",
            "topLevel": True,
        }).isOk()

        self.flow0 = self.authentication_flows_api.findFirstByKV("alias", "ci0-auth-flow-generic")
        self.flow0_executions_api = KeycloakCRUD.get_child(self.authentication_flows_api, self.flow0_alias, "executions")
        self.flow0_executions_execution_api = self.authentication_flows_api.executions(self.flow0)
        self.flow0_executions_flow_api = self.authentication_flows_api.flows(self.flow0)

    def test_publish_self__simple(self):
        # POST paylaod, {"provider":"auth-otp-form"}
        # Created object is
        execution_doc = {
            "requirement": "DISABLED",
            "displayName": "OTP Form",
            "requirementChoices": [
                "REQUIRED",
                "ALTERNATIVE",
                "DISABLED"
            ],
            "configurable": False,
            "providerId": "auth-otp-form",
            "level": 0,
            "index": 0
        }
        self.do_test_publish_self(execution_doc)

    def test_publish_self__from_json(self):
        # kcfetcher adds to json also authenticationConfigData.
        execution_doc = {
            "alias": "ci0-auth-flow-generic-exec-20-alias",
            "authenticationConfigData": {
                "alias": "ci0-auth-flow-generic-exec-20-alias",
                "config": {
                    "defaultOtpOutcome": "skip",
                    "forceOtpForHeaderPattern": "ci0-force-header",
                    "forceOtpRole": "ci0-client-0.ci0-client0-role0",
                    "noOtpRequiredForHeaderPattern": "ci0-skip-header",
                    "otpControlAttribute": "user-attr",
                    "skipOtpRole": "ci0-role-1"
                }
            },
            "configurable": True,
            "displayName": "Conditional OTP Form",
            "index": 0,
            "level": 0,
            "providerId": "auth-conditional-otp-form",
            "requirement": "ALTERNATIVE",
            "requirementChoices": [
                "REQUIRED",
                "ALTERNATIVE",
                "DISABLED"
            ]
        }
        self.do_test_publish_self(execution_doc)

    def do_test_publish_self(self, execution_doc):
        def _check_state():
            flow0_executions_b = flow0_executions_api.all()
            self.assertEqual(1, len(flow0_executions_b))
            execution_b_noid = copy(flow0_executions_b[0])
            execution_b_noid.pop("id")
            self.assertEqual(expected_execution, execution_b_noid)
            self.assertEqual(flow0_executions_a, flow0_executions_b)

        self.maxDiff = None
        testbed = self.testbed
        flow0_executions_api = self.flow0_executions_api
        flow0_execution_resource = AuthenticationExecutionsExecutionResource(
            {
                'path': "flow0_filepath---ignore",
                'keycloak_api': testbed.kc,
                'realm': testbed.REALM,
                'datadir': testbed.DATADIR,
            },
            body=execution_doc,
            flow_alias=self.flow0_alias,
        )

        expected_execution = deepcopy(execution_doc)
        expected_execution.pop("authenticationConfigData", None)
        expected_execution.pop("alias", None)

        # publish data - 1st time
        creation_state = flow0_execution_resource.publish_self()
        self.assertTrue(creation_state)
        flow0_executions_a = flow0_executions_api.all()
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_execution_resource.publish_self()
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        # there is no PUT for "authentication/executions", so use
        # PUT /{realm}/authentication/flows/{flowAlias}/executions
        assert execution_doc["requirement"] != "REQUIRED"
        data1 = flow0_executions_api.all()[0]
        data1.update({
            "requirement": "REQUIRED",
        })
        flow0_executions_api.update(None, data1).isOk()
        data2 = flow0_executions_api.all()[0]
        self.assertEqual(data1, data2)
        #
        creation_state = flow0_execution_resource.publish_self()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_execution_resource.publish_self()
        self.assertFalse(creation_state)
        _check_state()

    def test_publish(self):
        def _check_state():
            flow0_executions_b = self.flow0_executions_api.all()
            self.assertEqual(1, len(flow0_executions_b))
            self.assertEqual(flow0_executions_a, flow0_executions_b)
            #
            config_id_b = flow0_executions_b[0]["authenticationConfig"]
            config_obj_b = authentication_config_api.get_one(config_id_b)
            self.assertEqual(config_id_a, config_id_b)
            self.assertEqual(config_obj_a, config_obj_b)
            #
            execution_obj_b = authentication_executions_api.get_one(flow0_executions_b[0]["id"])
            execution_id_b = execution_obj_b["id"]
            self.assertIn("authenticatorConfig", execution_obj_b)
            self.assertEqual(execution_id_a, execution_id_b)
            self.assertEqual(execution_obj_a, execution_obj_b)
            # ---------------------------------------------------------------

        def _check_state2():
            flow0_executions_b = self.flow0_executions_api.all()
            self.assertEqual(1, len(flow0_executions_b))
            flow0_executions_a_temp = deepcopy(flow0_executions_a)
            flow0_executions_a_temp[0].pop("authenticationConfig")
            flow0_executions_a_temp[0].pop("alias")
            self.assertEqual(flow0_executions_a_temp, flow0_executions_b)
            #
            self.assertNotIn("authenticationConfig", flow0_executions_b[0])
            #
            execution_obj_b = authentication_executions_api.get_one(flow0_executions_b[0]["id"])
            execution_id_b = execution_obj_b["id"]
            self.assertNotIn("authenticatorConfig", execution_obj_b)
            self.assertEqual(execution_id_a, execution_id_b)
            execution_obj_a_temp = deepcopy(execution_obj_a)
            execution_obj_a_temp.pop("authenticatorConfig")
            self.assertEqual(execution_obj_a_temp, execution_obj_b)
            # ---------------------------------------------------------------

        # kcfetcher adds to json also authenticationConfigData (it replaces authenticationConfig UUID).
        # 'alias' in API response is side effect of assigining config.
        execution_doc = {
            "alias": "ci0-auth-flow-generic-exec-20-alias",
            "authenticationConfigData": {
                "alias": "ci0-auth-flow-generic-exec-20-alias",
                "config": {
                    "defaultOtpOutcome": "skip",
                    "forceOtpForHeaderPattern": "ci0-force-header",
                    "forceOtpRole": "ci0-client-0.ci0-client0-role0",
                    "noOtpRequiredForHeaderPattern": "ci0-skip-header",
                    "otpControlAttribute": "user-attr",
                    "skipOtpRole": "ci0-role-1"
                }
            },
            "configurable": True,
            "displayName": "Conditional OTP Form",
            "index": 0,
            "level": 0,
            "providerId": "auth-conditional-otp-form",
            "requirement": "ALTERNATIVE",
            "requirementChoices": [
                "REQUIRED",
                "ALTERNATIVE",
                "DISABLED"
            ]
        }

        self.maxDiff = None
        testbed = self.testbed
        authentication_config_api = self.authentication_config_api
        authentication_executions_api = self.authentication_executions_api
        flow0_executions_api = self.flow0_executions_api
        flow0_execution_resource = AuthenticationExecutionsExecutionResource(
            {
                'path': "flow0_filepath---ignore",
                'keycloak_api': testbed.kc,
                'realm': testbed.REALM,
                'datadir': testbed.DATADIR,
            },
            body=execution_doc,
            flow_alias=self.flow0_alias,
        )
        expected_execution = deepcopy(execution_doc)

        execution_doc2 = deepcopy(execution_doc)
        execution_doc2.pop("alias")
        execution_doc2.pop("authenticationConfigData")
        flow0_execution_resource2 = AuthenticationExecutionsExecutionResource(
            {
                'path': "flow0_filepath---ignore",
                'keycloak_api': testbed.kc,
                'realm': testbed.REALM,
                'datadir': testbed.DATADIR,
            },
            body=execution_doc2,
            flow_alias=self.flow0_alias,
        )

        # publish data - 1st time
        creation_state = flow0_execution_resource.publish()
        self.assertTrue(creation_state)
        flow0_executions_a = flow0_executions_api.all()
        execution_obj_a = authentication_executions_api.get_one(flow0_executions_a[0]["id"])
        execution_id_a = execution_obj_a["id"]
        config_id_a = flow0_executions_a[0]["authenticationConfig"]
        config_obj_a = authentication_config_api.get_one(config_id_a)
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_execution_resource.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        # there is no PUT for "authentication/executions", so use
        # PUT /{realm}/authentication/flows/{flowAlias}/executions
        assert execution_doc["requirement"] != "REQUIRED"
        data1 = flow0_executions_api.all()[0]
        data1.update({
            "requirement": "REQUIRED",
        })
        flow0_executions_api.update(None, data1).isOk()
        data2 = flow0_executions_api.all()[0]
        self.assertEqual(data1, data2)
        #
        creation_state = flow0_execution_resource.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_execution_resource.publish()
        self.assertFalse(creation_state)
        _check_state()

        # remove config, or just modify it
        data1 = authentication_config_api.get_one(config_id_a)
        data1["config"].update({
            "otpControlAttribute": "user-attr-NEW",
        })
        authentication_config_api.update(config_id_a, data1).isOk()
        data2 = authentication_config_api.get_one(config_id_a)
        self.assertEqual(data1, data2)
        #
        creation_state = flow0_execution_resource.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = flow0_execution_resource.publish()
        self.assertFalse(creation_state)
        _check_state()

        # request config removal
        creation_state = flow0_execution_resource2.publish()
        self.assertTrue(creation_state)
        _check_state2()
        # publish same data again - idempotence
        creation_state = flow0_execution_resource2.publish()
        self.assertFalse(creation_state)
        _check_state2()


class TestAuthenticationConfigResource(TestCaseBase):
    # POST /{realm}/authentication/executions/{executionId}/config
    # GET /{realm}/authentication/config/{id}
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.authentication_flows_api = testbed.kc.build("authentication", testbed.REALM)
        self.authentication_config_api = testbed.kc.build("authentication/config", testbed.REALM)
        self.flow0_alias = "ci0-auth-flow-generic"
        self.authentication_flows_api.create({
            "alias": self.flow0_alias,
            "authenticationExecutions": [],
            "builtIn": False,
            "description": self.flow0_alias + "-desc",
            "providerId": "basic-flow",
            "topLevel": True,
        }).isOk()

        self.flow0 = self.authentication_flows_api.findFirstByKV("alias", "ci0-auth-flow-generic")
        self.flow0_executions_api = KeycloakCRUD.get_child(self.authentication_flows_api, self.flow0_alias, "executions")
        self.flow0_executions_execution_api = self.authentication_flows_api.executions(self.flow0)
        self.flow0_executions_flow_api = self.authentication_flows_api.flows(self.flow0)

        self.execution_doc = {
            # "alias": "ci0-auth-flow-generic-exec-20-alias",
            # "authenticationConfigData": {...}
            "configurable": True,
            "displayName": "Conditional OTP Form",
            "index": 0,
            "level": 0,
            "providerId": "auth-conditional-otp-form",
            "requirement": "ALTERNATIVE",
            "requirementChoices": [
                "REQUIRED",
                "ALTERNATIVE",
                "DISABLED"
            ]
        }
        self.flow0_executions_execution_api.create({
            "provider":"auth-conditional-otp-form",
        })

        self.config_doc = {
            "alias": "ci0-auth-flow-generic-exec-20-alias",
            "config": {
                "defaultOtpOutcome": "skip",
                "forceOtpForHeaderPattern": "ci0-force-header",
                "forceOtpRole": "ci0-client-0.ci0-client0-role0",
                "noOtpRequiredForHeaderPattern": "ci0-skip-header",
                "otpControlAttribute": "user-attr",
                "skipOtpRole": "ci0-role-1"
            }
        }
        # config_create_payload = {"config":{"noOtpRequiredForHeaderPattern":"","forceOtpForHeaderPattern":""},"alias":"aaa"}
        # POST ci0-realm/authentication/executions/{execution_id}/config
        # GET ci0-realm/authentication/config/{config_id}

    def test_publish(self):
        def _check_state():
            flow0_executions_b = self.flow0_executions_api.all()
            self.assertEqual(1, len(flow0_executions_b))
            config_id_b = flow0_executions_b[0]["authenticationConfig"]
            config_obj_b = authentication_config_api.get_one(config_id_b)
            self.assertEqual(flow0_executions_a, flow0_executions_b)
            self.assertEqual(config_obj_a, config_obj_b)
            # ---------------------------------------------------------------

        testbed = self.testbed
        flow0_executions_api = self.flow0_executions_api
        authentication_config_api = self.authentication_config_api
        flow0_executions = flow0_executions_api.all()
        self.assertEqual(1, len(flow0_executions))
        execution_id = flow0_executions[0]["id"]

        config_resource = AuthenticationConfigResource(
            {
                'path': "flow0_filepath---ignore",
                'keycloak_api': testbed.kc,
                'realm': testbed.REALM,
                'datadir': testbed.DATADIR,
            },
            body=self.config_doc,
            execution_id=execution_id,
        )

        # publish data - 1st time
        creation_state = config_resource.publish()
        self.assertTrue(creation_state)
        flow0_executions_a = flow0_executions_api.all()
        config_id_a = flow0_executions_a[0]["authenticationConfig"]
        config_obj_a = authentication_config_api.get_one(config_id_a)
        _check_state()
        # publish same data again - idempotence
        creation_state = config_resource.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        data1 = authentication_config_api.get_one(config_id_a)
        self.assertEqual(config_obj_a, data1)
        data1["config"].update({
            "forceOtpForHeaderPattern": "ci0-force-header-NEW",
        })
        authentication_config_api.update(config_id_a, data1)
        data2 = authentication_config_api.get_one(config_id_a)
        self.assertEqual(data1, data2)
        #
        creation_state = config_resource.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = config_resource.publish()
        self.assertFalse(creation_state)
        _check_state()


class TestAuthenticationConfigManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.authentication_flows_api = testbed.kc.build("authentication", testbed.REALM)
        self.authentication_config_api = testbed.kc.build("authentication/config", testbed.REALM)
        self.authentication_executions_api = testbed.kc.build("authentication/executions", testbed.REALM)
        self.flow0_alias = "ci0-auth-flow-generic"
        self.authentication_flows_api.create({
            "alias": self.flow0_alias,
            "authenticationExecutions": [],
            "builtIn": False,
            "description": self.flow0_alias + "-desc",
            "providerId": "basic-flow",
            "topLevel": True,
        }).isOk()

        self.flow0 = self.authentication_flows_api.findFirstByKV("alias", "ci0-auth-flow-generic")
        self.flow0_executions_api = KeycloakCRUD.get_child(self.authentication_flows_api, self.flow0_alias, "executions")
        self.flow0_executions_execution_api = self.authentication_flows_api.executions(self.flow0)
        self.flow0_executions_flow_api = self.authentication_flows_api.flows(self.flow0)

        self.execution_doc = {
            "alias": "ci0-auth-flow-generic-exec-20-alias",
            "authenticationConfigData": {
                "alias": "ci0-auth-flow-generic-exec-20-alias",
                "config": {
                    "defaultOtpOutcome": "skip",
                    "forceOtpForHeaderPattern": "ci0-force-header",
                    "forceOtpRole": "ci0-client-0.ci0-client0-role0",
                    "noOtpRequiredForHeaderPattern": "ci0-skip-header",
                    "otpControlAttribute": "user-attr",
                    "skipOtpRole": "ci0-role-1"
                }
            },
            "configurable": True,
            "displayName": "Conditional OTP Form",
            "index": 0,
            "level": 0,
            "providerId": "auth-conditional-otp-form",
            "requirement": "ALTERNATIVE",
            "requirementChoices": [
                "REQUIRED",
                "ALTERNATIVE",
                "DISABLED"
            ]
        }
        self.flow0_executions_execution_api.create({
            "provider":"auth-conditional-otp-form",
        })

        # config_create_payload = {"config":{"noOtpRequiredForHeaderPattern":"","forceOtpForHeaderPattern":""},"alias":"aaa"}
        # POST ci0-realm/authentication/executions/{execution_id}/config
        # GET ci0-realm/authentication/config/{config_id}

    def test_publish(self):
        def _check_state():
            flow0_executions_b = self.flow0_executions_api.all()
            self.assertEqual(1, len(flow0_executions_b))
            self.assertEqual(flow0_executions_a, flow0_executions_b)
            #
            config_id_b = flow0_executions_b[0]["authenticationConfig"]
            config_obj_b = authentication_config_api.get_one(config_id_b)
            self.assertEqual(config_id_a, config_id_b)
            self.assertEqual(config_obj_a, config_obj_b)
            #
            execution_obj_b = authentication_executions_api.get_one(flow0_executions_b[0]["id"])
            execution_id_b = execution_obj_b["id"]
            self.assertEqual(execution_id_a, execution_id_b)
            self.assertEqual(execution_obj_a, execution_obj_b)
            # ---------------------------------------------------------------

        testbed = self.testbed
        flow0_executions_api = self.flow0_executions_api
        authentication_executions_api = self.authentication_executions_api
        authentication_config_api = self.authentication_config_api
        flow0_executions = flow0_executions_api.all()
        self.assertEqual(1, len(flow0_executions))
        execution_id = flow0_executions[0]["id"]
        requested_doc = self.execution_doc.get("authenticationConfigData", {})

        manager = AuthenticationConfigManager(
            self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR,
            requested_doc=requested_doc, execution_id=execution_id,
        )

        # publish data - 1st time
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        flow0_executions_a = flow0_executions_api.all()
        execution_obj_a = authentication_executions_api.get_one(flow0_executions_a[0]["id"])
        execution_id_a = execution_obj_a["id"]
        config_id_a = flow0_executions_a[0]["authenticationConfig"]
        config_obj_a = authentication_config_api.get_one(config_id_a)
        _check_state()
        # publish same data again - idempotence
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        data1 = authentication_config_api.get_one(config_id_a)
        self.assertEqual(config_obj_a, data1)
        data1["config"].update({
            "forceOtpForHeaderPattern": "ci0-force-header-NEW",
        })
        authentication_config_api.update(config_id_a, data1)
        data2 = authentication_config_api.get_one(config_id_a)
        self.assertEqual(data1, data2)
        #
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # remove the config from server. Manager needs to recreate it.
        execution_obj = authentication_executions_api.get_one(execution_id_a)
        self.assertIn("authenticatorConfig", execution_obj)
        authentication_config_api.remove(config_id_a, None).isOk()
        execution_obj = authentication_executions_api.get_one(execution_id_a)
        self.assertNotIn("authenticatorConfig", execution_obj)
        #
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        # update expected data - new config id
        execution_obj_new = authentication_executions_api.get_one(execution_id_a)
        config_id_new = execution_obj_new["authenticatorConfig"]
        flow0_executions_a[0]["authenticationConfig"] = config_id_new
        execution_obj_a["authenticatorConfig"] = config_id_new
        config_id_a = config_id_new
        config_obj_a["id"] = config_id_new
        #
        _check_state()
        # publish same data again - idempotence
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # test manager does remove config, but does not recreate execution
        requested_doc2 = {}
        manager2 = AuthenticationConfigManager(
            self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR,
            requested_doc=requested_doc2, execution_id=execution_id,
        )
        execution_obj_new = authentication_executions_api.get_one(execution_id_a)
        self.assertEqual(execution_id_a, execution_obj_new["id"])
        self.assertIn("authenticatorConfig", execution_obj_new)
        #
        creation_state = manager2.publish()
        self.assertTrue(creation_state)
        execution_obj_new = authentication_executions_api.get_one(execution_id_a)
        self.assertEqual(execution_id_a, execution_obj_new["id"])
        self.assertNotIn("authenticatorConfig", execution_obj_new)
        #
        creation_state = manager2.publish()
        self.assertFalse(creation_state)
        execution_obj_new = authentication_executions_api.get_one(execution_id_a)
        self.assertEqual(execution_id_a, execution_obj_new["id"])
        self.assertNotIn("authenticatorConfig", execution_obj_new)
