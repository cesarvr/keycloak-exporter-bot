import logging
import json
import os
import unittest
from glob import glob
from copy import copy, deepcopy

from kcapi.ie.auth_flows import create_child_flow_data
from kcapi.rest.crud import KeycloakCRUD

from kcloader.resource import RealmResource, RealmRoleResource
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase

from kcloader.resource import ClientRoleManager, ClientRoleResource, SingleClientResource
from kcloader.resource.custom_authentication_resource import AuthenticationFlowResource, \
    AuthenticationExecutionsExecutionResource, AuthenticationExecutionsFlowResource

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


# TODO test also with configurable execution
class TestAuthenticationExecutionsExecutionResource(TestCaseBase):
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

    def test_publish_self(self):
        def _check_state():
            flow0_executions_b = flow0_executions_api.all()
            self.assertEqual(1, len(flow0_executions_b))
            execution_b_noid = copy(flow0_executions_b[0])
            execution_b_noid.pop("id")
            self.assertEqual(execution_doc, execution_b_noid)
            self.assertEqual(flow0_executions_a, flow0_executions_b)

        testbed = self.testbed
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
        data1 = flow0_executions_api.all()[0]
        data1.update({
            "requirement": "ALTERNATIVE",
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


class TestAuthenticationExecutionConfigResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        # '/flows' is magically added to "authentication"
        self.authentication_flows_api = testbed.kc.build("authentication", testbed.REALM)

        # create required auth flow
        self.auth_flow_alias = "ci0-auth-flow-generic"
        self.auth_flow_doc = {
            "alias": "ci0-auth-flow-generic",
            "authenticationExecutions": [],
            "builtIn": False,
            "description": "ci0-auth-flow-generic-desc",
            "providerId": "basic-flow",
            "topLevel": True
        }
        self.authentication_flows_api.create(self.auth_flow_doc).isOk()
        self.this_authentication_flow_executions_api = self.authentication_flows_api.executions(self.auth_flow_doc)

        # # configuration not possible for "direct-grant-validate-username",
        # self.this_authentication_flow_executions_api.create({
        #     # RH SSO 7.4
        #     "provider": "direct-grant-validate-username",
        #     #
        #     # KC 9.0 - does is use different data for POST?
        #     # "authenticator": "direct-grant-validate-username",
        #     # "autheticatorFlow": False,
        #     # "priority": 0,
        #     # "requirement": "REQUIRED",
        #     # "userSetupAllowed": False
        # }).isOk()

        #  "Condition - User Role" - this execution is configurable
        self.this_authentication_flow_executions_api.create({
            "provider": "conditional-user-role",
        })
        self.this_authentication_flow_execution = self.this_authentication_flow_executions_api.findFirstByKV(
            "providerId", "conditional-user-role"
        )

        # return
        # POST {realm}/authentication/executions/{execution_id}/config
        # PUT {realm}/authentication/config/{config_id}
        # xx = self.this_authentication_flow_executions_api.get_child(self.this_authentication_flow_execution["id"], "config", "")
        xx = KeycloakCRUD.get_child(self.this_authentication_flow_executions_api, self.this_authentication_flow_execution["id"], "config")
        xx = xx

    def test_noop(self):
        def _check_state():
            pass

    def x_test_publish_minimal_representation(self):
        return
        def _check_state():
            realm_objs_b = self.realms_api.all()
            realm_obj_b = find_in_list(realm_objs_b, realm=realm_name)
            self.assertEqual(realm_obj_a["id"], realm_obj_b["id"])
            self.assertEqual(realm_obj_a, realm_obj_b)

        realm_roles_api = self.realm_roles_api
        testbed = self.testbed
        realms_api = self.realms_api
        realm_name = testbed.REALM
        realm_resource = RealmResource({
            'path': self.realm_filepath,
            'keycloak_api': testbed.kc,
            'realm': realm_name,
        })

        # publish data - 1st time
        creation_state = realm_resource.publish(minimal_representation=True)
        self.assertTrue(creation_state)
        realm_objs_a = self.realms_api.all()
        realm_obj_a = find_in_list(realm_objs_a, realm=realm_name)
        _check_state()
        # publish same data again - idempotence
        creation_state = realm_resource.publish(minimal_representation=True)
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        data1 = realms_api.findFirstByKV("realm", realm_name)
        data1.update({
            "displayName": "ci0-realm-display-NEW",
            "verifyEmail": True,
        })
        realms_api.update(realm_name, data1)
        data2 = realms_api.findFirstByKV("realm", realm_name)
        self.assertEqual(data1, data2)
        #
        # publish must revert changes
        creation_state = realm_resource.publish(minimal_representation=True)
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = realm_resource.publish(minimal_representation=True)
        self.assertFalse(creation_state)
        _check_state()

    def x_test_publish__default_realm_roles__auth_bindings(self):
        return
        # Only default realm roles are tested here.
        # Default client roles are part of client config.
        #
        # Menu authentication > bindings, what is seen there is stored in realm.json
        # Auth flow can be assigned only if it already exists.
        # Test bindings are correctly created/updated.
        def _check_state():
            realm_objs_b = self.realms_api.all()
            realm_obj_b = find_in_list(realm_objs_b, realm=realm_name)
            self.assertEqual(realm_obj_a["id"], realm_obj_b["id"])
            self.assertEqual(realm_obj_a, realm_obj_b)
            self.assertEqual(
                expected_default_role_names,
                sorted(realm_obj_a["defaultRoles"]),
            )
            self.assertEqual("ci0-auth-flow-generic", realm_obj_a["resetCredentialsFlow"])
            # --------------------------------------------------------------------------------
        return

        our_roles_names = sorted([
            "ci0-role-0",
            # "ci0-role-1",
            # "ci0-role-1a",
            # "ci0-role-1b",
        ])
        blacklisted_roles_names = sorted([
            "offline_access",
            "uma_authorization",
        ])
        expected_default_role_names = sorted(our_roles_names + blacklisted_roles_names)
        realm_roles_api = self.realm_roles_api
        authentication_flows_api = self.authentication_flows_api
        testbed = self.testbed
        realms_api = self.realms_api
        realm_name = testbed.REALM
        realm_resource = RealmResource({
            'path': self.realm_filepath,
            'keycloak_api': testbed.kc,
            'realm': realm_name,
        })

        # prepare - create unconfigured realm
        realms = realms_api.all()
        realm_names = [rr["realm"] for rr in realms]
        self.assertNotIn(realm_name, realm_names)
        realms_api.create({
            "realm": realm_name,
            "displayName": "ci0-realm-display-NOT-CONFIGURED",
        }).isOk()
        realms = realms_api.all()
        realm_names = [rr["realm"] for rr in realms]
        self.assertIn(realm_name, realm_names)

        # prepare - create other required objects - realm roles, auth flows, etc
        realm_role_name = "ci0-role-0"
        realm_roles_api.create({
            "name": realm_role_name,
            "description": realm_role_name + "---CI-INJECTED",
        }).isOk()
        #
        auth_flow_alias = "ci0-auth-flow-generic"  # used for realm resetCredentialsFlow
        auth_flows = authentication_flows_api.all()
        auth_flow_aliases = [auth_flow["alias"] for auth_flow in auth_flows]
        self.assertNotIn(auth_flow_alias, auth_flow_aliases)
        authentication_flows_api.create({
            "alias": auth_flow_alias,
            "providerId": "basic-flow",
            "description": auth_flow_alias + "---TEMP-INJECTED",
            "topLevel": True,
            "builtIn": False
        }).isOk()

        # publish data - 1st time
        creation_state = realm_resource.publish(minimal_representation=False)
        self.assertTrue(creation_state)
        realm_objs_a = self.realms_api.all()
        realm_obj_a = find_in_list(realm_objs_a, realm=realm_name)
        _check_state()
        # publish same data again - idempotence
        creation_state = realm_resource.publish(minimal_representation=False)
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        data1 = realms_api.findFirstByKV("realm", realm_name)
        data1.update({
            "displayName": "ci0-realm-display-NEW",
            "verifyEmail": True,
        })
        realms_api.update(realm_name, data1)
        data2 = realms_api.findFirstByKV("realm", realm_name)
        self.assertEqual(data1, data2)
        #
        # publish must revert changes
        creation_state = realm_resource.publish(minimal_representation=False)
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = realm_resource.publish(minimal_representation=False)
        self.assertFalse(creation_state)
        _check_state()

        # modify default roles, auth-flow
        data1 = realms_api.findFirstByKV("realm", realm_name)
        data1.update({
            "defaultRoles": ["uma_authorization"],
            "resetCredentialsFlow": "browser",
        })
        realms_api.update(realm_name, data1)
        data2 = realms_api.findFirstByKV("realm", realm_name)
        self.assertEqual(data1, data2)
        #
        # publish must revert changes
        creation_state = realm_resource.publish(minimal_representation=False)
        self.assertTrue(creation_state)
        _check_state()
        # publish same data again - idempotence
        creation_state = realm_resource.publish(minimal_representation=False)
        self.assertFalse(creation_state)
        _check_state()

        # minimal_representation=True must not misconfigure existing object
        creation_state = realm_resource.publish(minimal_representation=True)
        self.assertFalse(creation_state)
        _check_state()
