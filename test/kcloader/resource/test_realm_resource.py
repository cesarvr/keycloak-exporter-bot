import logging
import json
import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import RealmResource, RealmRoleResource
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase

from kcloader.resource import ClientRoleManager, ClientRoleResource, SingleClientResource

logger = logging.getLogger(__name__)

"""
KC 9.0 - default realm roles are stored in realm.
KC 15.0 - default realm roles are stored in realm role with special name.
"""


class TestRealmResource(TestCaseBase):
    def setUp(self):
        # we do not want to create realm here
        self.testbed = TestBed(realm='ci0-realm')
        testbed = self.testbed
        # create min realm first, ensure clean start
        testbed.kc.admin().remove(testbed.REALM)
        # testbed.kc.admin().create({"realm": testbed.REALM})

        self.realm_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/{testbed.REALM}.json")
        self.realm_roles_api = testbed.kc.build("roles", testbed.REALM)
        self.authentication_flows_api = testbed.kc.build("authentication", testbed.REALM)
        self.realms_api = testbed.kc.admin()
        # self.clients_api = testbed.kc.build("clients", testbed.REALM)
        # check clean start
        realm_objs = self.realms_api.all()
        realm_names = [rr["realm"] for rr in realm_objs]
        self.assertNotIn(self.testbed.REALM, realm_names)
        # assert len(self.realm_roles_api.all()) == 2  # 2 default realm roles (for master realm - 4)

    def test_publish_minimal_representation(self):
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

    def test_publish_default_realm_roles(self):
        # Only default realm roles are tested here.
        # Default client roles are part of client config.
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






