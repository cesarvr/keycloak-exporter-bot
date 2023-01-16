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

        # our_roles_names = sorted([
        #     "ci0-role-0",
        #     # "ci0-role-1",
        #     # "ci0-role-1a",
        #     # "ci0-role-1b",
        # ])
        # blacklisted_roles_names = sorted([
        #     "offline_access",
        #     "uma_authorization",
        # ])
        # expected_default_role_names = sorted(our_roles_names + blacklisted_roles_names)
        # testbed = self.testbed
        realm_roles_api = self.realm_roles_api
        testbed = self.testbed
        realms_api = self.realms_api
        realm_name = testbed.REALM
        realm_resource = RealmResource({
            'path': self.realm_filepath,
            'keycloak_api': testbed.kc,
            'realm': realm_name,
        })

        # check initial state
        # realm_objs = realms_api.all()
        # realm_obj = find_in_list(realm_objs, realm=realm_name)
        # self.assertEqual(blacklisted_roles_names, sorted(realm_obj["defaultRoles"]))
        # roles = realm_roles_api.all()
        # self.assertEqual(
        #     blacklisted_roles_names,
        #     sorted([role["name"] for role in roles])
        # )

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

        return

        # ------------------------------------------------------------------------------
        # create an additional role
        realm_roles_api.create({
            "name": "ci0-role-x-to-be-deleted",
            "description": "ci0-role-x-to-be-DELETED",
        }).isOk()
        roles = realm_roles_api.all()
        self.assertEqual(6 + 1, len(roles))
        self.assertEqual(
            sorted(our_roles_names + blacklisted_roles_names + ["ci0-role-x-to-be-deleted"]),
            sorted([role["name"] for role in roles])
        )

        create_ids, delete_objs = manager._difference_ids()
        delete_ids = sorted([obj["name"] for obj in delete_objs])
        self.assertEqual([], create_ids)
        self.assertEqual(['ci0-role-x-to-be-deleted'], delete_ids)

        # check extra role is deleted
        creation_state = manager.publish(include_composite=include_composite)
        self.assertTrue(creation_state)
        roles = realm_roles_api.all()
        self.assertEqual(6, len(roles))
        self.assertEqual(
            expected_roles_names,
            sorted([role["name"] for role in roles])
        )






