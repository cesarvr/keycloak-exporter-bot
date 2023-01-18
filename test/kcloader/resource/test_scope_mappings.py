import logging
import json
import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import ClientScopeResource, ClientScopeScopeMappingsRealmManager, \
    ClientScopeProtocolMapperResource, ClientScopeProtocolMapperManager, \
    ClientScopeScopeMappingsClientManager, ClientScopeScopeMappingsAllClientsManager, \
    ClientScopeManager
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase

logger = logging.getLogger(__name__)


class TestClientScopeScopeMappingsRealmManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        # self.client0_clientId = "ci0-client-0"
        # self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.realm_roles_api = testbed.kc.build("roles", testbed.REALM)
        # self.roles_by_id_api = testbed.kc.build("roles-by-id", testbed.REALM)
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)

        # create required realm role
        self.realm_roles_api.create({
            "name": "ci0-role-0",
            "description": "ci0-role-0-desc---CI-injected",
        })
        self.realm_roles_api.create({
            "name": "ci0-role-TEMP",
            "description": "ci0-role-TEMP-desc---CI-injected",
        })

        # create required client_scope
        self.client_scope_name = "ci0-client-scope"  # this one is complex
        client_scope_name = self.client_scope_name
        client_scopes_api = self.client_scopes_api
        self.client_scope_filepath = os.path.join(self.testbed.DATADIR, f"ci0-realm/client-scopes/{client_scope_name}.json")
        with open(self.client_scope_filepath) as ff:
            self.expected_client_scope = json.load(ff)
            self.expected_client_scope_scope_mappings_realm = self.expected_client_scope["scopeMappings"]["roles"]
        self.client_scope_resource = ClientScopeResource({
            'path': self.client_scope_filepath,
            'keycloak_api': self.testbed.kc,
            'realm': self.testbed.REALM,
            'datadir': self.testbed.DATADIR,
        })
        creation_state = self.client_scope_resource.publish_self()
        self.assertTrue(creation_state)
        client_scopes = client_scopes_api.all()
        self.assertEqual(9 + 1, len(client_scopes))  # there are 9 default client scopes
        self.client_scope = find_in_list(client_scopes, name=client_scope_name)
        client_scope_id = self.client_scope["id"]

        # GET /{realm}/client-scopes/{id}/scope-mappings
        # self.this_client_scope_scope_mappings_api = client_scopes_api.get_child(client_scopes_api, self.client_scope["id"], "scope-mappings")
        # self.this_client_scope_scope_mappings_api = ClientScopeScopeMappingsCRUD.get_child(client_scopes_api, self.client_scope["id"], "scope-mappings")
        self.this_client_scope_scope_mappings_api = client_scopes_api.scope_mappings_api(client_scope_id=client_scope_id)
        self.this_client_scope_scope_mappings_realm_api = client_scopes_api.scope_mappings_realm_api(client_scope_id=client_scope_id)
        # self.this_client_scope_scope_mappings_api = client_scopes_api.scope_mappings_client_api(client_scope_id=client_scope_id, client_id=client_id)

    def test_publish(self):
        def _check_state():
            client_scope_b = client_scopes_api.findFirstByKV("name", client_scope_name)
            self.assertEqual(client_scope_a["id"], client_scope_b["id"])
            self.assertEqual(client_scope_a, client_scope_b)
            client_scope_scope_mappings_realm_objs = this_client_scope_scope_mappings_realm_api.all()
            client_scope_scope_mappings_realm = [rr["name"] for rr in client_scope_scope_mappings_realm_objs]
            self.assertEqual(
                self.expected_client_scope_scope_mappings_realm,
                client_scope_scope_mappings_realm,
            )
            # -------------------------------------------

        client_scopes_api = self.client_scopes_api
        realm_roles_api = self.realm_roles_api
        client_scope_name = self.client_scope_name
        this_client_scope_scope_mappings_realm_api = self.this_client_scope_scope_mappings_realm_api

        client_scope_a = client_scopes_api.findFirstByKV("name", client_scope_name)

        # create/update
        # self.client_scope_resource.body["scopeMappings"]
        # client_scope_scope_mappings == cssm
        cssm_realm_manager = ClientScopeScopeMappingsRealmManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
            requested_doc=self.expected_client_scope["scopeMappings"],
            client_scope_id=self.client_scope["id"],
        )
        creation_state = cssm_realm_manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = cssm_realm_manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # add one extra mapping, it needs to be removed
        self.assertEqual(1, len(this_client_scope_scope_mappings_realm_api.all()))
        realm_role_extra = self.realm_roles_api.findFirstByKV("name", "ci0-role-TEMP")
        realm_role_extra.pop("attributes")
        this_client_scope_scope_mappings_realm_api.create([realm_role_extra])
        self.assertEqual(2, len(this_client_scope_scope_mappings_realm_api.all()))
        #
        creation_state = cssm_realm_manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = cssm_realm_manager.publish()
        self.assertFalse(creation_state)
        _check_state()


class TestClientScopeScopeMappingsClientManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)
        self.client_scope_name = "ci0-client-scope"
        self.client_scope_filepath = os.path.join(
            self.testbed.DATADIR,
            f"ci0-realm/client-scopes/{self.client_scope_name}.json",
        )
        client_scope_doc = read_from_json(self.client_scope_filepath)
        self.client_scopes_api.create(client_scope_doc).isOk()
        client_scopes = self.client_scopes_api.all()
        self.client_scope = find_in_list(client_scopes, name=self.client_scope_name)
        self.assertEqual(self.client_scope_name, self.client_scope["name"])

        self.client_clientId = "account"
        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.client = self.clients_api.findFirstByKV("clientId", self.client_clientId)
        client_query = dict(key="id", value=self.client["id"])
        self.this_client_roles_api = self.clients_api.roles(client_query)
        self.client_role_name = "view-profile"
        self.client_role = self.this_client_roles_api.findFirstByKV(
            "name", self.client_role_name,
            params=dict(briefRepresentation=True),
        )

        self.cssm_client_api = self.client_scopes_api.scope_mappings_client_api(
            client_scope_id=self.client_scope["id"],
            client_id=self.client["id"],
        )

    def test_publish(self):
        def _check_state():
            assigned_client_roles = sorted(cssm_client_api.all(), key=lambda d: d['name'])
            self.assertEqual(expected_client_roles, assigned_client_roles)
            # -------------------------------------

        self.maxDiff = None
        cssm_client_api = self.cssm_client_api
        requested_client_role_names = [self.client_role_name]
        expected_client_roles = [self.client_role]
        cssm_client_manager = ClientScopeScopeMappingsClientManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
            requested_doc=requested_client_role_names,  # this is normally read from json file
            client_scope_id=self.client_scope["id"],
            client_id=self.client["id"],
        )

        # check initial state - no roles assigned
        self.assertEqual([], cssm_client_api.all())

        # publish data - 1st time
        creation_state = cssm_client_manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = cssm_client_manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # add extra mapping to some role
        extra_role_name = "view-consent"
        extra_role = self.this_client_roles_api.findFirstByKV(
            "name", extra_role_name,
            params=dict(briefRepresentation=True),
        )
        self.assertEqual(1, len(cssm_client_api.all()))
        cssm_client_api.create([extra_role])
        self.assertEqual(2, len(cssm_client_api.all()))
        #
        # publish data - 1st time
        creation_state = cssm_client_manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = cssm_client_manager.publish()
        self.assertFalse(creation_state)
        _check_state()


class TestClientScopeScopeMappingsAllClientsManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)
        self.client_scope_name = "ci0-client-scope"
        self.client_scope_filepath = os.path.join(
            self.testbed.DATADIR,
            f"ci0-realm/client-scopes/{self.client_scope_name}.json",
        )
        self.client_scope_doc = read_from_json(self.client_scope_filepath)
        self.client_scopes_api.create(self.client_scope_doc).isOk()
        client_scopes = self.client_scopes_api.all()
        self.client_scope = find_in_list(client_scopes, name=self.client_scope_name)
        self.assertEqual(self.client_scope_name, self.client_scope["name"])

        self.client_clientId = "account"
        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.client = self.clients_api.findFirstByKV("clientId", self.client_clientId)
        client_query = dict(key="id", value=self.client["id"])
        this_client_roles_api = self.clients_api.roles(client_query)
        self.client_role_name = "view-profile"
        self.client_role = this_client_roles_api.findFirstByKV(
            "name", self.client_role_name,
            params=dict(briefRepresentation=True),
        )

        # self.cssm_client_api = self.client_scopes_api.scope_mappings_client_api(
        #     client_scope_id=self.client_scope["id"],
        #     client_id=self.client["id"],
        # )
        self.cssm_api = self.client_scopes_api.scope_mappings_api(
            client_scope_id=self.client_scope["id"],
        )

    def test_publish(self):
        def _check_state():
            assigned_scope_mappings = cssm_api.all()
            self.assertEqual(expected_scope_mappings, assigned_scope_mappings)
            # -------------------------------------

        self.maxDiff = None
        cssm_api = self.cssm_api
        # requested_client_scope_mappings is clientScopeMappings field in json file
        requested_client_scope_mappings = self.client_scope_doc["clientScopeMappings"]
        self.assertEqual(
            requested_client_scope_mappings,
            {
                "account": [
                    "view-profile",
                ],
            }
        )
        # expected_client_roles = [self.client_role]
        expected_scope_mappings = {
            "clientMappings": {
                "account": {
                    "client": "account",
                    "id": self.client["id"],
                    "mappings": [
                        self.client_role,
                    ],
                }
            }
        }
        cssm_clients_manager = ClientScopeScopeMappingsAllClientsManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
            requested_doc=requested_client_scope_mappings,
            client_scope_id=self.client_scope["id"],
        )

        # check initial state - no roles assigned
        self.assertEqual({}, cssm_api.all())

        # publish data - 1st time
        creation_state = cssm_clients_manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = cssm_clients_manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # add extra mapping to some role
        extra_client_clientId = "broker"
        extra_client = self.clients_api.findFirstByKV("clientId", extra_client_clientId)
        extra_role_name = "read-token"
        client_query = dict(key="id", value=extra_client["id"])
        extra_client_roles_api = self.clients_api.roles(client_query)
        extra_role = extra_client_roles_api.findFirstByKV(
            "name", extra_role_name,
            params=dict(briefRepresentation=True),
        )
        extra_cssm_client_api = self.client_scopes_api.scope_mappings_client_api(
            client_scope_id=self.client_scope["id"],
            client_id=extra_client["id"],
        )
        cssm = cssm_api.all()
        self.assertEqual(1, len(cssm))
        self.assertEqual(1, len(cssm["clientMappings"]))
        extra_cssm_client_api.create([extra_role])
        cssm = cssm_api.all()
        self.assertEqual(1, len(cssm))
        self.assertEqual(2, len(cssm["clientMappings"]))
        #
        # publish data - 1st time
        creation_state = cssm_clients_manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = cssm_clients_manager.publish()
        self.assertFalse(creation_state)
        _check_state()
