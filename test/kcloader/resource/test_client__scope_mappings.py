import logging
import json
import os
import unittest
from glob import glob
from copy import copy

from kcapi.rest.crud import KeycloakCRUD

from kcloader.resource import ClientScopeResource, ClientClientScopeScopeMappingsRealmManager, \
    RealmClientScopeScopeMappingsClientManager, RealmClientScopeScopeMappingsAllClientsManager
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase

logger = logging.getLogger(__name__)


class TestClientClientScopeScopeMappingsRealmManager(TestCaseBase):
    # Test Client--ClientScope--ScopeMappings--Realm Manager
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.realm_roles_api = testbed.kc.build("roles", testbed.REALM)
        # self.roles_by_id_api = testbed.kc.build("roles-by-id", testbed.REALM)
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)

        # create required client
        clients_all = self.clients_api.all()
        self.assertEqual(len(clients_all), 6 + 0)
        self.clients_api.create(dict(
            clientId="ci0-client-0",
            description="ci0-client-0---CI-INJECTED",
            protocol="openid-connect",
            fullScopeAllowed=False,  # this makes client:scopes configurable
        )).isOk()
        clients_all = self.clients_api.all()
        self.assertEqual(len(clients_all), 6 + 1)
        self.client0 = find_in_list(clients_all, clientId="ci0-client-0")

        # create required realm role
        self.realm_roles_api.create({
            "name": "ci0-role-0",
            "description": "ci0-role-0-desc---CI-injected",
        }).isOk()
        self.role0 = self.realm_roles_api.findFirstByKV("name", "ci0-role-0")
        # create an extra role
        self.realm_roles_api.create({
            "name": "ci0-role-TEMP",
            "description": "ci0-role-TEMP-desc---CI-injected",
        }).isOk()
        self.role_temp = self.realm_roles_api.findFirstByKV("name", "ci0-role-TEMP")

        # create required client role

        # GET /{realm}/clients/{client_id}/scope-mappings/realm
        self.this_client_scopeMappings_realm_api = KeycloakCRUD.get_child(self.clients_api, self.client0["id"], "scope-mappings/realm")

    def test_publish(self):
        def _check_state():
            client_scopeMappings_realm_b = this_client_scopeMappings_realm_api.all()
            self.assertEqual(client_scopeMappings_realm_a[0]["id"], client_scopeMappings_realm_b[0]["id"])
            self.assertEqual(client_scopeMappings_realm_a, client_scopeMappings_realm_b)
            client_scopeMappings_realm_names = [rr["name"] for rr in client_scopeMappings_realm_b]
            self.assertEqual(
                expected_client_scopeMappings_realm_names,
                client_scopeMappings_realm_names,
            )
            # -------------------------------------------

        this_client_scopeMappings_realm_api = self.this_client_scopeMappings_realm_api
        # requested_client_scopeMappings_realm_names - needs to be computed
        # from ci0-realm/clients/client-0/scope-mappings.json
        requested_client_scopeMappings_realm_names = ["ci0-role-0"]
        expected_client_scopeMappings_realm_names = ["ci0-role-0"]

        # check initial state
        self.assertEqual([], this_client_scopeMappings_realm_api.all())

        # create/update
        manager = ClientClientScopeScopeMappingsRealmManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
            requested_doc=requested_client_scopeMappings_realm_names,
            client_id=self.client0["id"],
        )
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        client_scopeMappings_realm_a = this_client_scopeMappings_realm_api.all()
        _check_state()
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # add one extra mapping, it needs to be removed
        self.assertEqual(1, len(this_client_scopeMappings_realm_api.all()))
        realm_role_extra = self.realm_roles_api.findFirstByKV("name", "ci0-role-TEMP")
        realm_role_extra.pop("attributes")
        this_client_scopeMappings_realm_api.create([realm_role_extra])
        self.assertEqual(2, len(this_client_scopeMappings_realm_api.all()))
        #
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

