import logging
import json
import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import ClientScopeResource
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase

logger = logging.getLogger(__name__)


class TestClientScopeResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        # self.client0_clientId = "ci0-client-0"
        # self.clients_api = testbed.kc.build("clients", testbed.REALM)
        # self.realm_roles_api = testbed.kc.build("roles", testbed.REALM)
        # self.roles_by_id_api = testbed.kc.build("roles-by-id", testbed.REALM)
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)

    def test_publish_simple(self):
        # client-scope, no roles assigned, no mappers assigned
        def _check_state():
            client_scopes_b = client_scopes_api.all()
            client_scope_b = find_in_list(client_scopes_b, name=client_scope_name)
            self.assertEqual(client_scope_a["id"], client_scope_b["id"])
            self.assertEqual(client_scope_a, client_scope_b)

            scope_mappings = this_client_scope_scope_mappings_api.all()
            self.assertEqual({}, scope_mappings)
            # API return something like:
            # {'realmMappings': [{'id': 'd0eb5122-8c45-42ec-906f-6f16a5e753ca', 'name': 'offline_access',
            #                     'description': '${role_offline-access}', 'composite': False, 'clientRole': False,
            #                     'containerId': 'a33bdcf4-33df-428e-adc4-a49eaf126ee7'}],
            #  'clientMappings': {
            #     'account': {'id': 'dbb3bd75-9cb1-44fe-a333-813d3757c155', 'client': 'account', 'mappings': [
            #         {'id': 'bd599fd1-73c8-48ce-bc7a-0562b1ebc8a1', 'name': 'manage-account',
            #          'description': '${role_manage-account}', 'composite': True, 'clientRole': True,
            #          'containerId': 'dbb3bd75-9cb1-44fe-a333-813d3757c155'}]}}}

        client_scope_name = "ci0-client-scope-1-saml"
        client_scopes_api = self.client_scopes_api
        client_scope_filepath = os.path.join(self.testbed.DATADIR, f"ci0-realm/client-scopes/{client_scope_name}.json")
        with open(client_scope_filepath) as ff:
            expected_client_scope = json.load(ff)
            expected_client_scope_clientScopeMappings = expected_client_scope.pop("clientScopeMappings")
            expected_client_scope_scopeMappings = expected_client_scope.pop("scopeMappings")

        blacklisted_client_scopes = sorted([
            "address",
            "email",
            "microprofile-jwt",
            "offline_access",
            "phone",
            "profile",
            "role_list",
            "roles",
            "web-origins",
        ])

        client_scope_resource = ClientScopeResource({
            'path': client_scope_filepath,
            'keycloak_api': self.testbed.kc,
            'realm': self.testbed.REALM,
            'datadir': self.testbed.DATADIR,
        })

        # check initial state
        client_scopes = client_scopes_api.all()
        self.assertEqual(
            blacklisted_client_scopes,
            sorted([client_scope["name"] for client_scope in client_scopes]),
        )

        # publish data - 1st time
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertTrue(creation_state)
        client_scopes_a = client_scopes_api.all()
        client_scope_a = find_in_list(client_scopes_a, name=client_scope_name)
        # GET /{realm}/client-scopes/{id}/scope-mappings
        this_client_scope_scope_mappings_api = client_scopes_api.get_child(client_scopes_api, client_scope_a["id"], "scope-mappings")
        _check_state()

        # publish data - 2nd time, idempotence
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        data = client_scopes_api.findFirstByKV("name", client_scope_name)
        data.update({
            "description": 'ci0-client-scope-1-saml-desc-NEW',
            "attributes": {
                # Hm, , KC 9.0 - new attribute was added, it did not replace old attributes.
                # Also web UI is not able to remove such attribute.\
                # Better to not use this.
                # "key-CI-injected": "value-CI-injected",
                'consent.screen.text': 'ci0-client-scope-1-saml-consent-text-NEW',
            },
        })
        client_scopes_api.update(client_scope_a["id"], data)
        client_scope_c = client_scopes_api.findFirstByKV("name", client_scope_name)
        self.assertEqual(client_scope_a["id"], client_scope_c["id"])
        self.assertEqual("ci0-client-scope-1-saml-desc-NEW", client_scope_c["description"])
        self.assertEqual(
            {
                'consent.screen.text': 'ci0-client-scope-1-saml-consent-text-NEW',
                'display.on.consent.screen': 'true',
                'include.in.token.scope': 'true',
                # "key-CI-injected": "value-CI-injected",
            },
            client_scope_c["attributes"],
        )
        # .publish must revert change
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertFalse(creation_state)
        _check_state()
