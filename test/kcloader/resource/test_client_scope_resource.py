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


class TestClientScopeResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.realm_roles_api = testbed.kc.build("roles", testbed.REALM)
        # self.roles_by_id_api = testbed.kc.build("roles-by-id", testbed.REALM)
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)

    def setUp_roles(self):
        # create needed realm role
        self.realm_roles_api.create(dict(
            name="ci0-role-0",
            description="ci0-role-0-decs---CI-injected",
        )).isOk()

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
            },
            client_scope_c["attributes"],
        )
        #
        # .publish must revert change
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertFalse(creation_state)
        _check_state()

    def test_publish_mappers(self):
        def _check_state():
            client_scopes_b = client_scopes_api.all()
            client_scope_b = find_in_list(client_scopes_b, name=client_scope_name)
            self.assertEqual(client_scope_a["id"], client_scope_b["id"])
            self.assertEqual(client_scope_a, client_scope_b)

            protocol_mappers_names = [pm["name"] for pm in client_scope_b["protocolMappers"]]
            self.assertEqual(["birthdate"], protocol_mappers_names)

        client_scope_name = "ci0-client-scope"
        client_scopes_api = self.client_scopes_api
        client_scope_filepath = os.path.join(self.testbed.DATADIR, f"ci0-realm/client-scopes/{client_scope_name}.json")

        client_scope_resource = ClientScopeResource({
            'path': client_scope_filepath,
            'keycloak_api': self.testbed.kc,
            'realm': self.testbed.REALM,
            'datadir': self.testbed.DATADIR,
        })

        self.maxDiff = None
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
        this_client_scope_mapper_api = client_scopes_api.get_child(client_scopes_api, client_scope_a["id"], "protocol-mappers/models")
        _check_state()

        # publish data - 2nd time, idempotence
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertFalse(creation_state)
        _check_state()

        # modify something - remove protocol mapper
        this_client_scope_mapper_api.remove(client_scope_a["protocolMappers"][0]["id"], None)
        client_scope_c = client_scopes_api.findFirstByKV("name", client_scope_name)
        self.assertEqual(client_scope_a["id"], client_scope_c["id"])
        self.assertNotIn("protocolMappers", client_scope_c)
        #
        # .publish must revert change
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertTrue(creation_state)
        #
        # only id should be changed, update it in expected client_scope_a
        protocol_mappers = this_client_scope_mapper_api.all()
        self.assertEqual(1, len(protocol_mappers))
        client_scope_a["protocolMappers"][0]["id"] = protocol_mappers[0]["id"]
        #
        _check_state()
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertFalse(creation_state)
        _check_state()

    def test_publish_with_mapping(self):
        # client-scope, with mappings/roles assigned, with mappers assigned
        def _check_state():
            client_scopes_b = client_scopes_api.all()
            client_scope_b = find_in_list(client_scopes_b, name=client_scope_name)
            self.assertEqual(client_scope_a["id"], client_scope_b["id"])
            self.assertEqual(client_scope_a, client_scope_b)

            scope_mappings = this_client_scope_scope_mappings_api.all()
            # self.assertEqual({}, scope_mappings)
            # API return something like:
            # {'realmMappings': [{'id': 'd0eb5122-8c45-42ec-906f-6f16a5e753ca', 'name': 'offline_access',
            #                     'description': '${role_offline-access}', 'composite': False, 'clientRole': False,
            #                     'containerId': 'a33bdcf4-33df-428e-adc4-a49eaf126ee7'}],
            #  'clientMappings': {
            #     'account': {'id': 'dbb3bd75-9cb1-44fe-a333-813d3757c155', 'client': 'account', 'mappings': [
            #         {'id': 'bd599fd1-73c8-48ce-bc7a-0562b1ebc8a1', 'name': 'manage-account',
            #          'description': '${role_manage-account}', 'composite': True, 'clientRole': True,
            #          'containerId': 'dbb3bd75-9cb1-44fe-a333-813d3757c155'}]}}}
            # ----------------------------------------------------------
            # mappings to realm roles
            client_scope_scopeMappings = {
                "roles": [rr["name"] for rr in scope_mappings.get('realmMappings', [])],
            }
            self.assertEqual(expected_client_scope_scopeMappings, client_scope_scopeMappings)
            # mappings to client roles
            client_scope_clientScopeMappings = {
                clientId: [
                    oo["name"] for oo in scope_mappings['clientMappings'][clientId]["mappings"]
                ]
                for clientId in scope_mappings.get('clientMappings', [])
            }
            self.assertEqual(expected_client_scope_clientScopeMappings, client_scope_clientScopeMappings)

        self.setUp_roles()
        client_scope_name = "ci0-client-scope"
        client_scopes_api = self.client_scopes_api
        client_scope_filepath = os.path.join(self.testbed.DATADIR, f"ci0-realm/client-scopes/{client_scope_name}.json")
        with open(client_scope_filepath) as ff:
            expected_client_scope = json.load(ff)
            expected_client_scope_clientScopeMappings = expected_client_scope.pop("clientScopeMappings")
            expected_client_scope_scopeMappings = expected_client_scope.pop("scopeMappings")

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
        creation_state = client_scope_resource.publish(include_scope_mappings=True)
        self.assertTrue(creation_state)
        client_scopes_a = client_scopes_api.all()
        client_scope_a = find_in_list(client_scopes_a, name=client_scope_name)
        # GET /{realm}/client-scopes/{id}/scope-mappings
        this_client_scope_scope_mappings_api = client_scopes_api.get_child(client_scopes_api, client_scope_a["id"], "scope-mappings")
        _check_state()

        # publish data - 2nd time, idempotence
        creation_state = client_scope_resource.publish(include_scope_mappings=True)
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        data = client_scopes_api.findFirstByKV("name", client_scope_name)
        data.update({
            "description": 'ci0-client-scope-desc-NEW',
            "attributes": {
                'consent.screen.text': 'consent-text-ci0-scope-NEW',
            },
        })
        client_scopes_api.update(client_scope_a["id"], data)
        client_scope_c = client_scopes_api.findFirstByKV("name", client_scope_name)
        self.assertEqual(client_scope_a["id"], client_scope_c["id"])
        self.assertEqual("ci0-client-scope-desc-NEW", client_scope_c["description"])
        self.assertEqual(
            {
                "consent.screen.text": "consent-text-ci0-scope-NEW",
                "display.on.consent.screen": "true",
                "include.in.token.scope": "true"
            },
            client_scope_c["attributes"],
        )
        #
        # .publish must revert change
        creation_state = client_scope_resource.publish(include_scope_mappings=True)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = client_scope_resource.publish(include_scope_mappings=True)
        self.assertFalse(creation_state)
        _check_state()

        # include_scope_mappings=False must not change existing mappings
        creation_state = client_scope_resource.publish(include_scope_mappings=False)
        self.assertFalse(creation_state)
        _check_state()


class TestClientScopeManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.realm_roles_api = testbed.kc.build("roles", testbed.REALM)
        # self.roles_by_id_api = testbed.kc.build("roles-by-id", testbed.REALM)
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)

    def test_publish_simple(self):
        # client-scope, no roles assigned, no mappers assigned
        def _check_state():
            client_scopes_b = client_scopes_api.all()
            client_scopes_b = sorted(client_scopes_b, key=lambda obj: obj["name"])
            client_scopes_b_names = [cs["name"] for cs in client_scopes_b]
            self.assertEqual(expected_client_scope_names, client_scopes_b_names)
            self.assertEqual(client_scopes_a[0]["id"], client_scopes_b[0]["id"])
            self.assertEqual(client_scopes_a, client_scopes_b)

        our_client_scope_names = [
            "ci0-client-scope",
            "ci0-client-scope-1-saml",
            "ci0-client-scope-2-saml",
        ]
        expected_client_scope_names = sorted(blacklisted_client_scopes + our_client_scope_names)
        client_scopes_api = self.client_scopes_api
        client_scope_manager = ClientScopeManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
        )

        # check initial state
        client_scopes = client_scopes_api.all()
        self.assertEqual(
            blacklisted_client_scopes,
            sorted([client_scope["name"] for client_scope in client_scopes]),
        )

        # publish data - 1st time
        creation_state = client_scope_manager.publish(include_scope_mappings=False)
        self.assertTrue(creation_state)
        client_scopes_a = client_scopes_api.all()
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = client_scope_manager.publish(include_scope_mappings=False)
        self.assertFalse(creation_state)
        _check_state()

        # modify something - add extra client scope
        self.assertEqual(9 + 3, len(client_scopes_api.all()))
        client_scopes_api.create({
            "name": "ci0-client-scope-EXTRA",
            "description": "ci0-client-scope-EXTRA-desc",
        }).isOk()
        self.assertEqual(9 + 3 + 1, len(client_scopes_api.all()))
        #
        # .publish must revert change
        creation_state = client_scope_manager.publish(include_scope_mappings=False)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = client_scope_manager.publish(include_scope_mappings=False)
        self.assertFalse(creation_state)
        _check_state()
