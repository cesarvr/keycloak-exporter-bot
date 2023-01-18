import logging
import json
import os
import unittest
from glob import glob
from copy import copy

from kcapi.rest.crud import KeycloakCRUD

from kcloader.resource import DefaultDefaultClientScopeManager, DefaultOptionalClientScopeManager, \
    ClientDefaultClientScopeManager, ClientOptionalClientScopeManager
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase

logger = logging.getLogger(__name__)


class TestDefaultDefaultClientScopeManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)
        self.default_default_client_scopes_api = testbed.kc.build("default-default-client-scopes", testbed.REALM)

        # create required client-scope
        self.client_scopes_api.create(dict(
            name="ci0-client-scope",
            description="ci0-client-scope---CI-INJECTED",
            protocol="openid-connect",
        )).isOk()
        extra_client_scope_name = "ci0-client-scope-EXTRA"
        self.client_scopes_api.create(dict(
            name=extra_client_scope_name,
            description=extra_client_scope_name + "---CI-INJECTED",
            protocol="openid-connect",
        )).isOk()
        self.extra_client_scope = self.client_scopes_api.findFirstByKV("name", extra_client_scope_name)

    def test_publish(self):
        def _check_state():
            default_default_client_scopes_b = default_default_client_scopes_api.all()

            self.assertEqual(default_default_client_scopes_a[0]["id"], default_default_client_scopes_b[0]["id"])
            self.assertEqual(default_default_client_scopes_a, default_default_client_scopes_b)

        default_default_client_scopes_api = self.default_default_client_scopes_api
        default_default_client_scopes_filepath = os.path.join(
            self.testbed.DATADIR,
            f"ci0-realm/client-scopes/default/default-default-client-scopes.json",
        )
        with open(default_default_client_scopes_filepath) as ff:
            expected_default_default_client_scopes_names = json.load(ff)
        ddcs_manager = DefaultDefaultClientScopeManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
        )
        # what is present in newly created realm
        _default_default_client_scopes_names___new_realm = sorted([
            "email",
            "profile",
            "role_list",
            "roles",
            "web-origins",
        ])

        # check initial state
        default_default_client_scopes_a = default_default_client_scopes_api.all()
        default_default_client_scopes_names = sorted([cs["name"] for cs in default_default_client_scopes_a])
        self.assertEqual(
            _default_default_client_scopes_names___new_realm,
            default_default_client_scopes_names,
        )

        # publish data - 1st time
        creation_state = ddcs_manager.publish(setup_new_links=True)
        self.assertTrue(creation_state)
        default_default_client_scopes_a = default_default_client_scopes_api.all()
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = ddcs_manager.publish(setup_new_links=True)
        self.assertFalse(creation_state)
        _check_state()

        # modify something - add one client-scope
        self.assertEqual(5 + 1, len(default_default_client_scopes_api.all()))
        default_default_client_scopes_api.update(
            self.extra_client_scope["id"],
            dict(
                realm=self.testbed.REALM,
                clientScopeId=self.extra_client_scope["id"],
            ),
        )
        self.assertEqual(5 + 2, len(default_default_client_scopes_api.all()))
        #
        # .publish must revert change
        creation_state = ddcs_manager.publish(setup_new_links=True)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = ddcs_manager.publish(setup_new_links=True)
        self.assertFalse(creation_state)
        _check_state()


    def test_publish__setup_new_links_false(self):
        def _check_state():
            default_default_client_scopes_b = default_default_client_scopes_api.all()

            self.assertEqual(default_default_client_scopes_a[0]["id"], default_default_client_scopes_b[0]["id"])
            self.assertEqual(default_default_client_scopes_a, default_default_client_scopes_b)

        default_default_client_scopes_api = self.default_default_client_scopes_api
        default_default_client_scopes_filepath = os.path.join(
            self.testbed.DATADIR,
            f"ci0-realm/client-scopes/default/default-default-client-scopes.json",
        )
        with open(default_default_client_scopes_filepath) as ff:
            expected_default_default_client_scopes_names = json.load(ff)
        ddcs_manager = DefaultDefaultClientScopeManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
        )
        # what is present in newly created realm
        _default_default_client_scopes_names___new_realm = sorted([
            "email",
            "profile",
            "role_list",
            "roles",
            "web-origins",
        ])

        # check initial state
        default_default_client_scopes_a = default_default_client_scopes_api.all()
        default_default_client_scopes_names = sorted([cs["name"] for cs in default_default_client_scopes_a])
        self.assertEqual(
            _default_default_client_scopes_names___new_realm,
            default_default_client_scopes_names,
        )

        # publish data - 1st time
        creation_state = ddcs_manager.publish(setup_new_links=False)
        self.assertFalse(creation_state)  # nothing was done, but change is needed
        default_default_client_scopes_a = default_default_client_scopes_api.all()
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = ddcs_manager.publish(setup_new_links=False)
        self.assertFalse(creation_state)
        _check_state()

        # modify something - add one client-scope
        self.assertEqual(5 + 0, len(default_default_client_scopes_api.all()))
        default_default_client_scopes_api.update(
            self.extra_client_scope["id"],
            dict(
                realm=self.testbed.REALM,
                clientScopeId=self.extra_client_scope["id"],
            ),
        )
        self.assertEqual(5 + 1, len(default_default_client_scopes_api.all()))
        #
        # .publish must revert change
        creation_state = ddcs_manager.publish(setup_new_links=False)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = ddcs_manager.publish(setup_new_links=False)
        self.assertFalse(creation_state)
        _check_state()


class TestDefaultOptionalClientScopeManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)
        self.default_optional_client_scopes_api = testbed.kc.build("default-optional-client-scopes", testbed.REALM)

        # create required client-scope
        self.client_scopes_api.create(dict(
            name="ci0-client-scope-1-saml",
            description="ci0-client-scope-1-saml---CI-INJECTED",
            protocol="saml",
        )).isOk()
        extra_client_scope_name = "ci0-client-scope-EXTRA"
        self.client_scopes_api.create(dict(
            name=extra_client_scope_name,
            description=extra_client_scope_name + "---CI-INJECTED",
            protocol="openid-connect",
        )).isOk()
        self.extra_client_scope = self.client_scopes_api.findFirstByKV("name", extra_client_scope_name)

    def test_publish(self):
        def _check_state():
            default_optional_client_scopes_b = default_optional_client_scopes_api.all()

            self.assertEqual(default_optional_client_scopes_a[0]["id"], default_optional_client_scopes_b[0]["id"])
            self.assertEqual(default_optional_client_scopes_a, default_optional_client_scopes_b)

        default_optional_client_scopes_api = self.default_optional_client_scopes_api
        default_optional_client_scopes_filepath = os.path.join(
            self.testbed.DATADIR,
            f"ci0-realm/client-scopes/default/default-optional-client-scopes.json",
        )
        with open(default_optional_client_scopes_filepath) as ff:
            expected_default_optional_client_scopes_names = json.load(ff)
        docs_manager = DefaultOptionalClientScopeManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
        )
        # what is present in newly created realm
        _default_optional_client_scopes_names___new_realm = sorted([
            "address",
            "microprofile-jwt",
            "offline_access",
            "phone",
        ])

        # check initial state
        default_optional_client_scopes_a = default_optional_client_scopes_api.all()
        default_optional_client_scopes_names = sorted([cs["name"] for cs in default_optional_client_scopes_a])
        self.assertEqual(
            _default_optional_client_scopes_names___new_realm,
            default_optional_client_scopes_names,
        )

        # publish data - 1st time
        creation_state = docs_manager.publish(setup_new_links=True)
        self.assertTrue(creation_state)
        default_optional_client_scopes_a = default_optional_client_scopes_api.all()
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = docs_manager.publish(setup_new_links=True)
        self.assertFalse(creation_state)
        _check_state()

        # modify something - add one extra client-scope
        self.assertEqual(4 + 1, len(default_optional_client_scopes_api.all()))
        default_optional_client_scopes_api.update(
            self.extra_client_scope["id"],
            dict(
                realm=self.testbed.REALM,
                clientScopeId=self.extra_client_scope["id"],
            ),
        )
        self.assertEqual(4 + 2, len(default_optional_client_scopes_api.all()))
        #
        # .publish must revert change
        creation_state = docs_manager.publish(setup_new_links=True)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = docs_manager.publish(setup_new_links=True)
        self.assertFalse(creation_state)
        _check_state()


class TestClientXClientScopeManager(TestCaseBase):
    # PUT/DELETE {realm}/clients/{client_id}/default-client-scopes
    # PUT/DELETE {realm}/clients/{client_id}/optional-client-scopes
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)
        self.clients_api = testbed.kc.build("clients", testbed.REALM)

        # create required client
        clients_all = self.clients_api.all()
        self.assertEqual(len(clients_all), 6 + 0)
        self.clients_api.create(dict(
            clientId="ci0-client-0",
            description="ci0-client-0---CI-INJECTED",
            protocol="openid-connect",
        )).isOk()
        clients_all = self.clients_api.all()
        self.assertEqual(len(clients_all), 6 + 1)
        #
        self.client0 = find_in_list(clients_all, clientId="ci0-client-0")
        self.this_client_default_client_scopes_api = KeycloakCRUD.get_child(
            self.clients_api,
            self.client0["id"],
            "default-client-scopes",
        )
        self.this_client_optional_client_scopes_api = KeycloakCRUD.get_child(
            self.clients_api,
            self.client0["id"],
            "optional-client-scopes",
        )

        # create required client-scope
        self.client_scopes_api.create(dict(
            name="ci0-client-scope",
            description="ci0-client-scope---CI-INJECTED",
            protocol="openid-connect",
        )).isOk()
        extra_client_scope_name = "ci0-client-scope-EXTRA"
        self.client_scopes_api.create(dict(
            name=extra_client_scope_name,
            description=extra_client_scope_name + "---CI-INJECTED",
            protocol="openid-connect",
        )).isOk()
        self.extra_client_scope = self.client_scopes_api.findFirstByKV("name", extra_client_scope_name)

    def test_ClientDefaultClientScopeManager_publish(self):
        def _check_state():
            assigned_client_scopes_b = this_client_default_client_scopes_api.all()
            self.assertEqual(assigned_client_scopes_a[0]["id"], assigned_client_scopes_b[0]["id"])
            self.assertEqual(assigned_client_scopes_a, assigned_client_scopes_b)

        this_client_default_client_scopes_api = self.this_client_default_client_scopes_api

        client_filepath = os.path.join(
            self.testbed.DATADIR,
            "ci0-realm/clients/client-0/ci0-client-0.json",
        )
        # with open(default_optional_client_scopes_filepath) as ff:
        #     expected_default_optional_client_scopes_names = json.load(ff)

        manager = ClientDefaultClientScopeManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
            client_id=self.client0["id"],
            client_filepath=client_filepath,
        )
        # what is present in newly created realm
        _client_default_client_scopes_names___new_realm = sorted([
            "email",
            "profile",
            "roles",
            "web-origins",
        ])

        # check initial state
        assigned_client_scopes_a = this_client_default_client_scopes_api.all()
        assigned_client_scopes_names = sorted([cs["name"] for cs in assigned_client_scopes_a])
        self.assertEqual(
            _client_default_client_scopes_names___new_realm,
            assigned_client_scopes_names,
        )

        # publish data - 1st time
        creation_state = manager.publish(setup_new_links=True)
        self.assertTrue(creation_state)
        assigned_client_scopes_a = this_client_default_client_scopes_api.all()
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = manager.publish(setup_new_links=True)
        self.assertFalse(creation_state)
        _check_state()

        # modify something - assign one extra client-scope
        self.assertEqual(4 + 1, len(this_client_default_client_scopes_api.all()))
        this_client_default_client_scopes_api.update(
            self.extra_client_scope["id"],
            dict(
                realm=self.testbed.REALM,
                clientX=self.client0["id"],
                clientScopeId=self.extra_client_scope["id"],
            ),
        ).isOk()
        self.assertEqual(4 + 2, len(this_client_default_client_scopes_api.all()))
        #
        # .publish must revert change
        creation_state = manager.publish(setup_new_links=True)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = manager.publish(setup_new_links=True)
        self.assertFalse(creation_state)
        _check_state()

    def test_ClientOptionalClientScopeManager_publish(self):
        def _check_state():
            assigned_client_scopes_b = this_client_optional_client_scopes_api.all()
            self.assertEqual(assigned_client_scopes_a[0]["id"], assigned_client_scopes_b[0]["id"])
            self.assertEqual(assigned_client_scopes_a, assigned_client_scopes_b)

        this_client_optional_client_scopes_api = self.this_client_optional_client_scopes_api

        client_filepath = os.path.join(
            self.testbed.DATADIR,
            "ci0-realm/clients/client-0/ci0-client-0.json",
        )
        # with open(default_optional_client_scopes_filepath) as ff:
        #     expected_default_optional_client_scopes_names = json.load(ff)

        manager = ClientOptionalClientScopeManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
            client_id=self.client0["id"],
            client_filepath=client_filepath,
        )
        # what is present in newly created realm
        _client_optional_client_scopes_names___new_realm = sorted([
            "address",
            "microprofile-jwt",
            "offline_access",
            "phone",
        ])

        # check initial state
        assigned_client_scopes_a = this_client_optional_client_scopes_api.all()
        assigned_client_scopes_names = sorted([cs["name"] for cs in assigned_client_scopes_a])
        self.assertEqual(
            _client_optional_client_scopes_names___new_realm,
            assigned_client_scopes_names,
        )

        # current state is already same as desired.
        # remove one client-scope to create some work for manager.
        self.assertEqual(4 - 0, len(this_client_optional_client_scopes_api.all()))
        client_scope_account = self.client_scopes_api.findFirstByKV("name", "address")
        this_client_optional_client_scopes_api.remove(client_scope_account["id"], None).isOk()
        self.assertEqual(4 - 1, len(this_client_optional_client_scopes_api.all()))

        # publish data - 1st time
        creation_state = manager.publish(setup_new_links=True)
        self.assertTrue(creation_state)
        # assigned_client_scopes_a = this_client_optional_client_scopes_api.all()
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = manager.publish(setup_new_links=True)
        self.assertFalse(creation_state)
        _check_state()

        # modify something - assign one extra client-scope
        self.assertEqual(4 + 0, len(this_client_optional_client_scopes_api.all()))
        this_client_optional_client_scopes_api.update(
            self.extra_client_scope["id"],
            dict(
                realm=self.testbed.REALM,
                clientX=self.client0["id"],
                clientScopeId=self.extra_client_scope["id"],
            ),
        ).isOk()
        self.assertEqual(4 + 1, len(this_client_optional_client_scopes_api.all()))
        #
        # .publish must revert change
        creation_state = manager.publish(setup_new_links=True)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = manager.publish(setup_new_links=True)
        self.assertFalse(creation_state)
        _check_state()
