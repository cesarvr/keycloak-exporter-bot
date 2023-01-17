import json
import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import SingleClientResource, \
    ClientManager, ClientRoleManager, ClientRoleResource
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase


class TestClientResource(TestCaseBase):
    expected_client0 = {
        "access": {
            "configure": True,
            "manage": True,
            "view": True
        },
        "alwaysDisplayInConsole": False,
        "attributes": {
            "access.token.lifespan": "600",
            "access.token.signed.response.alg": "ES256",
            "backchannel.logout.revoke.offline.tokens": "false",
            "backchannel.logout.session.required": "false",
            "client_credentials.use_refresh_token": "false",
            "display.on.consent.screen": "false",
            "exclude.session.state.from.auth.response": "true",
            "id.token.as.detached.signature": "false",
            "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false",
            "require.pushed.authorization.requests": "false",
            "saml.artifact.binding": "false",
            "saml.assertion.signature": "false",
            "saml.authnstatement": "false",
            "saml.client.signature": "false",
            "saml.encrypt": "false",
            "saml.force.post.binding": "false",
            "saml.multivalued.roles": "false",
            "saml.onetimeuse.condition": "false",
            "saml.server.signature": "false",
            "saml.server.signature.keyinfo.ext": "false",
            "saml_force_name_id_format": "false",
            "tls.client.certificate.bound.access.tokens": "false",
            "use.refresh.tokens": "true"
        },
        "authenticationFlowBindingOverrides": {
            # "browser": "browser"  #
        },
        "bearerOnly": False,
        "clientAuthenticatorType": "client-secret",
        "clientId": "ci0-client-0",
        "consentRequired": False,
        "defaultClientScopes": [
            # "ci0-client-scope",
            "email",
            "profile",
            "role_list",
            "roles",
            "web-origins"
        ],
        "defaultRoles": [
            "ci0-client0-role0"
        ],
        "description": "ci0-client-0-desc",
        "directAccessGrantsEnabled": False,
        "enabled": True,
        "frontchannelLogout": False,
        "fullScopeAllowed": False,
        "implicitFlowEnabled": False,
        "name": "ci0-client-0-name",
    }

    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        client0_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/clients/client-0/ci0-client-0.json")
        self.client0_resource = SingleClientResource({
            'path': client0_filepath,
            'keycloak_api': testbed.kc,
            'realm': testbed.REALM,
            'datadir': testbed.DATADIR,
        })

        self.clients_api = testbed.kc.build("clients", testbed.REALM)

        # check clean start
        assert len(self.clients_api.all()) == 6  # 6 default clients

    def _sort_object(self, obj):
        obj["defaultClientScopes"] = sorted(obj["defaultClientScopes"])
        return obj

    def test_publish_self(self):
        self.maxDiff = None
        default_client_count = 6  # newly created realm has 6 clients
        client0_resource = self.client0_resource
        clients_api = self.clients_api
        client0_clientId = self.client0_clientId

        # initial state
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count)

        # create client
        creation_state = client0_resource.publish_self()
        self.assertTrue(creation_state)
        # check objects are created
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count + 1)
        client_a = clients_api.findFirstByKV("clientId", client0_clientId)
        self._sort_object(client_a)
        self.assertEqual(client_a, client_a | self.expected_client0)

        # publish same data again
        creation_state = client0_resource.publish_self()
        self.assertTrue(creation_state)  # TODO - should be False if defaultClientScopes would contain ci0-client-scope
        # check content is not modified
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count + 1)
        client_b = clients_api.findFirstByKV("clientId", client0_clientId)
        self._sort_object(client_b)
        # check objects are not recreated without reason.
        self.assertEqual(client_a["id"], client_b["id"])
        self.assertEqual(client_a, client_b)

        # modify something
        clients_api.update_rmw(client_a["id"], {'description': 'ci0-client-0-desc-NEW'})
        self.assertEqual('ci0-client-0-desc-NEW', clients_api.get_one(client_a["id"])['description'])
        # publish same data again
        creation_state = client0_resource.publish_self()
        self.assertTrue(creation_state)
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count + 1)
        client_c = clients_api.get_one(client_a["id"])
        if 1:
            ref_client0_resource = copy(self.client0_resource)
            ref_client0_resource.body["defaultClientScopes"].remove("ci0-client-scope")
            self.assertTrue(ref_client0_resource.is_equal(client_c))
        else:
            # is not sorted...
            self.assertEqual(client_c, client_c | expected_client0)
        self.assertEqual('ci0-client-0-desc', clients_api.get_one(client_a["id"])['description'])

    def test_publish_without_composites(self):
        # TODO test also .publish with include_composite=True
        self.maxDiff = None
        expected_role_names = [
            'ci0-client0-role0',
            'ci0-client0-role1',
            'ci0-client0-role1a',
            'ci0-client0-role1b',
        ]
        expected_client0_a = copy(self.expected_client0)
        # none of those roles is present, API will drop whole defaultRoles attribute
        expected_client0_a.pop("defaultRoles")
        expected_client0_b = copy(self.expected_client0)
        # only one client role is present
        expected_client0_b["defaultRoles"] = ["ci0-client0-role0"]

        default_client_count = 6  # newly created realm has 6 clients
        client0_resource = self.client0_resource
        clients_api = self.clients_api
        client0_clientId = self.client0_clientId

        # initial state
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count)

        # create client
        creation_state = client0_resource.publish(include_composite=False)
        self.assertTrue(creation_state)
        # check objects are created
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count + 1)
        client_a = clients_api.findFirstByKV("clientId", client0_clientId)
        self._sort_object(client_a)
        self.assertEqual(client_a, client_a | expected_client0_a)
        # check roles
        roles_api = client0_resource.resource.resource_api.roles({'key': 'id', 'value': client_a["id"]})
        roles_a = roles_api.all()
        roles_a_names = sorted([role["name"] for role in roles_a])
        self.assertEqual(roles_a_names, expected_role_names)

        # TODO temporary test -
        # .publish() will not set defaultRoles (guess - roles are not updated, but removed/created).
        # So we test .publish_self(), this one should configure defaultRoles.
        # TODO - try not to use UpdatePolicy.DELETE - just avoid it.
        if 1:
            creation_state = client0_resource.publish_self()
            self.assertTrue(creation_state)  # is True, because of defaultClientScopes and defaultRoles
            # check content is not modified
            clients_all = clients_api.all()
            self.assertEqual(len(clients_all), default_client_count + 1)
            client_b = clients_api.findFirstByKV("clientId", client0_clientId)
            self._sort_object(client_b)
            # check objects are not recreated without reason.
            self.assertEqual(client_a["id"], client_b["id"])
            self.assertEqual(client_b, client_b | expected_client0_b)
            # check roles
            roles_b = roles_api.all()
            roles_b_names = sorted([role["name"] for role in roles_a])
            self.assertEqual(roles_b_names, expected_role_names)

            # TEMP - .publish_roles() is broken, and destroys defaultRoles
            expected_client0_b.pop("defaultRoles")

        # publish same data again - idempotence
        creation_state = client0_resource.publish(include_composite=False)
        self.assertTrue(creation_state)  # TODO - should be False if defaultClientScopes would contain ci0-client-scope
        # check content is not modified
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count + 1)
        client_b = clients_api.findFirstByKV("clientId", client0_clientId)
        self._sort_object(client_b)
        # check objects are not recreated without reason.
        self.assertEqual(client_a["id"], client_b["id"])
        self.assertEqual(client_b, client_b | expected_client0_b)
        # check roles
        roles_b = roles_api.all()
        roles_b_names = sorted([role["name"] for role in roles_a])
        self.assertEqual(roles_b_names, expected_role_names)

        # modify something


class TestClientResourceManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed
        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        # check clean start
        assert len(self.clients_api.all()) == 6  # 6 default clients

    def _sort_client_object(self, obj):
        obj["defaultClientScopes"] = sorted(obj["defaultClientScopes"])
        obj["defaultRoles"] = sorted(obj["defaultRoles"])
        return obj

    def test_publish(self):
        default_client_clientIds = [
            'account',
            'account-console',
            'admin-cli',
            'broker',
            'realm-management',
            'security-admin-console',
        ]
        our_client_clientIds = [
            'ci0-client-0',
            'ci0-client-1',
            'ci0-client-2-saml',
            'ci0-client-3-saml',
        ]
        testbed = self.testbed
        clients_api = self.clients_api
        manager = ClientManager(self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR)

        # check initial state
        create_ids, delete_objs = manager._difference_ids()
        delete_ids = sorted([obj["clientId"] for obj in delete_objs])
        self.assertEqual(our_client_clientIds, sorted(create_ids))
        self.assertEqual([], delete_ids)

        # publish data - 1st time
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)
        clients_all = clients_api.all()
        self.assertEqual(
            sorted(default_client_clientIds + our_client_clientIds),
            sorted([obj["clientId"] for obj in clients_all])
        )

        create_ids, delete_objs = manager._difference_ids()
        self.assertEqual([], create_ids)
        self.assertEqual([], delete_objs)

        # publish same data again - idempotence
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)  # TODO should be false
        clients_all = clients_api.all()
        self.assertEqual(
            sorted(default_client_clientIds + our_client_clientIds),
            sorted([obj["clientId"] for obj in clients_all])
        )

        # ------------------------------------------------------------------------------
        # create an additional client
        self.clients_api.create({
            "clientId": "ci0-client-x-to-be-deleted",
            "description": "ci0-client-x-to-be-DELETED",
            "protocol": "openid-connect",
            "enabled": True,
        }).isOk()
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), 6 + 4 + 1)
        self.assertEqual(
            sorted(default_client_clientIds + our_client_clientIds + ["ci0-client-x-to-be-deleted"]),
            sorted([obj["clientId"] for obj in clients_all])
        )

        create_ids, delete_objs = manager._difference_ids()
        delete_ids = sorted([obj["clientId"] for obj in delete_objs])
        self.assertEqual([], create_ids)
        self.assertEqual(['ci0-client-x-to-be-deleted'], delete_ids)

        # check extra client is deleted
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)
        clients_all = clients_api.all()
        self.assertEqual(
            sorted(default_client_clientIds + our_client_clientIds),
            sorted([obj["clientId"] for obj in clients_all])
        )

    def test_publish__client_default_roles__custom_client(self):
        client_clientId = "ci0-client-0"
        expected_client_role_names = [
            "ci0-client0-role0",
            "ci0-client0-role1",
            "ci0-client0-role1a",
            "ci0-client0-role1b",
        ]
        expected_client_default_roles = [
            "ci0-client0-role0",
        ]
        wrong_client_default_roles = [
            "ci0-client0-role1a",
            "ci0-client0-role1b",
        ]
        self.do_test_publish__client_default_roles(
            client_clientId,
            expected_client_role_names,
            expected_client_default_roles,
            wrong_client_default_roles,
        )

    def test_publish__client_default_roles__builtin_client(self):
        client_clientId = "account"
        expected_client_role_names = [
            "manage-account",
            "manage-account-links",
            "manage-consent",
            "view-applications",
            "view-consent",
            "view-profile",
        ]
        expected_client_default_roles = [
            "manage-account",
            "view-profile",
        ]
        wrong_client_default_roles = [
            "view-applications",
        ]
        self.do_test_publish__client_default_roles(
            client_clientId,
            expected_client_role_names,
            expected_client_default_roles,
            wrong_client_default_roles,
        )

    def do_test_publish__client_default_roles(
            self,
            client_clientId,
            expected_client_role_names,
            expected_client_default_roles,
            wrong_client_default_roles,
        ):
        def _check_state():
            # check objects are created
            clients_all = clients_api.all()
            self.assertEqual(len(clients_all), expected_client_count)
            client_b = clients_api.findFirstByKV("clientId", client_clientId)
            self._sort_client_object(client_b)
            self.assertEqual(expected_client_default_roles, client_b["defaultRoles"])

            # check objects are not recreated without reason.
            self.assertEqual(client_a["id"], client_b["id"])
            roles_b = this_client_roles_api.all()
            roles_b_names = sorted([role["name"] for role in roles_b])
            self.assertEqual(expected_client_role_names, roles_b_names)
            self.assertEqual(roles_a, roles_b)

        # -------------------------------------------------------------

        self.maxDiff = None

        default_client_count = 6  # newly created realm has 6 clients
        expected_client_count = 6 + 4
        # client_resource = self.client0_resource
        clients_api = self.clients_api

        manager = ClientManager(self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR)

        # initial state
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count)

        # Setup required objects - client-scopes

        # create client
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)
        # check objects are created
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), expected_client_count)
        client_a = clients_api.findFirstByKV("clientId", client_clientId)
        this_client_roles_api = clients_api.roles({'key': 'id', 'value': client_a["id"]})
        roles_a = this_client_roles_api.all()
        roles_a_names = sorted([role["name"] for role in roles_a])
        self.assertEqual(roles_a_names, expected_client_role_names)
        self._sort_client_object(client_a)
        self.assertEqual(expected_client_default_roles, client_a["defaultRoles"])
        _check_state()
        #
        # publish same data again - idempotence
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)
        _check_state()

        # modify something - set different default roles
        data1 = clients_api.findFirstByKV("clientId", client_clientId)
        data1.update({
            "defaultRoles": wrong_client_default_roles,
        })
        data1 = self._sort_client_object(data1)
        clients_api.update(client_a["id"], data1).isOk()
        data2 = clients_api.findFirstByKV("clientId", client_clientId)
        data2 = self._sort_client_object(data2)
        self.assertEqual(data1, data2)

        # publish must revert changes
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)
        _check_state()
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)
        _check_state()


class TestClientRoleResourceManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        client0_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/clients/client-0/ci0-client-0.json")
        self.client0_resource = SingleClientResource({
            'path': client0_filepath,
            'keycloak_api': testbed.kc,
            'realm': testbed.REALM,
            'datadir': testbed.DATADIR,
        })

        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        # check clean start
        assert len(self.clients_api.all()) == 6  # 6 default clients

        self.client0_resource.publish_self()

    def test_publish(self):
        our_roles_names = sorted([
            "ci0-client0-role0",
            "ci0-client0-role1",
            "ci0-client0-role1a",
            "ci0-client0-role1b",
        ])
        # testbed = self.testbed
        # client0 = self.clients_api.findFirstByKV("clientId", self.client0_clientId)
        client_query = {'key': 'clientId', 'value': self.client0_clientId}
        client0_roles_api = self.clients_api.roles(client_query)
        client0 = self.clients_api.findFirstByKV("clientId", self.client0_clientId)

        manager = ClientRoleManager(
            self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR,
            clientId=self.client0_clientId,
            client_id=client0["id"],
            client_filepath=os.path.join(self.testbed.DATADIR, "ci0-realm/clients/client-0/ci0-client-0.json"),
        )

        # check initial state
        # "empty" ci0-client0-role0 is created when we import ci0-client-0.json
        roles = client0_roles_api.all()
        self.assertEqual(["ci0-client0-role0"], [role["name"] for role in roles])
        create_ids, delete_objs = manager._difference_ids()
        delete_ids = sorted([obj["name"] for obj in delete_objs])
        expected_create_role_names = copy(our_roles_names)
        expected_create_role_names.remove("ci0-client0-role0")
        self.assertEqual(expected_create_role_names, sorted(create_ids))
        self.assertEqual([], delete_objs)

        # publish data - 1st time
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)
        roles = client0_roles_api.all()
        self.assertEqual(
            our_roles_names,
            sorted([role["name"] for role in roles])
        )

        create_ids, delete_objs = manager._difference_ids()
        self.assertEqual([], create_ids)
        self.assertEqual([], delete_objs)

        # publish same data again - idempotence
        creation_state = manager.publish(include_composite=False)
        # TODO should be false; but one composite (realm sub-role) is missing
        self.assertTrue(creation_state)
        roles = client0_roles_api.all()
        self.assertEqual(
            our_roles_names,
            sorted([role["name"] for role in roles])
        )

        # ------------------------------------------------------------------------------
        # create an additional role
        client0_roles_api.create({
            "name": "ci0-client0-role-x-to-be-deleted",
            "description": "ci0-client0-role-x-to-be-DELETED",
        }).isOk()
        roles = client0_roles_api.all()
        self.assertEqual(4 + 1, len(roles))
        self.assertEqual(
            sorted(our_roles_names + ["ci0-client0-role-x-to-be-deleted"]),
            sorted([role["name"] for role in roles])
        )

        create_ids, delete_objs = manager._difference_ids()
        delete_ids = sorted([obj["name"] for obj in delete_objs])
        self.assertEqual([], create_ids)
        self.assertEqual(['ci0-client0-role-x-to-be-deleted'], delete_ids)

        # check extra role is deleted
        creation_state = manager.publish(include_composite=False)
        self.assertTrue(creation_state)
        roles = client0_roles_api.all()
        self.assertEqual(4, len(roles))
        self.assertEqual(
            our_roles_names,
            sorted([role["name"] for role in roles])
        )


class TestClientRoleResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client0_clientId = "ci0-client-0"
        client0_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/clients/client-0/ci0-client-0.json")
        self.client0_resource = SingleClientResource({
            'path': client0_filepath,
            'keycloak_api': testbed.kc,
            'realm': testbed.REALM,
            'datadir': testbed.DATADIR,
        })

        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.realm_roles_api = testbed.kc.build("roles", testbed.REALM)
        self.roles_by_id_api = testbed.kc.build("roles-by-id", testbed.REALM)
        # check clean start
        assert len(self.clients_api.all()) == 6  # 6 default clients
        assert len(self.realm_roles_api.all()) == 2  # 2 default realm roles (for master realm - 4)

        # this creates "empty" "ci0-client0-role0"
        self.client0_resource.publish_self()
        self.client0 = self.clients_api.findFirstByKV("clientId", self.client0_clientId)

    def test_publish_without_composites(self):
        # testbed = self.testbed
        # client0 = self.clients_api.findFirstByKV("clientId", self.client0_clientId)
        client_query = {'key': 'clientId', 'value': self.client0_clientId}
        client0_roles_api = self.clients_api.roles(client_query)
        # TODO test with simple ci0-client-0.json and with some composite role
        role_filepath = os.path.join(self.testbed.DATADIR, "ci0-realm/clients/client-0/roles/ci0-client0-role1b.json")
        with open(role_filepath) as ff:
            expected_role = json.load(ff)
        # make sure we do test "attributes". They are just easy to miss.
        self.assertEqual({'ci0-client0-role1b-key0': ['ci0-client0-role1b-value0']}, expected_role["attributes"])

        role_resource = ClientRoleResource({
                'path': role_filepath,
                'keycloak_api': self.testbed.kc,
                'realm': self.testbed.REALM,
                'datadir': self.testbed.DATADIR,
            },
            clientId=self.client0_clientId,
            client_id=self.client0["id"],
            client_roles_api=client0_roles_api,
        )

        # check initial state
        # "empty" ci0-client0-role0 is created when we import ci0-client-0.json
        roles = client0_roles_api.all()
        self.assertEqual(["ci0-client0-role0"], [role["name"] for role in roles])

        # publish data - 1st time
        creation_state = role_resource.publish(include_composite=False)  # TODO extend CI test also with include_composite=True case
        self.assertTrue(creation_state)
        roles_a = client0_roles_api.all()
        self.assertEqual(
            ['ci0-client0-role0', 'ci0-client0-role1b'],
            sorted([role["name"] for role in roles_a])
        )
        role_a = find_in_list(roles_a, name='ci0-client0-role1b')
        # role attributes
        role_min = copy(role_a)
        role_min.pop("id")
        role_min.pop("containerId")
        self.assertEqual(expected_role, role_min)

        # publish data - 2nd time, idempotence
        creation_state = role_resource.publish(include_composite=False)  # TODO extend CI test also with include_composite=True case
        self.assertFalse(creation_state)
        roles_b = client0_roles_api.all()
        self.assertEqual(
            ['ci0-client0-role0', 'ci0-client0-role1b'],
            sorted([role["name"] for role in roles_b])
        )
        role_b = find_in_list(roles_b, name='ci0-client0-role1b')
        # role should not be re-created
        self.assertEqual(role_a["id"], role_b["id"])
        # role attributes
        role_min = copy(role_b)
        role_min.pop("id")
        role_min.pop("containerId")
        self.assertEqual(expected_role, role_min)

        # modify something
        #
        # hahaha, list endpoint cannot be used to get exactly one objects
        # client0_roles_api.update_rmw(role_a["id"], {"description": 'ci0-client0-role1b-desc-NEW'})
        #
        data = client0_roles_api.findFirstByKV("name", 'ci0-client0-role1b')
        data.update({"description": 'ci0-client0-role1b-desc-NEW'})
        client0_roles_api.update(role_a["id"], data)
        role_c = client0_roles_api.findFirstByKV("name", 'ci0-client0-role1b')
        self.assertEqual(role_a["id"], role_c["id"])
        self.assertEqual("ci0-client0-role1b-desc-NEW", role_c["description"])
        # .publish must revert change
        creation_state = role_resource.publish(include_composite=False)  # TODO extend CI test also with include_composite=True case
        roles_d = client0_roles_api.all()
        self.assertEqual(
            ['ci0-client0-role0', 'ci0-client0-role1b'],
            sorted([role["name"] for role in roles_d])
        )
        role_d = find_in_list(roles_d, name='ci0-client0-role1b')
        # role should not be re-created
        self.assertEqual(role_a["id"], role_d["id"])
        # role attributes
        role_min = copy(role_d)
        role_min.pop("id")
        role_min.pop("containerId")
        self.assertEqual(expected_role, role_min)

    def test_publish_with_composites(self):
        def _check_state():
            roles_b = client0_roles_api.all()
            self.assertEqual(
                ['ci0-client0-role0', 'ci0-client0-role1', 'ci0-client0-role1a', 'ci0-client0-role1b'],
                sorted([role["name"] for role in roles_b])
            )
            role_b = find_in_list(roles_b, name='ci0-client0-role1')
            # role should not be re-created
            self.assertEqual(role_a["id"], role_b["id"])
            # role attributes
            role_min = copy(role_b)
            role_min.pop("id")
            role_min.pop("containerId")
            self.assertEqual(expected_role, role_min)
            # check subroles
            composites = this_role_composites_api.all()
            composite_role_names = sorted([obj["name"] for obj in composites])
            composites_role_container_ids = sorted([obj["containerId"] for obj in composites])
            self.assertEqual(
                expected_composite_role_names,
                composite_role_names,
            )
            self.assertEqual(
                expected_composites_role_container_ids,
                composites_role_container_ids,
            )

        self.maxDiff = None
        # testbed = self.testbed
        # client0 = self.clients_api.findFirstByKV("clientId", self.client0_clientId)
        client_query = {'key': 'clientId', 'value': self.client0_clientId}
        client0_roles_api = self.clients_api.roles(client_query)
        roles_by_id_api = self.roles_by_id_api
        # TODO test with simple ci0-client-0.json and with some composite role
        role_filepath = os.path.join(self.testbed.DATADIR, "ci0-realm/clients/client-0/roles/ci0-client0-role1.json")
        with open(role_filepath) as ff:
            expected_role = json.load(ff)
            # API does not include composites into API response.
            # kcfetcher is "artificially" adding "composites" into role .json file.
            expected_role_composites = expected_role.pop("composites")
        # make sure we do test "attributes". They are just easy to miss.
        self.assertEqual({'ci0-client0-role1-key0': ['ci0-client0-role1-value0']}, expected_role["attributes"])
        # make sure composites are complex enough
        self.assertEqual([
                {
                    "clientRole": True,
                    "containerName": "ci0-client-0",
                    "name": "ci0-client0-role1a"
                },
                {
                    "clientRole": True,
                    "containerName": "ci0-client-0",
                    "name": "ci0-client0-role1b"
                },
                {
                    "clientRole": False,
                    "containerName": "ci0-realm",
                    "name": "ci0-role-1a"
                }
            ],
            expected_role_composites
        )

        role_resource = ClientRoleResource({
            'path': role_filepath,
            'keycloak_api': self.testbed.kc,
            'realm': self.testbed.REALM,
            'datadir': self.testbed.DATADIR,
            },
            clientId=self.client0_clientId,
            client_id=self.client0["id"],
            client_roles_api=client0_roles_api,
        )

        # check initial state
        # "empty" ci0-client0-role0 is created when we import ci0-client-0.json
        roles = client0_roles_api.all()
        self.assertEqual(["ci0-client0-role0"], [role["name"] for role in roles])

        # Fixup - create required sub-roles first
        self.realm_roles_api.create(dict(name="ci0-role-1a", description="ci0-role-1a---injected-by-CI-test"))
        assert len(self.realm_roles_api.all()) == 2 + 1  # 2 default realm roles
        client0_roles_api.create(dict(name="ci0-client0-role1a", description="ci0-client0-role1a---injected-by-CI-test"))
        client0_roles_api.create(dict(name="ci0-client0-role1b", description="ci0-client0-role1b---injected-by-CI-test"))
        assert len(client0_roles_api.all()) == 1 + 2  # the "empty" ci0-client0-role0 is created when client is createddf

        expected_composite_role_names = ["ci0-client0-role1a", "ci0-client0-role1b", "ci0-role-1a"]
        realm = self.testbed.master_realm.get_one(self.testbed.realm)
        expected_composites_role_container_ids = sorted([self.client0["id"], self.client0["id"], realm["id"]])

        # END prepare
        # -----------------------------------------

        # publish data - 1st time
        creation_state = role_resource.publish()
        self.assertTrue(creation_state)
        role_a = client0_roles_api.findFirstByKV("name", "ci0-client0-role1")
        role_id = role_a["id"]
        this_role_composites_api = roles_by_id_api.get_child(roles_by_id_api, role_id, "composites")
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = role_resource.publish()
        self.assertFalse(creation_state)
        _check_state()

        # ------------------------------------------------------------------------
        # modify something - change role config
        data = client0_roles_api.findFirstByKV("name", 'ci0-client0-role1')
        data.update({"description": 'ci0-client0-role1b-desc-NEW'})
        client0_roles_api.update(role_a["id"], data)
        role_c = client0_roles_api.findFirstByKV("name", 'ci0-client0-role1')
        self.assertEqual(role_a["id"], role_c["id"])
        self.assertEqual("ci0-client0-role1b-desc-NEW", role_c["description"])
        # .publish must revert change
        creation_state = role_resource.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = role_resource.publish()
        self.assertFalse(creation_state)
        _check_state()

        # ------------------------------------------------------------------------
        # modify something - add one sub-role
        self.realm_roles_api.create(dict(name="ci0-role-temp", description="ci0-role-TEMP---injected-by-CI-test"))
        realm_role_temp = self.realm_roles_api.findFirstByKV("name", "ci0-role-temp")
        this_role_composites_api.create([realm_role_temp])
        composites_e = this_role_composites_api.all()
        self.assertEqual(4, len(composites_e))
        self.assertEqual(
            ['ci0-client0-role1a', 'ci0-client0-role1b', 'ci0-role-1a', 'ci0-role-temp'],
            sorted([role["name"] for role in composites_e])
        )
        # .publish must revert change
        creation_state = role_resource.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = role_resource.publish()
        self.assertFalse(creation_state)
        _check_state()

        # ------------------------------------------------------------------------
        # modify something - remove one sub-role
        composites_f = this_role_composites_api.all()
        subrole_1b = find_in_list(composites_f, name="ci0-client0-role1b")
        this_role_composites_api.remove(None, [subrole_1b]).isOk()
        composites_f = this_role_composites_api.all()
        self.assertEqual(2, len(composites_f))
        self.assertEqual(
            ['ci0-client0-role1a', 'ci0-role-1a'],
            sorted([role["name"] for role in composites_f])
        )
        # .publish must revert change
        creation_state = role_resource.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = role_resource.publish()
        self.assertFalse(creation_state)
        _check_state()

        # ------------------------------------------------------------------------
        # publish composite role, with include_composite=False should not destroy existing composites
        # The composites should only remain unmodified.
        creation_state = role_resource.publish(include_composite=False)
        self.assertFalse(creation_state)
        _check_state()
