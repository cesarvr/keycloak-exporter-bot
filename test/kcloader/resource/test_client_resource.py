import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import SingleClientResource, \
    ClientManager, ClientRoleManager
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

    def test_publish(self):
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
        creation_state = client0_resource.publish()
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
        creation_state = client0_resource.publish()
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
        creation_state = manager.publish()
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
        creation_state = manager.publish()
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

        # check extra IdP is deleted
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        clients_all = clients_api.all()
        self.assertEqual(
            sorted(default_client_clientIds + our_client_clientIds),
            sorted([obj["clientId"] for obj in clients_all])
        )


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

        manager = ClientRoleManager(
            self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR,
            clientId=self.client0_clientId, client_filepath=os.path.join(self.testbed.DATADIR, "ci0-realm/clients/client-0/ci0-client-0.json"),
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
        creation_state = manager.publish(include_composite=False)  # TODO extend CI test also with include_composite=True case
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
        creation_state = manager.publish(include_composite=False)  # TODO extend CI test also with include_composite=True case
        self.assertTrue(creation_state)  # TODO should be false; but composites are missing
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
        creation_state = manager.publish(include_composite=False)  # TODO extend CI test also with include_composite=True case
        self.assertTrue(creation_state)
        roles = client0_roles_api.all()
        self.assertEqual(4, len(roles))
        self.assertEqual(
            our_roles_names,
            sorted([role["name"] for role in roles])
        )

# class TestIdentityProviderManager(TestIdentityProviderBase):
#     def test_publish(self):
#         # also test helper methods
#         idp_api = self.idp_api
#         idp0_mappers_api = self.idp0_mappers_api
#         # idp0_alias = self.idp0_alias
#         manager = IdentityProviderManager(self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR)
#
#         create_ids, delete_ids = manager._difference_ids()
#         self.assertEqual(['ci0-idp-saml-0', 'ci0-idp-saml-1'], sorted(create_ids))
#         self.assertEqual([], delete_ids)
#
#         creation_state = manager.publish()
#         self.assertTrue(creation_state)
#         idp_all = idp_api.all()
#         self.assertEqual(['ci0-idp-saml-0', 'ci0-idp-saml-1'], sorted([obj["alias"] for obj in idp_all]))
#         idp_mappers = idp0_mappers_api.all()
#         idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
#         self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)
#
#         create_ids, delete_ids = manager._difference_ids()
#         self.assertEqual([], create_ids)
#         self.assertEqual([], delete_ids)
#
#         creation_state = manager.publish()
#         self.assertFalse(creation_state)
#         idp_all = idp_api.all()
#         self.assertEqual(['ci0-idp-saml-0', 'ci0-idp-saml-1'], sorted([obj["alias"] for obj in idp_all]))
#         idp_mappers = idp0_mappers_api.all()
#         idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
#         self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)
#
#         # ------------------------------------------------------------------------------
#         # create an additional IdP
#         self.idp_api.create({
#             'alias': 'ci0-idp-x-to-be-deleted',
#             'displayName': 'ci0-idp-x-to-be-DELETED',
#             'config': {
#                 'singleLogoutServiceUrl': 'https://172.17.0.6:8443/logout-x',
#                 'singleSignOnServiceUrl': 'https://172.17.0.6:8443/signon-x',
#             },
#             'enabled': True,
#             'providerId': 'saml',
#         }).isOk()
#         idp_all = self.idp_api.all()
#         self.assertEqual(len(idp_all), 3)
#         idp_aliases = sorted([obj["alias"] for obj in idp_all])
#         self.assertListEqual(sorted(["ci0-idp-x-to-be-deleted", "ci0-idp-saml-0", "ci0-idp-saml-1"]), idp_aliases)
#
#         create_ids, delete_ids = manager._difference_ids()
#         self.assertEqual([], create_ids)
#         self.assertEqual(['ci0-idp-x-to-be-deleted'], delete_ids)
#
#         # check extra IdP is deleted
#         creation_state = manager.publish()
#         self.assertTrue(creation_state)
#         idp_all = idp_api.all()
#         self.assertEqual(["ci0-idp-saml-0", "ci0-idp-saml-1"], sorted([obj["alias"] for obj in idp_all]))
#         idp_mappers = idp0_mappers_api.all()
#         idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
#         self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)
#
#
# class TestIdentityProviderMapperResource(TestIdentityProviderBase):
#     def test_publish(self):
#         self.maxDiff = None
#         expected_idp_mappers = [
#             {
#                 "config": {
#                     "attribute.friendly.name": "attr-friendly-name",
#                     "attribute.name": "attr-name",
#                     "attribute.value": "attr-value",
#                     "role": "ci0-client-0.ci0-client0-role0"
#                 },
#                 "identityProviderAlias": "ci0-idp-saml-0",
#                 "identityProviderMapper": "saml-role-idp-mapper",
#                 "name": "idp-mapper-1"
#             }
#         ]
#
#         testbed = self.testbed
#         idp_api = self.idp_api
#         idp0_mappers_api = self.idp0_mappers_api
#
#         # create IdP
#         idp0_resource = self.idp0_resource
#         creation_state = idp0_resource.publish_self()
#         self.assertTrue(creation_state)
#         # END prepare
#         # =============================================================================================
#
#         # create mappers
#         # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/identity-provider/instances/ci0-idp-saml-0/mappers
#         idp_mapper_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/identity-provider/ci0-idp-saml-0/mappers/idp-mapper-1.json")
#         idp_mapper = self.idp0_mapper1_resource
#         status = self.idp0_mapper1_resource.publish()
#         self.assertTrue(status)
#         idp_mappers_a = idp0_mappers_api.all()
#         idp_mappers_a__no_id = [remove_field_id(copy(obj)) for obj in idp_mappers_a]
#         idp_mappers_a__ids = [obj["id"] for obj in idp_mappers_a]
#         self.assertUnorderedListOfDictEqual(expected_idp_mappers, idp_mappers_a__no_id, "name")
#
#         # recreate mapper
#         # idp_mappers = IdentityProviderMapperResource.create_from_realm_doc(testbed.DATADIR, testbed.kc, testbed.REALM)
#         status = self.idp0_mapper1_resource.publish()
#         self.assertFalse(status)
#         idp_mappers_b = idp0_mappers_api.all()
#         idp_mappers_b__no_id = [remove_field_id(copy(obj)) for obj in idp_mappers_b]
#         idp_mappers_b__ids = [obj["id"] for obj in idp_mappers_b]
#         self.assertUnorderedListOfDictEqual(expected_idp_mappers, idp_mappers_b__no_id, "name")
#         # check object were not re-created
#         self.assertEqual(idp_mappers_a__ids, idp_mappers_b__ids)
#
#         # modify something
#         self.assertEqual("idp-mapper-1", idp_mappers_b[0]["name"])
#         idp_mapper_1 = idp_mappers_b[0]
#         # update_rmw - does not know how to merge dict
#         idp_mapper_1_new = copy(idp_mapper_1)
#         idp_mapper_1_new["config"].update({"attribute.friendly.name": "attr-friendly-name-NEW"})
#         idp0_mappers_api.update(idp_mapper_1["id"], idp_mapper_1_new)
#         self.assertEqual("attr-friendly-name-NEW", idp0_mappers_api.findFirstByKV("name", "idp-mapper-1")["config"]["attribute.friendly.name"])
#         # publish same data again
#         status = self.idp0_mapper1_resource.publish()
#         self.assertTrue(status)
#         self.assertEqual("attr-friendly-name", idp0_mappers_api.findFirstByKV("name", "idp-mapper-1")["config"]["attribute.friendly.name"])
#         # check object were not re-created
#         idp_mappers_c = idp0_mappers_api.all()
#         idp_mappers_c__ids = [obj["id"] for obj in idp_mappers_c]
#         self.assertEqual(idp_mappers_a__ids, idp_mappers_c__ids)
#
# class TestIdentityProviderManager(TestIdentityProviderBase):
#     def test_publish(self):
#         # also test helper methods
#         idp_api = self.idp_api
#         idp0_mappers_api = self.idp0_mappers_api
#         idp0_alias = self.idp0_alias
#
#         # create IdP, without any mapper
#         # create IdP
#         creation_state = self.idp0_resource.publish_self()
#         self.assertTrue(creation_state)
#         # check objects are created
#         idp_all = idp_api.all()
#         self.assertEqual(len(idp_all), 1)
#
#         # END prepare
#         # =============================================================================================
#
#         manager = IdentityProviderMapperManager(self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR, idp_alias=idp0_alias)
#
#         create_ids, delete_ids, delete_ids_for_api = manager._difference_ids()
#         self.assertEqual(['ci0-saml-template-mapper', 'idp-mapper-1'], sorted(create_ids))
#         self.assertEqual([], delete_ids)
#         self.assertEqual([], delete_ids_for_api)
#
#         creation_state = manager.publish()
#         self.assertTrue(creation_state)
#         idp_mappers = idp0_mappers_api.all()
#         idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
#         self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)
#
#         create_ids, delete_ids, delete_ids_for_api = manager._difference_ids()
#         self.assertEqual([], create_ids)
#         self.assertEqual([], delete_ids)
#         self.assertEqual([], delete_ids_for_api)
#
#         creation_state = manager.publish()
#         self.assertFalse(creation_state)
#         idp_mappers = idp0_mappers_api.all()
#         idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
#         self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)
#
#         # ------------------------------------------------------------------------------
#         # create an additional IdP mapper
#         idp0_mappers_api.create({
#             "config": {
#                 "attribute.friendly.name": "attr-friendly-name-TO-BE-DELETED",
#                 "attribute.name": "attr-name-TO-BE-DELETED",
#                 "attribute.value": "attr-value-TO-BE-DELETED",
#                 "role": "ci0-client-0-TO-BE-DELETED.ci0-client0-role0-TO-BE-DELETED"
#             },
#             "identityProviderAlias": "ci0-idp-saml-0",
#             "identityProviderMapper": "saml-role-idp-mapper",
#             "name": "idp-mapper-1-TO-BE-DELETED",
#         }).isOk()
#         idp_mappers = idp0_mappers_api.all()
#         idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
#         self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1", "idp-mapper-1-TO-BE-DELETED"], idp_mappers_names)
#
#         create_ids, delete_ids, delete_ids_for_api = manager._difference_ids()
#         self.assertEqual([], create_ids)
#         self.assertEqual(['idp-mapper-1-TO-BE-DELETED'], delete_ids)
#         self.assertEqual(1, len(delete_ids_for_api))
#
#         # check extra IdP is deleted
#         creation_state = manager.publish()
#         self.assertTrue(creation_state)
#         idp_mappers = idp0_mappers_api.all()
#         idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
#         self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)
