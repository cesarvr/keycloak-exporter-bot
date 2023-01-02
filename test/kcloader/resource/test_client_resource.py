import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import SingleClientResource, \
    IdentityProviderResource, IdentityProviderMapperResource, \
    IdentityProviderManager, IdentityProviderMapperManager
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase


class TestClientResource(TestCaseBase):
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

        # create client
        creation_state = client0_resource.publish_self()
        self.assertTrue(creation_state)
        # check objects are created
        clients_all = clients_api.all()
        self.assertEqual(len(clients_all), default_client_count + 1)
        client_a = clients_api.findFirstByKV("clientId", client0_clientId)
        self._sort_object(client_a)
        self.assertEqual(client_a, client_a | expected_client0)

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
