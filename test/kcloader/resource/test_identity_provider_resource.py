import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import IdentityProviderResource
from ...helper import TestBed


class TestIdentityProviderResource(unittest.TestCase):
    def test_publish(self):
        idp_alias = "ci0-idp-saml-0"
        expected_idp = {
            'addReadTokenRoleOnCreate': False,
            'alias': 'ci0-idp-saml-0',
            'authenticateByDefault': False,
            'config': {'allowCreate': 'true',
                       'authnContextClassRefs': '["aa","bb"]',
                       'authnContextComparisonType': 'exact',
                       'authnContextDeclRefs': '["cc","dd"]',
                       'entityId': 'https://172.17.0.2:8443/auth/realms/ci0-realm',
                       'nameIDPolicyFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                       'principalType': 'SUBJECT',
                       'signatureAlgorithm': 'RSA_SHA256',
                       'singleLogoutServiceUrl': 'https://172.17.0.6:8443/logout',
                       'singleSignOnServiceUrl': 'https://172.17.0.6:8443/signon',
                       'syncMode': 'IMPORT',
                       'useJwksUrl': 'true',
                       'wantAssertionsEncrypted': 'true',
                       'xmlSigKeyInfoKeyNameTransformer': 'KEY_ID'},
            'displayName': 'ci0-idp-saml-0-displayName',
            'enabled': True,
            'firstBrokerLoginFlowAlias': 'first broker login',
            # 'internalId': '762712d6-6f2c-4d93-adc0-dd3aed625c9c',
            'linkOnly': False,
            'providerId': 'saml',
            'storeToken': False,
            'trustEmail': False,
            'updateProfileFirstLoginMode': 'on',
        }

        testbed = TestBed(realm='ci0-realm')
        idp_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/identity-provider/ci0-idp-saml-0.json")
        idp_resource = IdentityProviderResource({
            'path': idp_filepath,
            'keycloak_api': testbed.kc,
            'realm': testbed.REALM,
            'datadir': testbed.DATADIR,
        })

        # create min realm first, ensure clean start
        testbed.kc.admin().remove(testbed.REALM)
        testbed.kc.admin().create({"realm": testbed.REALM})

        # check clean start
        idp_api = testbed.kc.build("identity-provider", testbed.REALM)
        self.assertFalse(idp_api.findFirstByKV("alias", idp_alias))

        # create IdP
        creation_state = idp_resource.publish()
        self.assertTrue(creation_state)
        # check objects are created
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        # idp = idp_api.findFirstByKV("alias", idp_alias)
        idp_a = idp_all[0]
        self.assertEqual(idp_a, idp_a | expected_idp)

        # publish same data again
        creation_state = idp_resource.publish()
        self.assertTrue(creation_state)  # todo created should be False
        # check content is not modified
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        idp_b = idp_all[0]
        # check objects are not recreated without reason.
        self.assertEqual(idp_a["internalId"], idp_b["internalId"])
        self.assertEqual(idp_a, idp_b)

        # modify something, publish same data again
        idp_api.update_rmw(idp_alias, {'displayName': 'ci0-idp-saml-0-displayName-NEW'})
        self.assertEqual('ci0-idp-saml-0-displayName-NEW', idp_api.findFirstByKV("alias", idp_alias)['displayName'])
        creation_state = idp_resource.publish()
        self.assertTrue(creation_state)
        self.assertEqual('ci0-idp-saml-0-displayName', idp_api.findFirstByKV("alias", idp_alias)['displayName'])
