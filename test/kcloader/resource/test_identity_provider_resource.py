import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import IdentityProviderResource, IdentityProviderMapperResource, IdentityProviderManager
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id


# def setUpModule():
#     pass  # createConnection()
#
#
# def tearDownModule():
#     pass  # closeConnection()


class TestIdentityProviderBase(unittest.TestCase):
    # def setUp(self):
    #     pass
    #
    # def tearDown(self):
    #     pass

    @classmethod
    def setUpClass(cls):
        cls.idp_alias = "ci0-idp-saml-0"
        cls.testbed = TestBed(realm='ci0-realm')
        testbed = cls.testbed
        idp_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/identity-provider/ci0-idp-saml-0.json")
        cls.idp_resource = IdentityProviderResource({
            'path': idp_filepath,
            'keycloak_api': testbed.kc,
            'realm': testbed.REALM,
            'datadir': testbed.DATADIR,
        })
        cls.idp_api = testbed.kc.build("identity-provider", testbed.REALM)

        # create min realm first, ensure clean start
        testbed.kc.admin().remove(testbed.REALM)
        testbed.kc.admin().create({"realm": testbed.REALM})

        # check clean start
        assert cls.idp_api.all() == []

    @classmethod
    def tearDownClass(cls):
        # Removing realm make sense. But debugging is easier if realm is left.
        pass


class TestIdentityProviderResource(TestIdentityProviderBase):
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

    # 0.7 sec for setUpClass()
    # def test_noop(self):
    #     pass

    def test_publish_self(self):
        idp_resource = self.idp_resource
        idp_api = self.idp_api
        idp_alias = self.idp_alias
        expected_idp = self.expected_idp

        # create IdP
        creation_state = idp_resource.publish_self()
        self.assertTrue(creation_state)
        # check objects are created
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        # idp = idp_api.findFirstByKV("alias", idp_alias)
        idp_a = idp_all[0]
        self.assertEqual(idp_a, idp_a | expected_idp)

        # publish same data again
        creation_state = idp_resource.publish_self()
        self.assertTrue(creation_state)  # todo created should be False
        # check content is not modified
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        idp_b = idp_all[0]
        # check objects are not recreated without reason.
        self.assertEqual(idp_a["internalId"], idp_b["internalId"])
        self.assertEqual(idp_a, idp_b)

        # modify something
        idp_api.update_rmw(idp_alias, {'displayName': 'ci0-idp-saml-0-displayName-NEW'})
        self.assertEqual('ci0-idp-saml-0-displayName-NEW', idp_api.findFirstByKV("alias", idp_alias)['displayName'])
        # publish same data again
        creation_state = idp_resource.publish_self()
        self.assertTrue(creation_state)
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        idp_c = idp_all[0]
        self.assertEqual(idp_c, idp_c | expected_idp)
        self.assertEqual('ci0-idp-saml-0-displayName', idp_api.findFirstByKV("alias", idp_alias)['displayName'])


class TestIdentityProviderManager(TestIdentityProviderBase):
    def test_publish(self):
        # also test helper methods
        idp_api = self.idp_api
        idp_alias = self.idp_alias
        manager = IdentityProviderManager(self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR)

        create_ids, delete_ids = manager._difference_ids()
        self.assertEqual([idp_alias], create_ids)
        self.assertEqual([], delete_ids)

        creation_state = manager.publish()
        self.assertTrue(creation_state)
        idp_all = idp_api.all()
        self.assertEqual([idp_alias], [obj["alias"] for obj in idp_all])

        create_ids, delete_ids = manager._difference_ids()
        self.assertEqual([], create_ids)
        self.assertEqual([], delete_ids)

        creation_state = manager.publish()
        self.assertTrue(creation_state)  # TODO false
        idp_all = idp_api.all()
        self.assertEqual([idp_alias], [obj["alias"] for obj in idp_all])

        # ------------------------------------------------------------------------------
        # create an additional IdP
        self.idp_api.create({
            'alias': 'ci0-idp-x-to-be-deleted',
            'displayName': 'ci0-idp-x-to-be-DELETED',
            'config': {
                'singleLogoutServiceUrl': 'https://172.17.0.6:8443/logout-x',
                'singleSignOnServiceUrl': 'https://172.17.0.6:8443/signon-x',
            },
            'enabled': True,
            'providerId': 'saml',
        }).isOk()
        idp_all = self.idp_api.all()
        self.assertEqual(len(idp_all), 2)
        idp_aliases = sorted([obj["alias"] for obj in idp_all])
        self.assertListEqual(sorted(["ci0-idp-x-to-be-deleted", "ci0-idp-saml-0"]), idp_aliases)

        create_ids, delete_ids = manager._difference_ids()
        self.assertEqual([], create_ids)
        self.assertEqual(['ci0-idp-x-to-be-deleted'], delete_ids)

        # check extra IdP is deleted
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        idp_all = idp_api.all()
        self.assertEqual([idp_alias], [obj["alias"] for obj in idp_all])


class TestIdentityProviderMapperResource(unittest.TestCase):
    def assertUnorderedListOfDictEqual(self, a, b, key, msg=None):
        self.assertEqual(
            sorted(a, key=lambda x: x[key]),
            sorted(b, key=lambda x: x[key]),
            msg=msg,
        )

    def test_publish(self):
        self.maxDiff = None
        idp_alias = "ci0-idp-saml-0"
        # ci0-realm.json, attribute identityProviderMappers
        expected_idp_mappers = [
            {
                "config": {
                    "are.attribute.values.regex": "false",
                    "attributes": "[{\"key\":\"key0\",\"value\":\"value0\"}]",
                    "role": "ci0-role-0",
                    "syncMode": "INHERIT"
                },
                "identityProviderAlias": "ci0-idp-saml-0",
                "identityProviderMapper": "saml-advanced-role-idp-mapper",
                "name": "idp-mapper-0b"
            },
            {
                "config": {
                    "attribute.friendly.name": "attr-friendly-name",
                    "attribute.name": "attr-name",
                    "attribute.value": "attr-value",
                    "role": "ci0-client-0.ci0-client0-role0"
                },
                "identityProviderAlias": "ci0-idp-saml-0",
                "identityProviderMapper": "saml-role-idp-mapper",
                "name": "idp-mapper-1"
            }
        ]

        testbed = TestBed(realm='ci0-realm')
        idp_api = testbed.kc.build("identity-provider", testbed.REALM)
        idp_mappers_api = testbed.kc.build(f"identity-provider/instances/{idp_alias}/mappers", testbed.REALM)

        idp_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/identity-provider/ci0-idp-saml-0.json")
        idp_doc = read_from_json(idp_filepath)
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
        self.assertFalse(idp_api.findFirstByKV("alias", idp_alias))
        # self.assertEqual([], idp_mappers_api.all())

        # create IdP
        creation_state = idp_resource.publish_self()
        self.assertTrue(creation_state)
        # END prepare
        # =============================================================================================

        # create mappers
        # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/identity-provider/instances/ci0-idp-saml-0/mappers
        # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/identity-provider/instances/ci0-idp-saml-0/mappers
        idp_mappers = IdentityProviderMapperResource.create_from_realm_doc(testbed.DATADIR, testbed.kc, testbed.REALM)
        for idp_mapper in idp_mappers:
            status = idp_mapper.publish()
            self.assertTrue(status)
        idp_mappers_a = idp_mappers_api.all()
        idp_mappers_a__no_id = [remove_field_id(copy(obj)) for obj in idp_mappers_a]
        idp_mappers_a__ids = [obj["id"] for obj in idp_mappers_a]
        self.assertUnorderedListOfDictEqual(expected_idp_mappers, idp_mappers_a__no_id, "name")

        # recreate mappers
        # idp_mappers = IdentityProviderMapperResource.create_from_realm_doc(testbed.DATADIR, testbed.kc, testbed.REALM)
        for idp_mapper in idp_mappers:
            status = idp_mapper.publish()
            self.assertTrue(status)  # TODO should be status==False
        idp_mappers_b = idp_mappers_api.all()
        idp_mappers_b__no_id = [remove_field_id(copy(obj)) for obj in idp_mappers_b]
        idp_mappers_b__ids = [obj["id"] for obj in idp_mappers_b]
        self.assertUnorderedListOfDictEqual(expected_idp_mappers, idp_mappers_b__no_id, "name")
        # check object were not re-created
        self.assertEqual(idp_mappers_a__ids, idp_mappers_b__ids)

        # modify something
        idp_mapper_1 = find_in_list(idp_mappers_b, name="idp-mapper-1")
        # update_rmw - does not know how to merge dict
        idp_mapper_1_new = copy(idp_mapper_1)
        idp_mapper_1_new["config"].update({"attribute.friendly.name": "attr-friendly-name-NEW"})
        idp_mappers_api.update(idp_mapper_1["id"], idp_mapper_1_new)
        self.assertEqual("attr-friendly-name-NEW", idp_mappers_api.findFirstByKV("name", "idp-mapper-1")["config"]["attribute.friendly.name"])
        # publish same data again
        for idp_mapper in idp_mappers:
            status = idp_mapper.publish()
            self.assertTrue(status)  # TODO should be one True, other False
        self.assertEqual("attr-friendly-name", idp_mappers_api.findFirstByKV("name", "idp-mapper-1")["config"]["attribute.friendly.name"])
        # check object were not re-created
        idp_mappers_c = idp_mappers_api.all()
        idp_mappers_c__ids = [obj["id"] for obj in idp_mappers_c]
        self.assertEqual(idp_mappers_a__ids, idp_mappers_c__ids)
