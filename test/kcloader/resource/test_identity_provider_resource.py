import os
import unittest
from glob import glob
from copy import copy

from kcloader.resource import IdentityProviderResource, IdentityProviderMapperResource, \
    IdentityProviderManager, IdentityProviderMapperManager
from kcloader.tools import read_from_json, find_in_list
from ...helper import TestBed, remove_field_id, TestCaseBase


class TestIdentityProviderBase(TestCaseBase):
    def setUp(self):
        super().setUp()
        self.idp0_alias = "ci0-idp-saml-0"
        testbed = self.testbed

        idp0_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/identity-provider/ci0-idp-saml-0/ci0-idp-saml-0.json")
        self.idp0_resource = IdentityProviderResource({
            'path': idp0_filepath,
            'keycloak_api': testbed.kc,
            'realm': testbed.REALM,
            'datadir': testbed.DATADIR,
        })

        idp0_mapper1_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/identity-provider/ci0-idp-saml-0/mappers/idp-mapper-1.json")
        self.idp0_mapper1_resource = IdentityProviderMapperResource({
            'path': idp0_mapper1_filepath,
            'keycloak_api': testbed.kc,
            'realm': testbed.REALM,
            'datadir': testbed.DATADIR,
        })

        self.idp_api = testbed.kc.build("identity-provider", testbed.REALM)
        self.idp0_mappers_api = testbed.kc.build(f"identity-provider/instances/{self.idp0_alias}/mappers", testbed.REALM)

        # check clean start
        assert self.idp_api.all() == []

    @classmethod
    def tearDownClass(cls):
        # Removing realm make sense. But debugging is easier if realm is left.
        pass

    def assertUnorderedListOfDictEqual(self, a, b, key, msg=None):
        self.assertEqual(
            sorted(a, key=lambda x: x[key]),
            sorted(b, key=lambda x: x[key]),
            msg=msg,
        )


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
        idp0_resource = self.idp0_resource
        idp_api = self.idp_api
        idp0_alias = self.idp0_alias
        expected_idp = self.expected_idp

        # create IdP
        creation_state = idp0_resource.publish_self()
        self.assertTrue(creation_state)
        # check objects are created
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        # idp = idp_api.findFirstByKV("alias", idp0_alias)
        idp_a = idp_all[0]
        self.assertEqual(idp_a, idp_a | expected_idp)

        # publish same data again
        creation_state = idp0_resource.publish_self()
        self.assertFalse(creation_state)
        # check content is not modified
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        idp_b = idp_all[0]
        # check objects are not recreated without reason.
        self.assertEqual(idp_a["internalId"], idp_b["internalId"])
        self.assertEqual(idp_a, idp_b)

        # modify something
        idp_api.update_rmw(idp0_alias, {'displayName': 'ci0-idp-saml-0-displayName-NEW'})
        self.assertEqual('ci0-idp-saml-0-displayName-NEW', idp_api.findFirstByKV("alias", idp0_alias)['displayName'])
        # publish same data again
        creation_state = idp0_resource.publish_self()
        self.assertTrue(creation_state)
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        idp_c = idp_all[0]
        self.assertEqual(idp_c, idp_c | expected_idp)
        self.assertEqual('ci0-idp-saml-0-displayName', idp_api.findFirstByKV("alias", idp0_alias)['displayName'])

    def test_publish(self):
        idp0_resource = self.idp0_resource
        idp_api = self.idp_api
        idp0_alias = self.idp0_alias
        expected_idp = self.expected_idp
        idp0_mappers_api = self.idp0_mappers_api

        # create IdP and mappers
        creation_state = idp0_resource.publish()
        self.assertTrue(creation_state)
        # check objects are created
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        idp_a = idp_all[0]
        self.assertEqual(idp_a, idp_a | expected_idp)
        # check mapper objects are created
        idp_mappers = idp0_mappers_api.all()
        self.assertEqual(len(idp_mappers), 2)
        idp_mapper_names = [obj["name"] for obj in idp_mappers]
        self.assertListEqual(sorted(["ci0-saml-template-mapper", "idp-mapper-1"]), sorted(idp_mapper_names))
        idp_mapper_a_ids = [obj["id"] for obj in idp_mappers]

        # publish same data again
        creation_state = idp0_resource.publish()
        self.assertFalse(creation_state)
        # check content is not modified
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)
        idp_b = idp_all[0]
        # check objects are not recreated without reason.
        self.assertEqual(idp_a["internalId"], idp_b["internalId"])
        self.assertEqual(idp_a, idp_b)
        # check mapper objects are not recreated without reason
        idp_mappers = idp0_mappers_api.all()
        self.assertEqual(len(idp_mappers), 2)
        idp_mapper_names = [obj["name"] for obj in idp_mappers]
        self.assertListEqual(sorted(["ci0-saml-template-mapper", "idp-mapper-1"]), sorted(idp_mapper_names))
        idp_mapper_b_ids = [obj["id"] for obj in idp_mappers]
        self.assertListEqual(idp_mapper_a_ids, idp_mapper_b_ids)


class TestIdentityProviderManager(TestIdentityProviderBase):
    def test_publish(self):
        # also test helper methods
        idp_api = self.idp_api
        idp0_mappers_api = self.idp0_mappers_api
        # idp0_alias = self.idp0_alias
        manager = IdentityProviderManager(self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR)

        create_ids, delete_ids = manager._difference_ids()
        self.assertEqual(['ci0-idp-saml-0', 'ci0-idp-saml-1'], sorted(create_ids))
        self.assertEqual([], delete_ids)

        creation_state = manager.publish()
        self.assertTrue(creation_state)
        idp_all = idp_api.all()
        self.assertEqual(['ci0-idp-saml-0', 'ci0-idp-saml-1'], sorted([obj["alias"] for obj in idp_all]))
        idp_mappers = idp0_mappers_api.all()
        idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
        self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)

        create_ids, delete_ids = manager._difference_ids()
        self.assertEqual([], create_ids)
        self.assertEqual([], delete_ids)

        creation_state = manager.publish()
        self.assertFalse(creation_state)
        idp_all = idp_api.all()
        self.assertEqual(['ci0-idp-saml-0', 'ci0-idp-saml-1'], sorted([obj["alias"] for obj in idp_all]))
        idp_mappers = idp0_mappers_api.all()
        idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
        self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)

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
        self.assertEqual(len(idp_all), 3)
        idp_aliases = sorted([obj["alias"] for obj in idp_all])
        self.assertListEqual(sorted(["ci0-idp-x-to-be-deleted", "ci0-idp-saml-0", "ci0-idp-saml-1"]), idp_aliases)

        create_ids, delete_ids = manager._difference_ids()
        self.assertEqual([], create_ids)
        self.assertEqual(['ci0-idp-x-to-be-deleted'], delete_ids)

        # check extra IdP is deleted
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        idp_all = idp_api.all()
        self.assertEqual(["ci0-idp-saml-0", "ci0-idp-saml-1"], sorted([obj["alias"] for obj in idp_all]))
        idp_mappers = idp0_mappers_api.all()
        idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
        self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)


class TestIdentityProviderMapperResource(TestIdentityProviderBase):
    def test_publish(self):
        self.maxDiff = None
        expected_idp_mappers = [
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

        testbed = self.testbed
        idp_api = self.idp_api
        idp0_mappers_api = self.idp0_mappers_api

        # create IdP
        idp0_resource = self.idp0_resource
        creation_state = idp0_resource.publish_self()
        self.assertTrue(creation_state)
        # END prepare
        # =============================================================================================

        # create mappers
        # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/identity-provider/instances/ci0-idp-saml-0/mappers
        idp_mapper_filepath = os.path.join(testbed.DATADIR, f"{testbed.REALM}/identity-provider/ci0-idp-saml-0/mappers/idp-mapper-1.json")
        idp_mapper = self.idp0_mapper1_resource
        status = self.idp0_mapper1_resource.publish()
        self.assertTrue(status)
        idp_mappers_a = idp0_mappers_api.all()
        idp_mappers_a__no_id = [remove_field_id(copy(obj)) for obj in idp_mappers_a]
        idp_mappers_a__ids = [obj["id"] for obj in idp_mappers_a]
        self.assertUnorderedListOfDictEqual(expected_idp_mappers, idp_mappers_a__no_id, "name")

        # recreate mapper
        # idp_mappers = IdentityProviderMapperResource.create_from_realm_doc(testbed.DATADIR, testbed.kc, testbed.REALM)
        status = self.idp0_mapper1_resource.publish()
        self.assertFalse(status)
        idp_mappers_b = idp0_mappers_api.all()
        idp_mappers_b__no_id = [remove_field_id(copy(obj)) for obj in idp_mappers_b]
        idp_mappers_b__ids = [obj["id"] for obj in idp_mappers_b]
        self.assertUnorderedListOfDictEqual(expected_idp_mappers, idp_mappers_b__no_id, "name")
        # check object were not re-created
        self.assertEqual(idp_mappers_a__ids, idp_mappers_b__ids)

        # modify something
        self.assertEqual("idp-mapper-1", idp_mappers_b[0]["name"])
        idp_mapper_1 = idp_mappers_b[0]
        # update_rmw - does not know how to merge dict
        idp_mapper_1_new = copy(idp_mapper_1)
        idp_mapper_1_new["config"].update({"attribute.friendly.name": "attr-friendly-name-NEW"})
        idp0_mappers_api.update(idp_mapper_1["id"], idp_mapper_1_new)
        self.assertEqual("attr-friendly-name-NEW", idp0_mappers_api.findFirstByKV("name", "idp-mapper-1")["config"]["attribute.friendly.name"])
        # publish same data again
        status = self.idp0_mapper1_resource.publish()
        self.assertTrue(status)
        self.assertEqual("attr-friendly-name", idp0_mappers_api.findFirstByKV("name", "idp-mapper-1")["config"]["attribute.friendly.name"])
        # check object were not re-created
        idp_mappers_c = idp0_mappers_api.all()
        idp_mappers_c__ids = [obj["id"] for obj in idp_mappers_c]
        self.assertEqual(idp_mappers_a__ids, idp_mappers_c__ids)

class TestIdentityProviderManager(TestIdentityProviderBase):
    def test_publish(self):
        # also test helper methods
        idp_api = self.idp_api
        idp0_mappers_api = self.idp0_mappers_api
        idp0_alias = self.idp0_alias

        # create IdP, without any mapper
        # create IdP
        creation_state = self.idp0_resource.publish_self()
        self.assertTrue(creation_state)
        # check objects are created
        idp_all = idp_api.all()
        self.assertEqual(len(idp_all), 1)

        # END prepare
        # =============================================================================================

        manager = IdentityProviderMapperManager(self.testbed.kc, self.testbed.REALM, self.testbed.DATADIR, idp_alias=idp0_alias)

        create_ids, delete_ids, delete_ids_for_api = manager._difference_ids()
        self.assertEqual(['ci0-saml-template-mapper', 'idp-mapper-1'], sorted(create_ids))
        self.assertEqual([], delete_ids)
        self.assertEqual([], delete_ids_for_api)

        creation_state = manager.publish()
        self.assertTrue(creation_state)
        idp_mappers = idp0_mappers_api.all()
        idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
        self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)

        create_ids, delete_ids, delete_ids_for_api = manager._difference_ids()
        self.assertEqual([], create_ids)
        self.assertEqual([], delete_ids)
        self.assertEqual([], delete_ids_for_api)

        creation_state = manager.publish()
        self.assertFalse(creation_state)
        idp_mappers = idp0_mappers_api.all()
        idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
        self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)

        # ------------------------------------------------------------------------------
        # create an additional IdP mapper
        idp0_mappers_api.create({
            "config": {
                "attribute.friendly.name": "attr-friendly-name-TO-BE-DELETED",
                "attribute.name": "attr-name-TO-BE-DELETED",
                "attribute.value": "attr-value-TO-BE-DELETED",
                "role": "ci0-client-0-TO-BE-DELETED.ci0-client0-role0-TO-BE-DELETED"
            },
            "identityProviderAlias": "ci0-idp-saml-0",
            "identityProviderMapper": "saml-role-idp-mapper",
            "name": "idp-mapper-1-TO-BE-DELETED",
        }).isOk()
        idp_mappers = idp0_mappers_api.all()
        idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
        self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1", "idp-mapper-1-TO-BE-DELETED"], idp_mappers_names)

        create_ids, delete_ids, delete_ids_for_api = manager._difference_ids()
        self.assertEqual([], create_ids)
        self.assertEqual(['idp-mapper-1-TO-BE-DELETED'], delete_ids)
        self.assertEqual(1, len(delete_ids_for_api))

        # check extra IdP is deleted
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        idp_mappers = idp0_mappers_api.all()
        idp_mappers_names = sorted([obj["name"] for obj in idp_mappers])
        self.assertEqual(["ci0-saml-template-mapper", "idp-mapper-1"], idp_mappers_names)
