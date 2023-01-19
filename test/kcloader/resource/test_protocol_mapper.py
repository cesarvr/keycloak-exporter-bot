import logging
import json
import os
import unittest
from glob import glob
from copy import copy

from kcapi.rest.crud import KeycloakCRUD

from kcloader.resource import ClientScopeResource, ClientScopeScopeMappingsRealmManager, \
    ClientScopeProtocolMapperResource, ClientScopeProtocolMapperManager, \
    ClientScopeScopeMappingsClientManager, ClientScopeScopeMappingsAllClientsManager, \
    ClientScopeManager
from kcloader.tools import read_from_json, find_in_list
from kcloader.resource.protocol_mapper import ClientProtocolMapperResource, ClientProtocolMapperManager
from ...helper import TestBed, remove_field_id, TestCaseBase
from .test_client_scope_resource import blacklisted_client_scopes

logger = logging.getLogger(__name__)


class TestClientScopeProtocolMapperResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)
        self.client_scope_name = "ci0-client-scope"
        self.client_scope_filepath = os.path.join(self.testbed.DATADIR, f"ci0-realm/client-scopes/{self.client_scope_name}.json")
        client_scope_doc = read_from_json(self.client_scope_filepath)
        # self.protocol_mapper_docs = client_scope_doc["protocolMappers"]
        self.client_scopes_api.create(client_scope_doc).isOk()
        client_scopes = self.client_scopes_api.all()
        # self.client_scope = find_in_list(client_scopes, name=self.client_scope_name)


    def test_publish(self):
        def _check_state():
            client_scopes_b = client_scopes_api.all()
            client_scope_b = find_in_list(client_scopes_b, name=client_scope_name)
            self.assertEqual(client_scope_a["id"], client_scope_b["id"])
            self.assertEqual(client_scope_a, client_scope_b)

            for ii in range(len(client_scope_a["protocolMappers"])):
                self.assertEqual(client_scope_a["protocolMappers"][ii]["id"], client_scope_b["protocolMappers"][ii]["id"])
            protocol_mappers_min = copy(client_scope_b["protocolMappers"])
            protocol_mappers_min = sorted(protocol_mappers_min, key=lambda obj: obj["name"])
            for pm in protocol_mappers_min:
                pm.pop("id")
            self.assertEqual(protocol_mapper_docs, protocol_mappers_min)

            # -------------------------------------

        self.maxDiff = None
        client_scope_name = self.client_scope_name
        client_scopes_api = self.client_scopes_api
        client_scopes = client_scopes_api.all()
        client_scope_a = find_in_list(client_scopes, name=self.client_scope_name)
        protocol_mappers_a = client_scope_a["protocolMappers"]
        protocol_mappers_a = sorted(protocol_mappers_a, key=lambda pm: pm["name"])
        protocol_mapper_api = client_scopes_api.protocol_mapper_api(client_scope_id=client_scope_a["id"])

        protocol_mapper_docs = [
            {
                'config': {
                    'access.token.claim': 'true',
                    'claim.name': 'birthdate',
                    'id.token.claim': 'true',
                    'jsonType.label': 'String',
                    'user.attribute': 'birthdate',
                    'userinfo.token.claim': 'true',
                },
                'consentRequired': False,
                'name': 'birthdate',
                'protocol': 'openid-connect',
                'protocolMapper': 'oidc-usermodel-attribute-mapper',
            },
        ]

        # check initial state
        self.assertEqual(
            sorted([self.client_scope_name] + blacklisted_client_scopes),
            sorted([client_scope["name"] for client_scope in client_scopes]),
        )
        # client_scope.publish_self() already created one initial protocolMapper.
        cs_protocol_mapper_id = client_scope_a["protocolMappers"][0]["id"]
        _check_state()

        cs_protocol_mapper = ClientScopeProtocolMapperResource(
            {
                'path': self.client_scope_filepath,
                'keycloak_api': self.testbed.kc,
                'realm': self.testbed.REALM,
                'datadir': self.testbed.DATADIR,
            },
            body=protocol_mapper_docs[0],
            client_scope_id=client_scope_a["id"],
        )

        # publish data - 1st time, protocol mapper was already created when client scope was created
        creation_state = cs_protocol_mapper.publish()
        self.assertFalse(creation_state)
        _check_state()

        # Now a clean start - remove the mapper, it will be recreated, with new id.
        self.assertEqual(1, len(protocol_mapper_api.all()))
        protocol_mapper_api.remove(cs_protocol_mapper_id, None).isOk()
        self.assertEqual(0, len(protocol_mapper_api.all()))

        # publish data - 1st time
        creation_state = cs_protocol_mapper.publish()
        self.assertTrue(creation_state)
        # only id should be different in this client_scopes_a
        client_scope_a = find_in_list(client_scopes_api.all(), name=self.client_scope_name)
        cs_protocol_mapper_id = client_scope_a["protocolMappers"][0]["id"]
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = cs_protocol_mapper.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        data = protocol_mapper_api.get_one(cs_protocol_mapper_id)
        data["config"].update({
            'claim.name': 'birthdate-NEW-a',
            'user.attribute': 'birthdate-NEW-b',
        })
        protocol_mapper_api.update(cs_protocol_mapper_id, data)
        data2 = protocol_mapper_api.get_one(cs_protocol_mapper_id)
        self.assertEqual(data, data2)
        #
        # .publish must revert change
        creation_state = cs_protocol_mapper.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = cs_protocol_mapper.publish()
        self.assertFalse(creation_state)
        _check_state()


class TestClientScopeProtocolMapperManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)
        self.client_scope_name = "ci0-client-scope"
        self.client_scope_filepath = os.path.join(self.testbed.DATADIR, f"ci0-realm/client-scopes/{self.client_scope_name}.json")

        client_scope_doc = read_from_json(self.client_scope_filepath)
        self.protocol_mapper_docs = client_scope_doc["protocolMappers"]
        self.client_scopes_api.create(client_scope_doc).isOk()

        client_scopes = self.client_scopes_api.all()
        self.client_scope = find_in_list(client_scopes, name=self.client_scope_name)
        self.assertEqual(self.client_scope_name, self.client_scope["name"])
        self.protocol_mapper_api = self.client_scopes_api.protocol_mapper_api(client_scope_id=self.client_scope["id"])

    def test_publish(self):
        def _check_state():
            protocol_mappers_b = protocol_mapper_api.all()
            protocol_mappers_b = sorted(protocol_mappers_b, key=lambda obj: obj["name"])
            self.assertEqual(protocol_mappers_a, protocol_mappers_b)

            for ii in range(len(protocol_mappers_b)):
                self.assertEqual(protocol_mappers_a[ii]["id"], protocol_mappers_b[ii]["id"])
            protocol_mappers_min = copy(protocol_mappers_b)
            for pm in protocol_mappers_min:
                pm.pop("id")
            self.assertEqual(self.protocol_mapper_docs, protocol_mappers_min)
            # -------------------------------------

        self.maxDiff = None
        extra_protocol_mapper_docs = [
            {
                'config': {
                    'access.token.claim': 'true',
                    'claim.name': 'birthdate-EXTRA',
                    'id.token.claim': 'true',
                    'jsonType.label': 'String',
                    'user.attribute': 'birthdate-EXTRA',
                    'userinfo.token.claim': 'true',
                },
                'consentRequired': False,
                'name': 'birthdate-EXTRA',
                'protocol': 'openid-connect',
                'protocolMapper': 'oidc-usermodel-attribute-mapper',
            },
        ]

        protocol_mapper_api = self.protocol_mapper_api
        protocol_mappers_a = protocol_mapper_api.all()
        protocol_mappers_a = sorted(protocol_mappers_a, key=lambda pm: pm["name"])
        protocol_mapper_a_0_min = copy(protocol_mappers_a[0])
        protocol_mapper_a_0_id = protocol_mapper_a_0_min.pop("id")

        # check initial state
        self.assertEqual(self.protocol_mapper_docs, [protocol_mapper_a_0_min])
        _check_state()

        cs_pm_manager = ClientScopeProtocolMapperManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
            requested_doc=self.protocol_mapper_docs,  # was read from json file
            client_scope_id=self.client_scope["id"],
        )

        # publish data - 1st time, protocol mapper was already created when client scope was created
        creation_state = cs_pm_manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # Now a clean start - remove the mapper, it will be recreated, with new id.
        self.assertEqual(1, len(protocol_mapper_api.all()))
        protocol_mapper_api.remove(protocol_mapper_a_0_id, None).isOk()
        self.assertEqual(0, len(protocol_mapper_api.all()))

        # publish data - 1st time
        creation_state = cs_pm_manager.publish()
        self.assertTrue(creation_state)
        # only id should be different in this client_scopes_a
        protocol_mappers_a = protocol_mapper_api.all()
        self.assertEqual(1, len(protocol_mappers_a))
        protocol_mapper_a_0_id = protocol_mappers_a[0]["id"]
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = cs_pm_manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # add extra mapper
        self.assertEqual(1, len(protocol_mapper_api.all()))
        protocol_mapper_api.create(extra_protocol_mapper_docs[0]).isOk()
        self.assertEqual(2, len(protocol_mapper_api.all()))
        #
        # publish data - 1st time
        creation_state = cs_pm_manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = cs_pm_manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something in mapper
        data = protocol_mapper_api.get_one(protocol_mapper_a_0_id)
        data["config"].update({
            'claim.name': 'birthdate-NEW-aa',
            'user.attribute': 'birthdate-NEW-bb',
        })
        protocol_mapper_api.update(protocol_mapper_a_0_id, data)
        data2 = protocol_mapper_api.get_one(protocol_mapper_a_0_id)
        self.assertEqual(data, data2)
        #
        # .publish must revert change
        creation_state = cs_pm_manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = cs_pm_manager.publish()
        self.assertFalse(creation_state)
        _check_state()


class TestClientProtocolMapperResource(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.client_clientId = "ci0-client-0"
        self.clients_api.create(dict(
            clientId=self.client_clientId,
            description=self.client_clientId + "---CI-INJECTED",
            protocol="openid-connect",
            fullScopeAllowed=False,  # this makes client:scopes configurable
        )).isOk()
        clients = self.clients_api.all()
        self.client = find_in_list(clients, clientId=self.client_clientId)
        self.client_protocol_mappers_api = KeycloakCRUD.get_child(self.clients_api, self.client["id"], "protocol-mappers/models")

    def test_publish(self):
        def _check_state():
            protocol_mappers_b = client_protocol_mappers_api.all()
            protocol_mappers_b = sorted(protocol_mappers_b, key=lambda obj: obj["name"])
            self.assertEqual(1, len(protocol_mappers_b))
            self.assertEqual(protocol_mappers_a, protocol_mappers_b)

            for ii in range(len(protocol_mappers_a)):
                self.assertEqual(protocol_mappers_a[ii]["id"], protocol_mappers_b[ii]["id"])
            protocol_mappers_min = copy(protocol_mappers_b)
            for pm in protocol_mappers_min:
                pm.pop("id")
            self.assertEqual([protocol_mapper_doc], protocol_mappers_min)

            # -------------------------------------

        self.maxDiff = None
        protocol_mapper_doc = {
            "config": {
                "access.token.claim": "true",
                "claim.name": "ci-claim-name",
                "id.token.claim": "true",
                "jsonType.label": "String",
                "user.attribute": "ci-user-property-name",
                "userinfo.token.claim": "true"
            },
            "consentRequired": False,
            "name": "ci0-client0-mapper-1",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper"
        }

        # check initial state
        client_protocol_mappers_api = self.client_protocol_mappers_api
        self.assertEqual([], client_protocol_mappers_api.all())

        client_protocol_mapper = ClientProtocolMapperResource(
            {
                'path': "self.client_filepath---but-is-ignored",
                'keycloak_api': self.testbed.kc,
                'realm': self.testbed.REALM,
                'datadir': self.testbed.DATADIR,
            },
            body=protocol_mapper_doc,
            client_id=self.client["id"],
        )

        # publish data - 1st time
        creation_state = client_protocol_mapper.publish()
        self.assertTrue(creation_state)
        protocol_mappers_a = client_protocol_mappers_api.all()
        protocol_mapper_id = find_in_list(protocol_mappers_a, name=protocol_mapper_doc["name"])["id"]
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = client_protocol_mapper.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something
        data = client_protocol_mappers_api.get_one(protocol_mapper_id)
        data["config"].update({
            'claim.name': 'birthdate-NEW-a',
            'user.attribute': 'birthdate-NEW-b',
        })
        client_protocol_mappers_api.update(protocol_mapper_id, data)
        data2 = client_protocol_mappers_api.get_one(protocol_mapper_id)
        self.assertEqual(data, data2)
        #
        # .publish must revert change
        creation_state = client_protocol_mapper.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = client_protocol_mapper.publish()
        self.assertFalse(creation_state)
        _check_state()


class TestClientProtocolMapperManager(TestCaseBase):
    def setUp(self):
        super().setUp()
        testbed = self.testbed

        self.clients_api = testbed.kc.build("clients", testbed.REALM)
        self.client_clientId = "ci0-client-0"
        self.clients_api.create(dict(
            clientId=self.client_clientId,
            description=self.client_clientId + "---CI-INJECTED",
            protocol="openid-connect",
            fullScopeAllowed=False,  # this makes client:scopes configurable
        )).isOk()
        clients = self.clients_api.all()
        self.client = find_in_list(clients, clientId=self.client_clientId)
        self.client_protocol_mappers_api = KeycloakCRUD.get_child(self.clients_api, self.client["id"], "protocol-mappers/models")

    def test_publish(self):
        def _check_state():
            protocol_mappers_b = client_protocol_mappers_api.all()
            protocol_mappers_b = sorted(protocol_mappers_b, key=lambda obj: obj["name"])
            self.assertEqual(2, len(protocol_mappers_b))
            self.assertEqual(protocol_mappers_a, protocol_mappers_b)

            for ii in range(len(protocol_mappers_a)):
                self.assertEqual(protocol_mappers_a[ii]["id"], protocol_mappers_b[ii]["id"])
            protocol_mappers_min = copy(protocol_mappers_b)
            for pm in protocol_mappers_min:
                pm.pop("id")
            self.assertEqual(protocol_mappers_doc, protocol_mappers_min)

            # -------------------------------------

        self.maxDiff = None
        # desired objects
        protocol_mappers_doc = [
            {
                "config": {
                    "access.token.claim": "true",
                    "claim.name": "ci-claim-name",
                    "id.token.claim": "true",
                    "jsonType.label": "String",
                    "user.attribute": "ci-user-property-name",
                    "userinfo.token.claim": "true"
                },
                "consentRequired": False,
                "name": "ci0-client0-mapper-1",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-property-mapper"
            },
            {
                "config": {
                    "access.token.claim": "true",
                    "claim.name": "gender",
                    "id.token.claim": "true",
                    "jsonType.label": "String",
                    "user.attribute": "gender",
                    "userinfo.token.claim": "true"
                },
                "consentRequired": False,
                "name": "gender",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper"
            }
        ]
        # extra object, manager must remove it
        protocol_mapper_extra_doc = {
            "config": {
                "access.token.claim": "true",
                "claim.name": "ci-claim-name-EXTRA",
                "id.token.claim": "true",
                "jsonType.label": "String",
                "user.attribute": "ci-user-property-name-EXTRA",
                "userinfo.token.claim": "true"
            },
            "consentRequired": False,
            "name": "ci0-client0-mapper-EXTRA",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper"
        }

        # check initial state
        client_protocol_mappers_api = self.client_protocol_mappers_api
        self.assertEqual([], client_protocol_mappers_api.all())

        manager = ClientProtocolMapperManager(
            self.testbed.kc,
            self.testbed.REALM,
            self.testbed.DATADIR,
            requested_doc=protocol_mappers_doc,
            client_id=self.client["id"],
        )

        # publish data - 1st time
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        protocol_mappers_a = client_protocol_mappers_api.all()
        protocol_mappers_a = sorted(protocol_mappers_a, key=lambda obj: obj["name"])
        protocol_mapper_0_id = find_in_list(protocol_mappers_a, name=protocol_mappers_doc[0]["name"])["id"]
        _check_state()
        # publish data - 2nd time, idempotence
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something - remove one mapper
        self.assertEqual(2, len(client_protocol_mappers_api.all()))
        client_protocol_mappers_api.remove(protocol_mapper_0_id).isOk()
        self.assertEqual(1, len(client_protocol_mappers_api.all()))
        #
        # .publish must revert change
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        #
        # protocol_mapper_0_id is now different, change protocol_mappers_a
        protocol_mapper_0_id_new = find_in_list(client_protocol_mappers_api.all(), name=protocol_mappers_doc[0]["name"])["id"]
        protocol_mapper_0 = find_in_list(protocol_mappers_a, name=protocol_mappers_doc[0]["name"])
        protocol_mapper_0["id"] = protocol_mapper_0_id_new
        #
        _check_state()
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()

        # modify something - add one extra mapper
        self.assertEqual(2, len(client_protocol_mappers_api.all()))
        client_protocol_mappers_api.create(protocol_mapper_extra_doc).isOk()
        self.assertEqual(3, len(client_protocol_mappers_api.all()))
        #
        # .publish must revert change
        creation_state = manager.publish()
        self.assertTrue(creation_state)
        _check_state()
        creation_state = manager.publish()
        self.assertFalse(creation_state)
        _check_state()
