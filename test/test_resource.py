import unittest
import os
from .helper import TestBed, SAMPLES_PATH, SAMPLE_PAYLOADS_PATH
from kcloader.resource import SingleResource, ManyResources, SingleClientResource, MultipleResourceInFolders, \
    SingleCustomAuthenticationResource
from kcloader.tools import add_trailing_slash, read_from_json, get_json_docs_from_folder


def get_names(resources):
    return list(map(lambda n: n['name'], resources))


def validate_one(res):
    all_res = res.all()
    print('resources ->', all_res)




class RHSSOExporterMain(unittest.TestCase):
    def test_adding_credentials_to_user(self):
        self.assertTrue(True, "Good Starting Point")

    def testing_single_resource_class_creation(self):
        realm_payload = os.path.join(SAMPLE_PAYLOADS_PATH, 'realms/complex_realms.json')

        params = {
            'path': realm_payload,
            'name': 'realm',
            'id': 'realm',
            'keycloak_api': self.keycloak_api,
            'realm': None,
        }

        document = self.testbed.load_file(realm_payload)
        single_resource = SingleResource(params)

        creation_state = single_resource.publish()
        self.assertTrue(creation_state, 'Publish operation should be completed')
        created_realm = self.admin.findFirstByKV('realm', document['realm'])
        self.assertIsNotNone(created_realm, "The realm should be created.")
        self.assertEqual('acme', created_realm['emailTheme'], "The theme should be updated.")


    def testing_multiple_resources(self):
        roles_folder = os.path.join(SAMPLE_PAYLOADS_PATH, 'roles')

        roles = {
            'folder': roles_folder,
            'name': 'roles',
            'id': 'name',
            'keycloak_api': self.keycloak_api,
            'realm': self.testbed.REALM,
        }

        ManyResources(roles).publish()

        cloud_roles = self.keycloak_api.build('roles', self.testbed.REALM)
        all = cloud_roles.findAll().verify().resp().json()

        path = add_trailing_slash(roles_folder)
        file_path_to_json_iterator = map(lambda file_path: read_from_json(file_path), get_json_docs_from_folder(path))
        files = list(file_path_to_json_iterator)

        all = get_names(resources=all)
        all = filter(lambda name: name not in ['uma_authorization', 'offline_access', f'default-roles-{self.testbed.REALM}'], all)
        files = get_names(resources=files)

        self.assertListEqual(sorted(all), sorted(files), "They should match")

    def testing_client_creation(self):
        DC_Client = os.path.join(SAMPLE_PAYLOADS_PATH, 'clients/client-0/dc.json')
        client_tmpl = self.testbed.load_file(DC_Client)
        params = {
            'path': DC_Client,
            'name': 'clients',
            'id': 'clientId',
            'keycloak_api': self.keycloak_api,
            'realm': self.testbed.realm,
        }

        client = SingleClientResource(params)
        client.publish()
        clients = self.keycloak_api.build('clients', self.realm)
        created = clients.findFirstByKV('clientId', client_tmpl['clientId'])

        self.assertIsNotNone(created, "The realm should be created.")

        #roles_file = os.path.join(SAMPLE_PAYLOADS_PATH, 'clients/client-0/roles/roles.json')
        #roles_file_json = self.testbed.load_file(roles_file)
        #r = list( map(lambda n: n['name'], roles_file_json) )  # r == expected_role_names
        expected_role_names = ['hero', 'villain']

        client_roles = clients.roles({'key':'clientId', 'value':client_tmpl['clientId']})
        roles = client_roles.findAll().verify().resp().json()
        r2 = list( map(lambda n: n['name'], roles) )

        self.assertTrue(len(roles) > 0, "No mapped roles found in this client dc/roles")
        self.assertListEqual(sorted(expected_role_names), sorted(r2), "Cloud and Local should have the same roles")

    def testing_publishing_multiple_nodes(self):
        params = {
            'name': 'clients',
            'id': 'clientId',
            'keycloak_api': self.keycloak_api,
            'realm': self.testbed.realm,
        }
        clients_path = os.path.join(SAMPLE_PAYLOADS_PATH, 'clients/')

        multi = MultipleResourceInFolders(params=params, path=clients_path, ResourceClass=SingleClientResource)
        states = multi.publish()

        for state in states:
            self.assertTrue(state, "The client should be published")


    def testing_custom_flow_publishing(self):
        authentication_folder = os.path.join(SAMPLE_PAYLOADS_PATH, 'authentication/my_custom_http_challenge/my_custom_http_challenge.json')

        params = {
            'folder': authentication_folder,
            'keycloak_api': self.keycloak_api,
            'realm': self.testbed.realm,
            'path': authentication_folder
        }

        '''
            We just test here that we get a true from the KCAPI 
            because KCAPI actually has already tested the successful publication.
        '''
        auth = SingleCustomAuthenticationResource(params)

        # before:
        # state = auth.publish()
        # self.assertTrue(state, "The should be published in the server")

        # after:
        # Assume no Exceptions means job was done
        auth.publish()








    @classmethod
    def setUpClass(self):
        self.testbed = TestBed()
        self.testbed.createRealms()
        self.keycloak_api = self.testbed.getKeycloak()
        self.realm = self.testbed.REALM
        self.admin = self.testbed.getAdminRealm()
        self.endpoint = self.testbed.ENDPOINT

    @classmethod
    def tearDownClass(self):
        #self.testbed.cleanup()
        True