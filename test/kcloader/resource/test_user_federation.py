import os

from kcloader.resource.user_federation_resource import UserFederationResource
from ...helper import TestCaseBase


class TestUserFederationResource(TestCaseBase):
    def get_test_resource_a(self):
        resource_filepath = os.path.join(self.testbed.DATADIR, f"{self.testbed.REALM}/user-federations/ci0-uf0-ldap/ci0-uf0-ldap.json")
        return self.get_test_resource(resource_filepath)

    def get_test_resource_b(self):
        resource_filepath = os.path.join(self.testbed.DATADIR, f"{self.testbed.REALM}/user-federations/ci0-uf1-ldap/ci0-uf1-ldap.json")
        return self.get_test_resource(resource_filepath)

    def get_test_resource(self, resource_filepath):
        resource = UserFederationResource({
            'path': resource_filepath,
            'keycloak_api': self.testbed.kc,
            'realm': self.testbed.REALM,
            'datadir': self.testbed.DATADIR,
        })
        return resource

    def test_publish_empty(self):
        realm_obj = self.testbed.kc.admin().get_one(self.testbed.REALM)
        
        resource = self.get_test_resource_a()
        creation_state = resource.publish(realm_obj)
        self.assertTrue(creation_state)

    def test_publish_idenpotent(self):
        realm_obj = self.testbed.kc.admin().get_one(self.testbed.REALM)
        
        resource = self.get_test_resource_a()
        creation_state = resource.publish(realm_obj)
        self.assertTrue(creation_state)

        resource_update = self.get_test_resource_a()
        update_state = resource_update.publish(realm_obj)
        self.assertFalse(update_state)

    def test_publish_update(self):
        realm_obj = self.testbed.kc.admin().get_one(self.testbed.REALM)
        
        resource = self.get_test_resource_a()
        creation_state = resource.publish(realm_obj)
        self.assertTrue(creation_state)

        resource_update = self.get_test_resource_a()
        resource_update.body["config"]["enabled"] = ["false"]
        update_state = resource_update.publish(realm_obj)
        self.assertTrue(update_state)

    def test_publish_different_obj(self):
        realm_obj = self.testbed.kc.admin().get_one(self.testbed.REALM)
        
        resource = self.get_test_resource_a()
        creation_state = resource.publish(realm_obj)
        self.assertTrue(creation_state)

        resource_b = self.get_test_resource_b()
        update_state = resource_b.publish(realm_obj)
        self.assertTrue(update_state)
