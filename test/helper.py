import json

from kcapi import OpenID, Keycloak
from kcloader.tools import read_from_json
import os

# We run unittest from top level directory
SAMPLES_PATH = "test/samples"
SAMPLE_PAYLOADS_PATH = "test/sample_payloads"


class TestBed:
    def __init__(self, realm = None, username = None, password = None, endpoint = None): 

        self.USER = os.getenv('KC_USER')
        self.PASSWORD = os.environ.get('KC_PASSWORD')
        self.REALM = realm or os.environ.get('KC_REALM')
        self.ENDPOINT = os.environ.get('KC_ENDPOINT')
        self.DATADIR = 'test/data/kcfetcher-latest' or os.environ.get('KC_DATADIR')

        self.groupName = 'DC'
        self.roleNames = ['level-1', 'level-2', 'level-3'] 
        
        token = OpenID.createAdminClient(self.USER, self.PASSWORD, url=self.ENDPOINT).getToken()
        self.kc = Keycloak(token, self.ENDPOINT)
        self.master_realm = self.kc.admin()
        self.realm = self.REALM 
        self.token = token

    def deleteRealms(self):
        realm = self.realm
        if self.master_realm.existByKV("id", realm):
            self.master_realm.removeFirstByKV("id", realm)

    def createRealms(self):
        realm = self.realm
        self.master_realm.create({"enabled": "true", "id": realm, "realm": realm})

    def createGroups(self):
        group = self.kc.build('groups', self.realm)
        g_creation_state = group.create({"name": self.groupName}).isOk()
        self.createRoles()


    def createRoles(self):
        roles = self.kc.build('roles', self.realm)
        for role in self.roleNames:
            roles.create({"name": role}).isOk() 


    def createClients(self):
        realm = self.realm
        client = {"enabled":True,
                  "attributes":{},
                  "redirectUris":[],
                  "clientId":"dc",
                  "protocol":"openid-connect", 
                  "directAccessGrantsEnabled":True
                  }

        clients = self.kc.build('clients', realm)
        if not clients.create(client).isOk(): 
            raise Exception('Cannot create Client')

    def createUsers(self):
        realm = self.realm
        test_users = [
                {"enabled":'true',"attributes":{},"username":"batman","firstName":"Bruce", "lastName":"Wayne", "emailVerified":""}, 
                {"enabled":'true',"attributes":{},"username":"superman","firstName":"Clark", "lastName":"Kent", "emailVerified":""}, 
                {"enabled":'true',"attributes":{},"username":"aquaman","firstName":"AAA%", "lastName":"Corrupt", "emailVerified":""}
        ]

        users = self.kc.build('users', realm)
        
        for usr in test_users: 
            users.create(usr).isOk()

    def cleanup(self):
        state = self.master_realm.remove(self.realm).ok()
        if not state:
            raise Exception("Cannot delete the realm -> " + self.realm )

    def getKeycloak(self):
        return self.kc

    def getAdminRealm(self):
        return self.master_realm

    def load_file(self, fname):
        f = open(fname)
        data = json.loads(f.read())
        f.close()

        return data


def remove_field_id(obj):
    assert isinstance(obj, dict)
    obj.pop("id", None)
    return obj
