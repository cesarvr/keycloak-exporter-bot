from copy import copy
from glob import glob

import logging
import os
import kcapi
from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list
from kcloader.tools import read_from_json
from kcfetcher.utils import normalize

logger = logging.getLogger(__name__)


class UserFederationResource(SingleResource):
    _resource_name = 'components'
    _resource_id = 'name'
    _resource_delete_id = 'id'

    def __init__(self, resource):
        super().__init__({
            'name': self._resource_name,
            'id': self._resource_id,
            **resource,
        })
        self.datadir = resource['datadir']

    def _get_query_params(self, parent):
        params = {
            "parent": parent["id"],
            "type": "org.keycloak.storage.UserStorageProvider"
        }
        return params

    def find_created_object(self, parent: dict, body: dict):
        # This part can be optimized if we first create/update all federations in first pass, and then
        # update mapping is second pass
        #
        # In that case we would be able to get ID/s for all object on one REST call, and then just
        # do mathing in memory. Now we get whole list for each element. Optimization is not there
        # because this would make code less readable.
        params = self._get_query_params(parent)
        listed = self.keycloak_api.build(self._resource_name, self.realm_name).all(params)
        match = next((x for x in listed if x[self._resource_id]==body[self._resource_id]), None)
        return match

    def publish_self(self):
        return super().publish()

    def publish(self, parent: dict):
        self.body.pop("parentName", None)  # might be already deleted
        self.body["parentId"] = parent["id"]

        self_state = self.resource.publish_object(self.body, self)
        match = self.find_created_object(parent, self.body)
        mapper_manager = UserFederationMapperManager(self.keycloak_api, self.realm_name, self.datadir, parent=match)

        status_mappers = mapper_manager.publish()
        return any([self_state, status_mappers])

    def is_equal(self, obj):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
        return obj1 == obj2


class UserFederationManager:
    _resource_name = UserFederationResource._resource_name
    _resource_id = UserFederationResource._resource_id
    _resource_delete_id = UserFederationResource._resource_delete_id

    @classmethod
    def _get_path(cls, datadir: str, realm: str):
        return glob(os.path.join(datadir, f"{normalize(realm)}/user-federations/*/*.json"))


    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str):
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.datadir = datadir

        self.parent = self.keycloak_api.admin().get_one(self.realm)
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)

        idp_filepaths = self._get_path(datadir, realm)
        self.resources = [
            UserFederationResource({
                'path': idp_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for idp_filepath in idp_filepaths
        ]

    def publish(self):
        create_ids, delete_objs = self._difference_ids()
        status_resources = [resource.publish(self.parent) for resource in self.resources]
        status_deleted = False
        for obj in delete_objs:
            self.resource_api.remove(obj[self._resource_delete_id]).isOk()
            status_deleted = True
        return any(status_resources + [status_deleted])

    def _get_query_params(self):
        params = {
            "parent": self.parent["id"],
            "type": "org.keycloak.storage.UserStorageProvider"
        }
        return params


    def _difference_ids(self):
        """
        If item is present on server but missing in datadir, then it needs to be removed.
        This function will return list of items that needs to be removed.
        """
        filepaths = self._get_path(self.datadir, self.realm)
        file_docs = [read_from_json(filepath) for filepath in filepaths]
        file_ids = [doc[self._resource_id] for doc in file_docs]
        
        params = self._get_query_params()
        server_objs = self.resource_api.all(params)
        
        server_ids = [obj[self._resource_id] for obj in server_objs]
        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = list(set(file_ids).difference(server_ids))
        delete_objs = [obj for obj in server_objs if obj[self._resource_id] in delete_ids]
        return create_ids, delete_objs


class UserFederationProviderMapperResource(SingleResource):
    _resource_name = 'components'
    _resource_id = 'name'
    _resource_delete_id = 'id'

    def __init__(self, resource):
        super().__init__({
            "name": "components",
            "id": "name",
            **resource,
        })

    def _get_query_params(self, parent):
            params = {
                "parent": parent["id"],
                "type": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
            }
            return params

    def publish(self, parent):
        providerType = self.body["providerType"]
        if providerType != "org.keycloak.storage.ldap.mappers.LDAPStorageMapper":
            raise Exception(f"Unknown user federation mapping type: {providerType}!")
        mappers_api = self.resource.resource_api

        params = self._get_query_params(parent)
        mappers = mappers_api.all(params)
        mapper_item = find_in_list(mappers, name=self.body[self._resource_id])

        body = copy(self.body)
        body["parentId"] = parent["id"]
        
        if not mapper_item:
            mappers_api.create(body).isOk()
            # was created
            return True
        body.update({"id": mapper_item["id"]})
        if body == mapper_item:
            # no change
            return False
        mappers_api.update(mapper_item["id"], body).isOk()
        return True


class UserFederationMapperManager:
    _resource_name = UserFederationProviderMapperResource._resource_name
    _resource_id = UserFederationProviderMapperResource._resource_id
    _resource_delete_id = UserFederationProviderMapperResource._resource_delete_id

    @classmethod
    def _get_path(cls, datadir: str, realm: str, identifier: str):
        normalized_realm = normalize(realm)
        normalized_identifier = normalize(identifier)
        return glob(os.path.join(datadir, f"{normalized_realm}/user-federations/{normalized_identifier}/mappers/*.json"))

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *, parent: dict):
        self.parent = parent
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.datadir = datadir
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)

        mappers_filepaths = self._get_path(datadir, realm, parent[self._resource_id])  #
        self.resources = [
            UserFederationProviderMapperResource({
                'path': mappers_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for mappers_filepath in mappers_filepaths
        ]

    def publish(self):
        create_ids, delete_objs = self._difference_ids()
        status_resources = [resource.publish(self.parent) for resource in self.resources]
        status_deleted = False
        for obj in delete_objs:
            self.resource_api.remove(obj[self._resource_delete_id])
            status_deleted = True
        return any(status_resources + [status_deleted])

    def _get_query_params(self):
            params = {
                "parent": self.parent["id"],
                "type": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
            }
            return params

    def _difference_ids(self):
        """
        If item is present on server but missing in datadir, then it needs to be removed.
        This function will return list of items that needs to be removed.
        """
        filepaths = self._get_path(self.datadir, self.realm, self.parent[self._resource_id])
        file_docs = [read_from_json(filepath) for filepath in filepaths]
        file_ids = [doc[self._resource_id] for doc in file_docs]

        params = self._get_query_params()
        server_objs = self.resource_api.all(params)

        server_ids = [obj[self._resource_id] for obj in server_objs]
        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = list(set(file_ids).difference(server_ids))
        delete_objs = [obj for obj in server_objs if obj[self._resource_id] in delete_ids]
        return create_ids, delete_objs
