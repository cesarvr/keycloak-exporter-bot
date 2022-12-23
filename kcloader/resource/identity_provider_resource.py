import json
import logging
import os
from copy import copy
from glob import glob

import kcapi

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list
from kcloader.tools import read_from_json, remove_unnecessary_fields
from kcloader.resource import Resource

logger = logging.getLogger(__name__)


class IdentityProviderResource(SingleResource):
    _resource_name = 'identity-provider/instances'
    _resource_id = 'alias'

    def __init__(self, resource):
        super().__init__({
            'name': self._resource_name,
            'id': self._resource_id,
            **resource,
        })
        self.datadir = resource['datadir']

        idp_alias = self.body["alias"]
        self.idp_mapper_manager = IdentityProviderMapperManager(self.keycloak_api, self.realm_name, self.datadir, idp_alias=idp_alias)

    def publish_self(self):
        return super().publish()

    def publish(self):
        status_self = self.publish_self()
        status_mappers = self.idp_mapper_manager.publish()
        return any([status_self, status_mappers])


class IdentityProviderManager:
    _resource_name = IdentityProviderResource._resource_name
    _resource_id = IdentityProviderResource._resource_id

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str):
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.datadir = datadir
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)

        idp_filepaths = glob(os.path.join(datadir, f"{realm}/identity-provider/*/*.json"))
        self.resources = [
            IdentityProviderResource({
                'path': idp_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for idp_filepath in idp_filepaths
        ]

    def publish(self):
        create_ids, delete_ids = self._difference_ids()
        status_resources = [resource.publish() for resource in self.resources]
        status_deleted = False
        for obj_id in delete_ids:
            self.resource_api.remove(obj_id)
            status_deleted = True
        return any(status_resources + [status_deleted])

    def _difference_ids(self):
        """
        If IdP is present on server but missing in datadir, then it needs to ber removed.
        This function will return list of ids (aliases) that needs to be removed.
        """
        idp_filepaths = glob(os.path.join(self.datadir, f"{self.realm}/identity-provider/*/*.json"))
        file_docs = [read_from_json(idp_filepath) for idp_filepath in idp_filepaths]
        file_ids = [doc[self._resource_id] for doc in file_docs]
        server_objs = self.resource_api.all()
        server_ids = [obj[self._resource_id] for obj in server_objs]
        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = list(set(file_ids).difference(server_ids))
        return create_ids, delete_ids


# For each IdentityProviderResource we need one IdentityProviderMapperManager.
class IdentityProviderMapperManager:
    _resource_name_template = "identity-provider/instances/{idp_alias}/mappers"
    _resource_id = "name"

    @property
    def _resource_name(self):
        return self._resource_name_template.format(idp_alias=self._idp_alias)

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *, idp_alias: str):
        self._idp_alias = idp_alias
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.datadir = datadir
        self.resource_api = self.keycloak_api.build(self._resource_name, self.realm)

        idp_mappers_filepaths = glob(os.path.join(datadir, f"{realm}/identity-provider/{idp_alias}/mappers/*.json"))
        self.resources = [
            IdentityProviderMapperResource({
                'path': idp_mappers_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for idp_mappers_filepath in idp_mappers_filepaths
        ]

    def publish(self):
        create_ids, delete_ids, delete_ids_for_api = self._difference_ids()
        status_resources = [resource.publish() for resource in self.resources]
        status_deleted = False
        for obj_id in delete_ids_for_api:
            self.resource_api.remove(obj_id)
            status_deleted = True
        return any(status_resources + [status_deleted])

    def _difference_ids(self):
        """
        If IdP is present on server but missing in datadir, then it needs to ber removed.
        This function will return list of ids (aliases) that needs to be removed.
        """
        idp_filepaths = glob(os.path.join(self.datadir, f"{self.realm}/identity-provider/{self._idp_alias}/mappers/*.json"))
        file_docs = [read_from_json(idp_filepath) for idp_filepath in idp_filepaths]
        file_ids = [doc[self._resource_id] for doc in file_docs]
        server_objs = self.resource_api.all()
        server_ids = [obj[self._resource_id] for obj in server_objs]
        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = list(set(file_ids).difference(server_ids))

        # IdP - is identified by alias, is removed by alias
        # IdP_mapper - is identified by name, is removed by id
        # Find those id.
        delete_ids_for_api = [obj["id"] for obj in server_objs if obj[self._resource_id] in delete_ids]

        return create_ids, delete_ids, delete_ids_for_api


class IdentityProviderMapperResource(SingleResource):
    def __init__(self, resource):
        mapper_doc = read_from_json(resource["path"])
        idp_alias = mapper_doc["identityProviderAlias"]
        super().__init__({
            "name": f"identity-provider/instances/{idp_alias}/mappers",  # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/identity-provider/instances/ci0-idp-saml-0/mappers
            "id": "name",
            **resource,
        })

    def publish(self):
        # super().publish()
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/identity-provider/instances/ci0-idp-saml-0/mappers
        idp_mappers_api = self.resource.resource_api
        idp_mappers = idp_mappers_api.all()
        idp_mapper = find_in_list(idp_mappers, name=self.body["name"])

        """
        mapper with "identityProviderMapper": "saml-advanced-role-idp-mapper"
        can be .create/.update-ed, but this is not enough,
        type is sort-of-ignored.
        Do we need to create SAML user fedaration first, or something?

        Update:
        Seems saml-advanced-role-idp-mapper is something from RH SSO 7.5.
        """
        # logger.error("IdP provider mapper - not yet fully functional")

        if not idp_mapper:
            idp_mappers_api.create(self.body).isOk()
            # was created
            return True
        body = copy(self.body)
        body.update({"id": idp_mapper["id"]})
        if body == idp_mapper:
            # no change
            return False
        idp_mappers_api.update(idp_mapper["id"], body).isOk()
        return True
