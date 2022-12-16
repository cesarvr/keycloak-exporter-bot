import json
import logging
from copy import copy

import kcapi

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list
from kcloader.tools import read_from_json, remove_unnecessary_fields
from kcloader.resource import Resource

logger = logging.getLogger(__name__)


class IdentityProviderResource(SingleResource):
    pass


class IdentityProviderMapperResource(SingleResource):
    def __init__(self, resource, idp_mapper_doc):
        self.resource = Resource(resource)
        self.resource_path = resource['path']
        ## self.body = read_from_json(self.resource_path)
        ## self.body = remove_unnecessary_fields(self.body)
        self.body = idp_mapper_doc

        self.keycloak_api = resource['keycloak_api']
        self.realm_name = resource['realm']

    """
    identityProviderMappers are stored in realm.json.
    Set them after realm and IdP are created.
    """
    @classmethod
    def create_from_realm_doc(cls, realm_doc, keycloak_api, realm_name):
        if "identityProviderMappers" not in realm_doc:
            return []
        assert isinstance(realm_doc["identityProviderMappers"], list)
        assert isinstance(realm_doc["identityProviderMappers"][0], dict)
        idp_mapper_resources = []
        for idp_mapper in realm_doc["identityProviderMappers"]:
            idp_mapper_params = {
                'path': "",  # could be path to realm_doc
                'name': f'identity-provider/instances/{idp_mapper["identityProviderAlias"]}/mappers',
                #'name': 'identity-provider/instances',
                # 'id': 'alias',
                'id': 'identityProviderAlias',
                'keycloak_api': keycloak_api,
                'realm': realm_name,
            }
            idp_mapper_resource = IdentityProviderMapperResource(idp_mapper_params, idp_mapper)
            idp_mapper_resources.append(idp_mapper_resource)
        return idp_mapper_resources

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
        else:
            body = copy(self.body)
            body.update({"id": idp_mapper["id"]})
            idp_mappers_api.update(idp_mapper["id"], body).isOk()
        return True
