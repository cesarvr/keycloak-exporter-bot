import json
import logging
from copy import copy

import kcapi

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list
from kcloader.tools import read_from_json, remove_unnecessary_fields
from kcloader.resource import Resource

logger = logging.getLogger(__name__)


class UserFederationResource(SingleResource):
    def publish(self):
        # revert realm parentName back to parentId
        master_realm_api = self.keycloak_api.admin()
        realms = master_realm_api.all()

        body = copy(self.body)
        realm_name = body.pop("parentName")
        realm = find_in_list(realms, realm=realm_name)
        body["parentId"] = realm["id"]

        return self.resource.publish(body)
