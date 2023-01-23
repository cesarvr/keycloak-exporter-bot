import logging
import kcapi
from copy import copy, deepcopy

from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list

logger = logging.getLogger(__name__)


class RealmResource(SingleResource):
    _unsafe_attrs = [
        "defaultRoles",
        # "identityProviderMappers",
        # every configured flow might not be present yet
        "browserFlow",
        "clientAuthenticationFlow",
        "directGrantFlow",
        "dockerAuthenticationFlow",
        "registrationFlow",
        "resetCredentialsFlow",
    ]

    def __init__(self, resource):
        super().__init__({'name': 'realm', 'id': 'realm', **resource})
        self._minimal_representation = None

    def publish(self, minimal_representation=False):
        """
        :param minimal_representation: publish realm, but roles and auth flows configured in .json file
        will not be configured in keycloak if they are not already present.
        :return:
        """
        # self._minimal_representation should be contex manager (with A() as a: ...)
        self._minimal_representation = minimal_representation
        # return super().publish(body)
        state = self.resource.publish_object(self.body, self)
        self._minimal_representation = None
        return state

    def is_equal(self, obj):
        """
        :param obj: dict returned by API
        :return: True if content in self.body is same as in obj
        """
        # self.body is already sorted
        obj1 = deepcopy(self.body)
        obj2 = deepcopy(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            if self._minimal_representation is True:
                for unsafe_attr in self._unsafe_attrs:
                    oo.pop(unsafe_attr, None)
            # also sort enabledEventTypes, etc
            for list_name in ["enabledEventTypes", "defaultRoles", "eventsListeners"]:
                if list_name in oo:
                    oo[list_name] = sorted(oo[list_name])
        obj1 = SortedDict(obj1)
        obj2 = SortedDict(obj2)
        return obj1 == obj2

    def get_update_payload(self, obj):
        # With minimal_representation=True, we do not want to change
        # any of _unsafe_attrs, but some are still mandatory in payload.
        # Set them to what is currently on server.
        body = copy(self.body)
        if self._minimal_representation is True:
            for unsafe_attr in self._unsafe_attrs:
                body.pop(unsafe_attr, None)  # TODO TEMP - assumes minimal_representation=True !!!!!!
                if unsafe_attr in obj:
                    body[unsafe_attr] = obj[unsafe_attr]
        return body

    def get_create_payload(self):
        body = copy(self.body)
        if self._minimal_representation:
            # TODO be smart, figure out if really need to drop roles and outh flows.
            # This is a must - we need to avoid temporal inconsistent states.
            # But for today, be stupid.
            for unsafe_attr in self._unsafe_attrs:
                body.pop(unsafe_attr, None)
        return body
