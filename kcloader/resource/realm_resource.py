import logging
import kcapi
from copy import copy

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list

logger = logging.getLogger(__name__)


class RealmResource(SingleResource):
    def __init__(self, resource):
        super().__init__({'name': 'realm', 'id': 'realm', **resource})

    def publish(self, minimal_representation=False):
        """
        :param minimal_representation: publish realm, but roles and auth flows configured in .json file
        will not be configured in keycloak if they are not already present.
        :return:
        """
        body = copy(self.body)
        if minimal_representation:
            # TODO be smart, figure out if really need to drop roles and outh flows.
            # This is a must - we need to avoid temporal inconsistent states.
            # But for today, be stupid.
            unsafe_attrs = [
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
            for unsafe_attr in unsafe_attrs:
                body.pop(unsafe_attr)
        super().publish(body)
