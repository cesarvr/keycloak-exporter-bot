import logging
import kcapi

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list

logger = logging.getLogger(__name__)


# This can be used to find role assigned to client scope-mappings,
# or a role assigned to be sub-role (of composite role).
def find_sub_role(self, clients, realm_roles, clients_roles, sub_role):
    clients_api = self.keycloak_api.build("clients", self.realm_name)
    if sub_role["clientRole"]:
        # client role
        some_client = find_in_list(clients, clientId=sub_role["containerName"])
        if not some_client:
            # https://github.com/justinc1/keycloak-exporter-bot/actions/runs/3699240874/jobs/6266392682
            # I'm not able to reproduce locally.
            logger.error(f"client clientId={sub_role['containerName']} not found")
            return None
        # TODO move also this out, to cache/reuse API responses
        # But how often is data for _all_ clients needed? Lazy loading would be nice.
        some_client_roles_api = clients_api.get_child(clients_api, some_client["id"], "roles")
        some_client_roles = some_client_roles_api.all()  # TODO cache this response
        role = find_in_list(some_client_roles, name=sub_role["name"])
        # TODO create those roles first
    else:
        # realm role
        assert self.realm_name == sub_role["containerName"]
        role = find_in_list(realm_roles, name=sub_role["name"])
    return role
