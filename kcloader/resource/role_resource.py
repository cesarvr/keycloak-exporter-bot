import logging
from abc import ABC

import kcapi

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list, read_from_json

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


class BaseRoleManager(ABC):
    _resource_name = "roles"
    _resource_id = "name"
    _resource_delete_id = "id"
    _resource_id_blacklist = [
    ]

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str):
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.datadir = datadir

        self.resource_api = self._get_resource_api()
        object_filepaths = self._object_filepaths()
        self.resources = [
            self._get_resource_instance({
                'path': object_filepath,
                'keycloak_api': keycloak_api,
                'realm': realm,
                'datadir': datadir,
            })
            for object_filepath in object_filepaths
        ]

    def _get_resource_api(self):
        raise NotImplementedError()

    def _get_resource_instance(self, params):
        raise NotImplementedError()

    def _object_filepaths(self):
        raise NotImplementedError()

    def publish(self, *, include_composite=True):
        create_ids, delete_objs = self._difference_ids()
        # TODO publish simple roles first, then composites;
        # group per client, or per all-clients; group also per realm-roles?
        status_resources = [resource.publish(include_composite=include_composite) for resource in self.resources]
        status_deleted = False
        for delete_obj in delete_objs:
            delete_id = delete_obj[self._resource_delete_id]
            self.resource_api.remove(delete_id).isOk()
            status_deleted = True
        return any(status_resources + [status_deleted])

    def _difference_ids(self):
        """
        If object is present on server but missing in datadir, then it needs to be removed.
        This function will return list of ids (alias-es, clientId-s, etc.) that needs to be removed.
        """
        # idp_filepaths = glob(os.path.join(self.datadir, f"{self.realm}/identity-provider/*/*.json"))
        object_filepaths = self._object_filepaths()

        file_docs = [read_from_json(object_filepath) for object_filepath in object_filepaths]
        file_ids = [doc[self._resource_id] for doc in file_docs]
        server_objs = self.resource_api.all()
        server_ids = [obj[self._resource_id] for obj in server_objs]

        # do not try to create/remove/modify blacklisted objects
        server_ids = [sid for sid in server_ids if sid not in self._resource_id_blacklist]

        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = list(set(file_ids).difference(server_ids))
        delete_objs = [obj for obj in server_objs if obj[self._resource_id] in delete_ids]
        return create_ids, delete_objs
