import logging
from abc import ABC
from copy import copy
from sortedcontainers import SortedDict

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


class BaseRoleResource(SingleResource):
    def __init__(self, resource, *, body=None, resource_api=None):
        super().__init__(resource, body=body, resource_api=resource_api)
        self._include_composite = None

    def get_update_payload(self, obj):
        body = copy(self.body)
        body.pop("composites", None)
        return body

    def get_create_payload(self):
        body = copy(self.body)
        # always remove "composites" - it contains containerName (not containerId)
        body.pop("composites", None)
        return body

    def publish(self, *, include_composite=True):
        body = copy(self.body)
        # both or none. If this assert fails, we have invalid/synthetic data.
        assert (body["composite"] and body["composites"]) or \
               ((not body["composite"]) and ("composites" not in body))
        # body.pop("composites", None)  # it will be used as create payload

        # new role - body.composite and .composites are ignored
        # old role - body.composites must be valid
        self._include_composite = include_composite
        creation_state = self.resource.publish_object(self.body, self)
        self._include_composite = None

        # We can setup composites only after role is created
        creation_state_link = False
        if include_composite:
            creation_state_link = self._link_roles()

        return creation_state or creation_state_link

    def _link_roles(self):
        # Get required global knowledge - TODO - move this out, and reuse data, to reduce network traffic
        realm_roles_api = self.keycloak_api.build("roles", self.realm_name)
        realm_roles = realm_roles_api.all()
        clients_api = self.keycloak_api.build("clients", self.realm_name)
        clients = clients_api.all()
        roles_by_id_api = self.keycloak_api.build('roles-by-id', self.realm_name)

        this_role = self._get_this_role_obj(clients, clients_api, realm_roles)
        this_role_composites_api = roles_by_id_api.get_child(roles_by_id_api, this_role["id"], "composites")
        # Full role representation will be sent to API (this_role_composites_api) that expects briefRepresentation.
        # Hopefully this will work.

        # role_obj - object returned by API, role_doc - same data but formatted as if read from json doc
        this_role_composite_objs = this_role_composites_api.all()
        this_role_composite_docs = self._get_composites_docs(this_role_composite_objs, clients)

        creation_state = False
        for sub_role_doc in self.body.get("composites", []):
            if sub_role_doc in this_role_composite_docs:
                # link already created
                # There is nothing that could be updated
                continue
            sub_role = find_sub_role(self, clients, realm_roles, clients_roles=None, sub_role=sub_role_doc)
            if not sub_role:
                logger.error(f"sub_role {sub_role_doc} not found")
                # Either ignore or crash
                # For now, ignore.
                # TODO - code should crash - on second pass, all subroles should be present.
                continue
            this_role_composites_api.create([sub_role]).isOk()
            creation_state = True

        # remove composites that should not be there
        for role_obj, role_doc in zip(this_role_composite_objs, this_role_composite_docs):
            if role_doc not in self.body.get("composites", []):
                # must be removed
                this_role_composites_api.remove(None, [role_obj]).isOk()
                creation_state = True

        return creation_state

    def _get_this_role_obj(self, clients, clients_api):
        raise NotImplementedError()

    def _get_composites_docs(
            self,
            this_role_composite_objs,  # returned by API
            clients,  # returned by API
            # realm_roles,  # returned by API
            # clients_api,
    ):
        """
        For each sub_role/composite role, get dict that would be stored into json doc.
        """
        docs = []
        for composite in this_role_composite_objs:
            if composite["clientRole"]:
                subrole_client_id = composite["containerId"]
                # subrole_client = clients_api.findFirstByKV("id", subrole_client_id)
                subrole_client = find_in_list(clients, id=subrole_client_id)
                doc = dict(
                    name=composite["name"],
                    clientRole=composite["clientRole"],
                    containerName=subrole_client["clientId"],
                )
            else:
                # realm role
                # must be the same realm
                # assert composite["containerId"] == realm["id"]
                # assert realm["realm"] == self.realm_name
                doc = dict(
                    name=composite["name"],
                    clientRole=composite["clientRole"],
                    containerName=self.realm_name,
                )
            docs.append(doc)
        return docs

    def is_equal(self, obj):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(obj)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            oo.pop("containerId", None)
            # composites - ignore them, or convert one to hava containerId or containerName in both
            oo.pop("composites", None)
        """
        If we have complex role, and is published with include_composite=False,
        and it is still a simple role on server, then:
        Composites will not be set anyway, so ignore fact that composite flag is wrong on server.
        """
        if self._include_composite is False and self.body["composite"] is True:
            obj1.pop("composite")
            obj2.pop("composite")
        return obj1 == obj2
