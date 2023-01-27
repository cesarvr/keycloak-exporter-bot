import logging
import os
from abc import ABC
from glob import glob

import kcapi

logger = logging.getLogger(__name__)


class BaseManager(ABC):
    # part of URL path - clients, roles, client-scopes, ...
    _resource_name = ""
    # name or clientId or ...
    _resource_id = ""
    # id or name or ...
    _resource_delete_id = ""
    # resource_ids that manager should ignore.
    # For example default clients, they are not stored to disk by kcfetcher,
    # so kcimport should not create/update/delete them.
    _resource_id_blacklist = []

    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str):
        self.keycloak_api = keycloak_api
        self.realm = realm
        self.datadir = datadir
        self.resource_api = self._get_resource_api()

        self.resources = []
        # object_filepaths = self._object_filepaths()
        # self.resources = [
        #     SingleClientResource({
        #         'path': object_filepath,
        #         'keycloak_api': keycloak_api,
        #         'realm': realm,
        #         'datadir': datadir,
        #     })
        #     for object_filepath in object_filepaths
        # ]

    def _get_resource_api(self):
        # Works for simple URLs - GET /{realm}/clients
        # Not enough for URLs with id - GET /{realm}/clients/{id}/protocol-mappers/models
        assert self._resource_name != ''
        resource_api = self.keycloak_api.build(self._resource_name, self.realm)
        return resource_api

    def publish(self, **publish_kwargs):
        create_ids, delete_objs = self._difference_ids()
        status_resources = [resource.publish(**publish_kwargs) for resource in self.resources]
        status_deleted = [self.remove_server_object(delete_obj) for delete_obj in delete_objs]
        return any(status_resources + status_deleted)

    def remove_server_object(self, delete_obj: dict):
        delete_id = delete_obj[self._resource_delete_id]
        self.resource_api.remove(delete_id).isOk()
        return True

    # def _object_filepaths(self):
    #     object_filepaths = glob(os.path.join(self.datadir, f"{normalize(self.realm)}/clients/*/*.json"))
    #     # remove scope-mappings.json
    #     object_filepaths = [fp for fp in object_filepaths if not fp.endswith("/scope-mappings.json")]
    #     return object_filepaths

    def _object_docs(self):
        raise NotImplementedError()
        # object_filepaths = glob(os.path.join(self.datadir, f"{normalize(self.realm)}/clients/*/*.json"))
        # # remove scope-mappings.json
        # object_filepaths = [fp for fp in object_filepaths if not fp.endswith("/scope-mappings.json")]
        # file_docs = [read_from_json(object_filepath) for object_filepath in object_filepaths]
        # return file_docs

    def _object_docs_ids(self):
        file_docs = self._object_docs()
        file_ids = [doc[self._resource_id] for doc in file_docs]
        return file_ids

    def _get_server_objects(self):
        server_objs = self.resource_api.all()
        return server_objs

    def _difference_ids(self):
        """
        If object is present on server but missing in datadir, then it needs to be removed.
        This function will return list of ids (alias-es, clientId-s, etc.) that needs to be removed.
        """
        file_ids = self._object_docs_ids()
        server_objs = self._get_server_objects()
        server_ids = [obj[self._resource_id] for obj in server_objs]

        # do not try to create/remove/modify blacklisted objects
        server_ids = [sid for sid in server_ids if sid not in self._resource_id_blacklist]

        # auth execution manager - It can have nonunique displayName.
        # Try to be ignorant...
        if len(server_ids) != len(set(server_ids)):
            extra_msg = ""
            if type(self).__name__ == "AuthenticationFlowExecutionsManager":
                extra_msg = f"self.flow_alias={self.flow_alias}"
            logger.exception(f"ID values should are not unique - {extra_msg} len(file_ids)={len(file_ids)}, len(set(server_ids))={len(set(server_ids))}, file_ids={file_ids}, server_ids={server_ids}, ")
        assert len(file_ids) == len(set(file_ids))
        assert len(server_ids) == len(set(server_ids))
        # TODO - combo displayName+alias should be used.
        # Or, each subflow would need its own manager.
        # Or both.

        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = list(set(file_ids).difference(server_ids))
        delete_objs = [obj for obj in server_objs if obj[self._resource_id] in delete_ids]
        return create_ids, delete_objs
