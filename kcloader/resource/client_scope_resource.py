import json
import logging
import kcapi
from sortedcontainers import SortedDict

from kcloader.resource import SingleResource
from kcloader.tools import find_in_list

logger = logging.getLogger(__name__)


class ClientScopeResource(SingleResource):
    def __init__(
            self,
            resource: dict,
         ):
        super().__init__({
            "name": "client-scopes",
            "id": "name",
            **resource,
        })

    def publish_self(self):
        creation_state = self.resource.publish_object(self.body, self)
        return creation_state

    def publish(self, body=None, *, include_scope_mappings=True):
        creation_state = self.publish_self()
        return creation_state

    def is_equal(self, other):
        obj1 = SortedDict(self.body)
        obj2 = SortedDict(other)
        for oo in [obj1, obj2]:
            oo.pop("id", None)
            # clientScopeMappings and scopeMappings are added by kcfetcher
            oo.pop("clientScopeMappings", None)
            oo.pop("scopeMappings", None)
            if "protocolMappers" in oo:
                for pm in oo["protocolMappers"]:
                    pm.pop("id", None)
        return obj1 == obj2


# not needed
# class ClientScopeScopeMappingsRealmResource(SingleResource):

class ClientScopeScopeMappingsRealmManager:
    def __init__(self, keycloak_api: kcapi.sso.Keycloak, realm: str, datadir: str,
                 *, client_scope_name: str, client_scope_id: str, client_scope_filepath: str):
        self._client_scope_name = client_scope_name
        self._client_scope_id = client_scope_id
        self._client_scope_filepath = client_scope_filepath

        # Manager will directly update the links - less REST calls.
        # A single ClientScopeScopeMappingsRealmCRUD will be enough.
        client_scopes_api = keycloak_api.build("client-scopes", realm)
        self.realm_roles_api = keycloak_api.build("roles", realm)
        self.cssm_realm_resource = client_scopes_api.scope_mappings_realm_api(client_scope_id=client_scope_id)
        with open(client_scope_filepath) as ff:
            client_scope_doc = json.load(ff)
        self.cssm_realm_doc = client_scope_doc.get("scopeMappings", [])

    def publish(self, body=None):
        creation_state = False
        # requested_roles = self.cssm_realm_body.get("roles", [])
        create_ids, delete_objs = self._difference_ids()

        realm_roles = self.realm_roles_api.all(
            params=dict(briefRepresentation=True)
        )
        create_roles = [rr for rr in realm_roles if rr["name"] in create_ids]
        status_created = False
        if create_roles:
            self.cssm_realm_resource.create(create_roles).isOk()
            status_created = True

        status_deleted = False
        if delete_objs:
            self.cssm_realm_resource.remove(None, delete_objs).isOk()
            status_deleted = True

        return any([status_created, status_deleted])

    def _difference_ids(self):
        file_ids = self.cssm_realm_doc.get("roles", [])

        # file_ids is list of realm role names
        server_objs = self.cssm_realm_resource.all()
        server_ids = [obj["name"] for obj in server_objs]

        # remove objects that are on server, but missing in datadir
        delete_ids = list(set(server_ids).difference(file_ids))
        # create objects that are in datdir, but missing on server
        create_ids = list(set(file_ids).difference(server_ids))
        delete_objs = [obj for obj in server_objs if obj["name"] in delete_ids]
        return create_ids, delete_objs

class ClientScopeResource___old(SingleResource):
    def publish_scope_mappings(self):
        state = self.publish_scope_mappings_realm()
        state = state and self.publish_scope_mappings_client()

    def publish_scope_mappings_client(self):
        clients_api = self.keycloak_api.build('clients', self.realm_name)
        clients = clients_api.all()

        client_scopes_api = self.keycloak_api.build('client-scopes', self.realm_name)
        this_client_scope = client_scopes_api.findFirstByKV("name", self.body["name"])  # .verify().resp().json()

        for clientId in self.body["clientScopeMappings"]:
            client = find_in_list(clients, clientId=clientId)
            client_roles_api = clients_api.get_child(clients_api, client["id"], "roles")
            client_roles = client_roles_api.all()
            this_client_scope_scope_mappings_client_api = client_scopes_api.get_child(
                client_scopes_api,
                this_client_scope["id"],
                f"scope-mappings/clients/{client['id']}"
            )
            for role_name in self.body["clientScopeMappings"][clientId]:
                role = find_in_list(client_roles, name=role_name)
                if not role:
                    logger.error(f"scopeMappings clientId={clientId} client role {role_name} not found")
                this_client_scope_scope_mappings_client_api.create([role])
        return True

    def publish_scope_mappings_realm(self):
        if "scopeMappings" not in self.body:
            return True

        client_scopes_api = self.keycloak_api.build('client-scopes', self.realm_name)
        this_client_scope = client_scopes_api.findFirstByKV("name", self.body["name"])  # .verify().resp().json()
        this_client_scope_scope_mappings_realm_api = client_scopes_api.get_child(client_scopes_api, this_client_scope["id"], "scope-mappings/realm")

        realm_roles_api = self.keycloak_api.build('roles', self.realm_name)
        realm_roles = realm_roles_api.all()

        for role_name in self.body["scopeMappings"]["roles"]:
            role = find_in_list(realm_roles, name=role_name)
            if not role:
                logger.error(f"scopeMappings realm role {role_name} not found")
            this_client_scope_scope_mappings_realm_api.create([role])
        return True
