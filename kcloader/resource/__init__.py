from .resource_publisher import ResourcePublisher, UpdatePolicy
from .resource import Resource

from .single_resource import SingleResource
from .client_resource import SingleClientResource, ClientManager, ClientRoleManager, ClientRoleResource
from .custom_authentication_resource import SingleCustomAuthenticationResource
# from .role_resource import RoleResource
from .realm_role_resource import RealmRoleManager, RealmRoleResource
from .client_scope_resource import ClientScopeResource
from .identity_provider_resource import IdentityProviderResource, IdentityProviderMapperResource
from .identity_provider_resource import IdentityProviderManager, IdentityProviderMapperManager
from .user_federation_resource import UserFederationResource
from .realm_resource import RealmResource

from .many_resources import ManyResources, MultipleResourceInFolders


__all__ = [
    ResourcePublisher,
    Resource,
    UpdatePolicy,

    SingleResource,
    RealmResource,
    SingleClientResource,
    SingleCustomAuthenticationResource,
    IdentityProviderResource,
    IdentityProviderMapperResource,
    UserFederationResource,

    ManyResources,
    MultipleResourceInFolders,
]
