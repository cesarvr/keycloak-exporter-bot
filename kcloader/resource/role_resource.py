import logging
import kcapi

from kcloader.resource import SingleResource

logger = logging.getLogger(__name__)


class RoleResource(SingleResource):
    def __init__(self, resource):
        super().__init__({'name': 'role', 'id':'name', **resource})
        if "composites" in self.body:
            logger.error(f"Composite roles are not implemented yet, role={self.body['name']}")
            self.body.pop("composites")
