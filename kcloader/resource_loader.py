import logging

import kcapi.rest.auth_flows
from kcapi.ie import AuthenticationFlowsImporter

from kcloader.tools import read_from_json, get_json_docs_from_folder, add_trailing_slash, traverse_and_remove_field, get_path, \
    bfs_folder, lookup_child_resource
import os

from kcloader.resource import ResourcePublisher, SingleResource, UpdatePolicy

logger = logging.getLogger(__name__)











