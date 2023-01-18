import logging
import json
import os
import unittest
from glob import glob
from copy import copy
from collections import namedtuple

from kcloader.tools import read_from_json, find_in_list
from ..helper import TestBed, remove_field_id, TestCaseBase
from main import main

logger = logging.getLogger(__name__)

MainArgs = namedtuple("MainArgs", ["username", "password", "url", "datadir", "realm_name"])


class TestCaseMain(TestCaseBase):
    def setUp(self):
        super().setUp()
        self.main_args = MainArgs(
            username=self.testbed.USER,
            password=self.testbed.PASSWORD,
            url=self.testbed.ENDPOINT,
            datadir=self.testbed.DATADIR,
            realm_name=self.testbed.REALM,
        )


class TestMain_remove_default_client_scope(TestCaseMain):
    def setUp(self):
        super().setUp()
        testbed = self.testbed
        self.client_scopes_api = testbed.kc.build("client-scopes", testbed.REALM)
        self.default_default_client_scopes_api = testbed.kc.build("default-default-client-scopes", testbed.REALM)
        self.default_optional_client_scopes_api = testbed.kc.build("default-optional-client-scopes", testbed.REALM)

    def test_1(self):
        """
        Client scope is also (default or optional) default client scope.
        main() needs to remove the client-scope.
        But first client-scope needs to be removed from default client scopes.
        """
        def _check_state():
            client_scopes_b = client_scopes_api.all()
            default_default_client_scopes_b = default_default_client_scopes_api.all()
            default_optional_client_scopes_b = default_optional_client_scopes_api.all()
            self.assertEqual(client_scopes_a, client_scopes_b)
            self.assertEqual(default_default_client_scopes_a, default_default_client_scopes_b)
            self.assertEqual(default_optional_client_scopes_a, default_optional_client_scopes_b)

        args = self.main_args
        client_scopes_api = self.client_scopes_api
        default_default_client_scopes_api = self.default_default_client_scopes_api
        default_optional_client_scopes_api = self.default_optional_client_scopes_api

        main(args)
        client_scopes_a = client_scopes_api.all()
        default_default_client_scopes_a = default_default_client_scopes_api.all()
        default_optional_client_scopes_a = default_optional_client_scopes_api.all()
        _check_state()

        # create extra client scopes, and make them default
        extra_def_client_scope_name = "ci0-client-scope-EXTRA-def"
        extra_opt_client_scope_name = "ci0-client-scope-EXTRA-opt"
        for extra_cs_name, extra_cs_api in zip(
                [extra_def_client_scope_name, extra_opt_client_scope_name],
                [default_default_client_scopes_api, default_optional_client_scopes_api]
            ):
            self.client_scopes_api.create(dict(
                name=extra_cs_name,
                description=extra_cs_name + "---CI-INJECTED",
                protocol="openid-connect",
            )).isOk()
            extra_cs = self.client_scopes_api.findFirstByKV("name", extra_cs_name)
            extra_cs_api.update(
                extra_cs["id"],
                dict(
                    realm=self.testbed.REALM,
                    clientScopeId=extra_cs["id"],
                ),
            )
        # extra_def_client_scope = self.client_scopes_api.findFirstByKV("name", extra_def_client_scope_name)
        # extra_opt_client_scope = self.client_scopes_api.findFirstByKV("name", extra_def_client_scope_name)

        main(args)
        _check_state()
