import json
import unittest
import os

from .helper import TestBed, SAMPLES_PATH, SAMPLE_PAYLOADS_PATH
from kcloader.tools import traverse_and_remove_field, bfs_folder


def load_file( fname):
    f = open(fname)
    data = json.loads(f.read())
    f.close()

    return data


class TestingHelperAlgorithms(unittest.TestCase):
    def xtesting_tool_for_field_removal(self):
        DC_Client = os.path.join(SAMPLE_PAYLOADS_PATH, 'clients/client-0/dc.json')
        client_tmpl = load_file(DC_Client)
        client_tmpl = traverse_and_remove_field(client_tmpl, 'id')
        self.assertFalse('id' in client_tmpl['protocolMappers'][0], 'The id field have to be None')

    def testing_bfs_for_resource_file(self):
        Clients = os.path.join(SAMPLE_PAYLOADS_PATH, 'clients/')
        success = [
            os.path.join(SAMPLE_PAYLOADS_PATH, 'clients/client-1/marvel.json'),
            os.path.join(SAMPLE_PAYLOADS_PATH, 'clients/client-0/dc.json'),
        ]
        res = bfs_folder(Clients)
        self.assertListEqual(sorted(success),sorted(res))

        Empty = os.path.join(SAMPLES_PATH, 'bfs/empty/')
        empty_res = bfs_folder(Empty)
        self.assertListEqual(['test/samples/bfs/empty/1/1.json'], empty_res, "We expect this response:['test/samples/bfs/empty/1/1.json'] " )

        Empty2 = os.path.join(SAMPLES_PATH, 'bfs/empty2/')
        success2 = ['test/samples/bfs/empty2/1/1.json', 'test/samples/bfs/empty2/2/3/2.json']
        empty_res_2 = bfs_folder(Empty2)
        self.assertListEqual(sorted(success2), sorted(empty_res_2), "We expect this path: " + ''.join(success2))



if __name__ == '__main__':
    unittest.main()
