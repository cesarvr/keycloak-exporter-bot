import json
import os, copy


def retrieve_json_files_only(doc):
    return '.json' in doc


def add_trailing_slash(path):
    if path[-1] != '/':
        path += '/'
    return path


def get_path(filepath):
    f = filepath.split('/')
    f.pop()
    return '/'.join(f)


def read_from_json(filename):
    with open(filename) as json_file:
        return json.load(json_file)


def get_json_docs_from_folder(folder):
    ret_list = []
    docs = os.listdir(folder)
    json_file_names = filter(retrieve_json_files_only, docs)
    for file in json_file_names:
        ret_list.append(folder + file)

    return ret_list


def bfs_folder(path):
    # bfs = breadth-first search
    is_node = False
    path = add_trailing_slash(path)
    docs = os.listdir(path)
    folders = []
    ret = []

    for file in docs:
       if not os.path.isfile(path+'/'+file):
           folders.append(file)
       else:
           is_node = True
           ret.append(path + file)

    if not is_node:
        for folder in folders:
            file = bfs_folder(path + folder)
            ret = ret + file


    return ret


def process_dict(val, field):
    if isinstance(val, dict):
        return traverse_and_remove_field(val, field)
    return val


'''
    good to remove fields like id that can mess up publishing.
'''
def traverse_and_remove_field(resource = {}, field='id'):
    update = copy.deepcopy(resource)
    for key in resource:
        val = resource[key]
        if isinstance(val, list):
            for index in range(len(val)):
                val[index] = process_dict(val[index], field)

        update[key] = process_dict(val, field)

        if key == field:
            assert 0  # input data should be already cleaned up
            del update[key]

    return update


# TODO remove_unnecessary_fields is not needed any more, remove it
def remove_unnecessary_fields(resource):
    updated_resource = traverse_and_remove_field(resource, 'id')
    return updated_resource


def lookup_child_resource(resource_path, child_path):
    new_path = os.path.join(get_path(resource_path), child_path)
    return [os.path.exists(new_path), new_path]


# TODO import from kcfetcher
def find_in_list(objects, **kwargs):
    # objects - list of dict
    # kwargs - key=value, used to find one object
    key = list(kwargs.keys())[0]
    value = kwargs[key]
    for obj in objects:
        if key in obj and obj[key] == value:
            return obj
