import os

cur_dir = os.path.dirname(os.path.abspath(__file__))

def project_file(name):
    return os.path.join(cur_dir, name)
