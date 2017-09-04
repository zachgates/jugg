import os
import yaml


MAIN_DIR = os.path.dirname(os.path.realpath(__file__))


with open(os.path.join(MAIN_DIR, 'config/dev.yml'), 'r') as config:
    data = yaml.load(config.read())
    for k, v in data.items():
        globals()[k.upper()] = v
