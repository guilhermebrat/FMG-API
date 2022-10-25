import yaml


with open("inventory.yaml", "r") as stream:
    try:
        info = yaml.safe_load(stream)
        print (info['fmg'])
    except yaml.YAMLError as exc:
        print (exc)