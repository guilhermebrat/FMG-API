import json
import requests
from fmglogin import sess
import yaml


with open("inventory.yaml", "r") as stream:
    yaml_inv = yaml.safe_load(stream)

base_url = f"https://{yaml_inv['fmg']}/jsonrpc"

body_out = {
    "id": 1,
    "method": "exec",
    "params": [
        {
            "url": "/sys/logout"
        }
    ],
    "session": sess
}

json_body_out = json.dumps(body_out)


def logout(fmg_url, body_logout):
    logout_result = requests.post(url=fmg_url, data=body_logout, verify=False)
    return logout_result


logout_sess = logout(base_url, json_body_out)
