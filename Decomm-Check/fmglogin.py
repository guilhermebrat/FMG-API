import json
import requests
import getpass
import yaml
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

user = input("Username: ")
password = getpass.getpass(prompt='Password: ')

#user = getpass.getuser()

with open("inventory.yaml", "r") as stream:
    yaml_inv = yaml.safe_load(stream)


base_url = f"https://{yaml_inv['fmg']}/jsonrpc"




body = {
    "id": 1,
    "method": "exec",
    "params": [
        {
            "data": {
                "user": user,
                "passwd": password
            },
            "url": "/sys/login/user"
        }
    ]
}

json_body = json.dumps(body)


def login(fmg_url, body_login):
    login_result = requests.post(url=fmg_url, data=body_login, verify=False)
    parsed_result = json.loads(login_result.content)
    session_id = parsed_result['session']
    return session_id


sess = login(base_url, json_body)
