import json
import requests

user = "admin"
password = 'admin'
fmg = "192.168.227.230"
base_url = f"https://{fmg}/jsonrpc"

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
