import json
import requests


def get_policy_by_source(fmg_url, sessi, adom, obj_name,fw_pkg):
    fw_obj_adom = f"/pm/config/adom/{adom}/pkg/{fw_pkg}/firewall/policy"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "fields": ['obj seq', 'srcintf', 'dstintf','srcaddr', 'dstaddr','action', 'status'],
                "filter": [[
                    "srcaddr", "==", obj_name
                ]],
                "url": fw_obj_adom
            }
        ],
        "session": sessi
    }

    body = json.dumps(body)

    response = requests.post(url=fmg_url, data=body, verify=False)
    response = json.loads(response.content)
    return response


def get_policy_by_destination(fmg_url, sessi, adom, obj_name,fw_pkg):
    fw_obj_adom = f"/pm/config/adom/{adom}/pkg/{fw_pkg}/firewall/policy"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "fields": ['obj seq', 'srcintf', 'dstintf','srcaddr', 'dstaddr','action', 'status'],
                "filter": [[
                    "dstaddr", "==", obj_name
                ]],
                "url": fw_obj_adom
            }
        ],
        "session": sessi
    }
    body = json.dumps(body)

    response = requests.post(url=fmg_url, data=body, verify=False)
    response = json.loads(response.content)
    return response
