import json
import requests


def get_object_from_subnet(fmg_url, sessi, adom, ip_addr):
    fw_obj_adom = f"/pm/config/adom/{adom}/obj/firewall/address/"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "fields": ['name'],
                "filter": [[
                    "subnet", "==", [str(ip_addr.network), str(ip_addr.netmask)]
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


def get_object_range(fmg_url, sessi, adom):
    fw_obj_adom = f"/pm/config/adom/{adom}/obj/firewall/address/"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                    "filter": [[
                    "type", "==", 1
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


def get_object_group(fmg_url, sessi, adom, obj_name):
    fw_obj_adom = f"/pm/config/adom/{adom}/obj/firewall/addrgrp/"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "fields": ['name'],
                "filter": [[
                    "member", "==", obj_name
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
