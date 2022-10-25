import json
import requests


def get_object_from_subnet(fmg_url, sessi, adom, ip_addr):
    fw_obj_adom_6_4 = f"/pm/config/adom/{adom}/obj/firewall/address/"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "fields": ['name'],
                "filter": [[
                    "subnet", "==", [str(ip_addr.network), str(ip_addr.netmask)]
                ]],
                "url": fw_obj_adom_6_4
            }
        ],
        "session": sessi
    }

    body = json.dumps(body)

    response = requests.post(url=fmg_url, data=body, verify=False)
    response = json.loads(response.content)
    return response
