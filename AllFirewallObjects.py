import json
import requests
from fmglogin import sess
from rich.console import Console
from rich.table import Table
from rich import box

session_info = sess

fmg = "192.168.227.230"
base_url = f"https://{fmg}/jsonrpc"


def get_all_objects(fmg_url, sessi):
    all_fw_obj_adom_6_4 = "/pm/config/adom/FGT-6-4/obj/firewall/address"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "url": all_fw_obj_adom_6_4
            }
        ],
        "session": sessi
    }

    body = json.dumps(body)

    response = requests.post(url=fmg_url, data=body, verify=False)
    response = json.loads(response.content)
    return response

parsed_objs = get_all_objects(base_url, session_info)

objs = (json.dumps(parsed_objs['result'][0]['data'], indent=4))

objs = json.loads(objs)


table = Table(title="FMG Objects", box=box.SQUARE, show_lines=True, leading=False, pad_edge=False)
table.add_column("Name", justify="center", style="green")
table.add_column("Subnet/FQDN", justify="left", style="magenta")

for objects in objs:
    # print(objects)
    obj_name = (objects['name'])
    obj_type = (objects['type'])
    if objects['type'] == 0:
        obj_subnet = (objects['subnet'][0] + "/" + objects['subnet'][1])
        table.add_row(obj_name, obj_subnet)
    elif objects['type'] == 1:
        obj_start_end_ip=(objects['start-ip'] + " to " + objects['end-ip'])
        table.add_row(obj_name, obj_start_end_ip)
    elif objects['type'] == 2:
        obj_fqdn = (objects['fqdn'])
        table.add_row(obj_name, obj_fqdn)


console = Console()
console.print(table)

from fmglogout import logout_sess
logout_sess

