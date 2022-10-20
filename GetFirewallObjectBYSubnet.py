import json
import requests
from fmglogin import sess
from rich.console import Console
from rich.table import Table
from rich import box
from rich.style import Style
from netaddr import *

requests.packages.urllib3.disable_warnings()

session_info = sess

fmg = "192.168.227.230"
base_url = f"https://{fmg}/jsonrpc"

adoms = ["root", "FGT-6-0", "FGT-6-2", "FGT-6-4"]

ip_input = input("Object IP you want to find format - 192.168.0.0/24: ")
#ip_input = '1.1.1.1'
ip_input = IPNetwork(ip_input)

console = Console()
present_style = Style(color="green", blink=True, bold=True)
not_present_style = Style(color="red", blink=True, bold=True)


def get_object_from_subnet(fmg_url, sessi, adom, ip_addr):
    fw_obj_adom_6_4 = f"/pm/config/adom/{adom}/obj/firewall/address/"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "fields": ['name'],
                "filter": [[
                    "subnet", "==", [str(ip_input.network), str(ip_input.netmask)]
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


empty_list = []
result_dict = {}

for adomm in adoms:
    parsed_objs = get_object_from_subnet(base_url, session_info, adomm, ip_input)
    if parsed_objs['result'][0]['data'] == empty_list:
        console.print(f"Object {ip_input} does not exist in [magenta]ADOM {adomm}", style=not_present_style)
        result_dict[adomm] = f'Object {ip_input} does not exist'

    else:
        for objects in parsed_objs['result'][0]['data']:
            console.print(
                f"[yellow]Object IP: {ip_input}[/yellow] [blue]Object Name is: {objects['name']}[/blue] and is [green][bold]PRESENT[/bold][/green] in [magenta]ADOM {adomm}")
            result_dict[adomm] = f'Object {ip_input} Name {objects["name"]} exists in ADOM'

f = open("demo2.txt", "w")
f.write(json.dumps(result_dict))
f.close()

from fmglogout import logout_sess

logout_sess
