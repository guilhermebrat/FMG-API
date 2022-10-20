import json
import requests
from fmglogin import sess
from rich.console import Console
from rich.table import Table
from rich import box
from rich.style import Style
from netaddr import *
from rich.console import Console
from rich.table import Table
import AdomLockUnlock
import time
import AdomCommit

requests.packages.urllib3.disable_warnings()

session_info = sess

fmg = "192.168.227.230"
base_url = f"https://{fmg}/jsonrpc"

adoms = ["root", "FGT-6-0", "FGT-6-2", "FGT-6-4"]
other_adoms = []
# ip_input = input("Object IP you want to find format - 192.168.0.0/24: ")
# ip_input = IPNetwork(ip_input)

console = Console()
present_style = Style(color="green", blink=True, bold=True)
not_present_style = Style(color="red", blink=True, bold=True)


def create_object(fmg_url, sessi, adom, ip_addr, obj_name):
    fw_obj_adom_6_4 = f"/pm/config/adom/{adom}/obj/firewall/address"

    body = {
        "id": 1,
        "method": "add",
        "params": [
            {
                "url": fw_obj_adom_6_4,
                "data": [{
                    "name": obj_name,
                    "type": 0,
                    "subnet": [str(ip_input.network), str(ip_input.netmask)]
                }
                ]
            }
        ],
        "session": sessi
    }

    body = json.dumps(body)

    response = requests.post(url=fmg_url, data=body, verify=False)
    response = json.loads(response.content)
    #print (response)
    return response


table = Table(title="FMG Objects", box=box.SQUARE, show_lines=True, leading=False, pad_edge=False)
table.add_column("Name", justify="center", style="green")
table.add_column("ADOM", justify="left", style="magenta")
table.add_column("Subnet", justify="left", style="magenta")
table.add_column("Status", justify="left", style="magenta")


not_valid_list = []

for adomm in adoms:
    AdomLockUnlock.adom_lock(base_url, session_info, adomm)
    time.sleep(1)
    with open("bulk_objects.txt") as file:
        for line in file:
            data = line.split()
            try:
                ip_input = IPNetwork(data[1])
                parsed_objs = create_object(base_url, session_info, adomm, ip_input, data[0])
                if parsed_objs['result'][0]['status']['message'] == 'OK':
                    table.add_row(data[0], adomm, str(ip_input), 'Object Added Successfully')
                elif parsed_objs['result'][0]['status']['message'] == 'Object already exists':
                    table.add_row(data[0], adomm, str(ip_input), 'Object Already Exists')
            except AddrFormatError:
                if ip_input not in not_valid_list:
                    not_valid_list.append(ip_input)
    AdomCommit.adom_commit(base_url, session_info,adomm)
    AdomLockUnlock.adom_unlock(base_url,session_info, adomm)
    time.sleep(1)



console = Console()
console.print(table)

for objects_not_added in not_valid_list:
    print('*' * len(objects_not_added) + "*" * 17)
    console.print(f"*Object {objects_not_added} [red]NOT VALID[/red]*")
print('*' * len(objects_not_added) + "*" * 17)
from fmglogout import logout_sess

logout_sess
