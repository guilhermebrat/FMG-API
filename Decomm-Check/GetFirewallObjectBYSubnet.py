import json
import requests
from fmglogin import sess
from rich.console import Console
from rich.table import Table
from rich import box
from rich.style import Style
from netaddr import *
import yaml
import DefGetObjectIP
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


session_info = sess

with open("inventory.yaml", "r") as stream:
    yaml_inv = yaml.safe_load(stream)

fmg = yaml_inv['fmg']
base_url = f"https://{fmg}/jsonrpc"

adoms = ["root", "FGT-6-0", "FGT-6-2", "FGT-6-4"]

ip_input = input("Object IP you want to find format - 192.168.0.0/24: ")
#ip_input = '1.1.1.1'
ip_input = IPNetwork(ip_input)

console = Console()
present_style = Style(color="green", blink=True, bold=True)
not_present_style = Style(color="red", blink=True, bold=True)




empty_list = []
result_dict = {}

for adomm in yaml_inv['adoms']:
    parsed_objs = DefGetObjectIP.get_object_from_subnet(base_url, session_info, adomm, ip_input)
    if parsed_objs['result'][0]['data'] == empty_list:
        console.print(f"Object Searched: {ip_input.cidr} does not exist in [magenta]ADOM {adomm}", style=not_present_style)
        result_dict[adomm] = f'Object {ip_input} does not exist'

    else:
        for objects in parsed_objs['result'][0]['data']:
            console.print(
                f"[yellow]Object IP: {ip_input.cidr}[/yellow] [blue]Object Name is: {objects['name']}[/blue] and is [green][bold]PRESENT[/bold][/green] in [magenta]ADOM {adomm}")
            result_dict[adomm] = f'Object {ip_input} Name {objects["name"]} exists in ADOM'

f = open("demo2.txt", "w")
f.write(json.dumps(result_dict))
f.close()

from fmglogout import logout_sess

logout_sess
