import json
import requests
from fmglogin import sess
from rich.console import Console
from rich.table import Table
from rich import box
from rich.style import Style
from netaddr import *
import yaml
import DefGetObject
import urllib3
import os
import getpass
from prettytable import PrettyTable as pt
from datetime import datetime

today = datetime.today().strftime("%d-%m-%Y")

directory = str(getpass.getuser())
root_dir = os.getcwd()

path = os.path.join(root_dir, directory)
if not os.path.exists(path):
    os.makedirs(path)

path_date = os.path.join(path, today)
if not os.path.exists(path_date):
    os.makedirs(path_date)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session_info = sess
decom_tkt = input("Ticket Number: ")
with open("inventory.yaml", "r") as stream:
    yaml_inv = yaml.safe_load(stream)

base_url = f"https://{yaml_inv['fmg']}/jsonrpc"

ip_input = input("Object IP you want to find (ip/mask): ")
ip_input = IPNetwork(ip_input)


empty_list = []
result_dict = {}
obj_range_found_list = []

tb = pt()
tb.field_names = ["ADOM", "Object Searched", "Result", "Object Name Found"]

tb_iprange = pt()
tb_iprange.field_names = ["ADOM", "Object Searched", "Result", "Ip Range Object Found"]

for adomm in yaml_inv['adoms']:
    parsed_objs = DefGetObject.get_object_from_subnet(base_url, session_info, adomm, ip_input)
    if parsed_objs['result'][0]['data'] == empty_list:
        tb.add_row([adomm, ip_input.cidr, "Object Not Found", " - "])

    else:
        for objects in parsed_objs['result'][0]['data']:
            tb.add_row([adomm, ip_input.cidr, "Object Found", objects["name"]])

print('\n' * 2)
print(f"Checking for IP {str(ip_input)} in  IP Range Objects")

for adom in yaml_inv['adoms']:
    parsed_objs_range = DefGetObject.get_object_range(base_url, session_info, adom)
    result_objs_range = parsed_objs_range['result'][0]['data']

    # print (result_objs_range)
    for objects in result_objs_range:
        object_ip_range = iter_iprange(objects['start-ip'], objects['end-ip'], step=1)
        for curr_ip in object_ip_range:
            if IPAddress(curr_ip) == IPAddress(ip_input):
                obj_range_found_list.append(str(ip_input))
                tb_iprange.add_row([adom, str(ip_input), "IP Found in Range Object", objects['name']])
                # print (f"IP {str(ip_input)} in object  {objects['name']} ADOM {adom} ")

if len(obj_range_found_list) == 0:
    tb_iprange.add_row(["-", str(ip_input), "IP Not Found in any Range Object", " - "])
    # print(f"IP {str(ip_input)} NOT found in any Range Object")

print(tb.get_string(title="IP Object Checker"))
print(tb_iprange.get_string(title="IP Range Object Checker"))

file_name = decom_tkt + ".txt"

tb_string = tb.get_string(title="IP Object Checker")
tb_iprange_string = tb_iprange.get_string(title="IP Range Object Checker")
open

if os.path.isfile(os.path.join(path_date, file_name)):
    with open(os.path.join(path_date, file_name), "a+") as fa:
        fa.write("\n\n")
        fa.write("*"*100)
        fa.write("\n\n")
        fa.write(tb_string)
        fa.write("\n\n\n")
        fa.write(tb_iprange_string)
        fa.write("\n\n")
        fa.write(f"File written at: {datetime.now()}")
else:
    with open(os.path.join(path_date, file_name), "w") as f:
        f.write(tb_string)
        f.write("\n\n\n")
        f.write(tb_iprange_string)
        f.write("\n\n")
        f.write(f"File written at: {datetime.now()}")

from fmglogout import logout_sess

logout_sess
