import json
import requests
from fmglogin import sess
from rich.console import Console
from rich.table import Table
from rich import box
from rich.style import Style
from netaddr import *
import pandas as pd

requests.packages.urllib3.disable_warnings()

session_info = sess

fmg = "192.168.227.230"
base_url = f"https://{fmg}/jsonrpc"

adoms = ["FGT-6-4"]


def get_firewall_services(fmg_url, sessi, adom):
    fw_services = f"/pm/config/adom/{adom}/obj/firewall/service/custom"

    body = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "url": fw_services
            }
        ],
        "session": sessi
    }

    body = json.dumps(body)

    response = requests.post(url=fmg_url, data=body, verify=False)
    response = json.loads(response.content)
    return response

service_with_ip = []
adom_list =[]


for adomm in adoms:
    parsed_objs = get_firewall_services(base_url, session_info, adomm)
    #print(parsed_objs)
    #print (json.dumps(parsed_objs, indent=4))
    services  = parsed_objs['result'][0]['data']
    for service in services:
        if str(service['iprange']) != '0.0.0.0':
            #print(service['name'])
            service_with_ip.append(service['name'])
            adom_list.append(adomm)


from fmglogout import logout_sess

print (adom_list)
print (service_with_ip)
df = pd.DataFrame({'ADOM': adom_list,
                   'Service with IP': service_with_ip
})

writer = pd.ExcelWriter('service_checker.xlsx')
df.to_excel(writer, sheet_name='Service Check', index=False)
writer.save()

logout_sess
