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
import time

requests.packages.urllib3.disable_warnings()

session_info = sess

fmg = "192.168.227.230"
base_url = f"https://{fmg}/jsonrpc"


def adom_commit(fmg_url, sessi, adom):
    fw_adom_lock = f"/dvmdb/adom/{adom}/workspace/commit"

    body = {
        "id": 1,
        "method": "exec",
        "params": [
            {
                "url": fw_adom_lock,
            }
        ],
        "session": sessi
    }

    body = json.dumps(body)
    response = requests.post(url=base_url, data=body, verify=False)
    response = json.loads(response.content)
    if response['result'][0]['status']['message'] == 'OK':
        print(f'Change to ADOM {adom} Committed successfully')
    else:
        print(f'Unable to commit changes to ADOM {adom}')
