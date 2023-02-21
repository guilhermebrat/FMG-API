import json
import requests
"""
FMGLOGIN:
IMPORTANT
When importing the funcintion sess from the script fmglogin
It will AUTOMATICALLY ask for the user/password
This can be improved by invoking the function and passing the user/password to it.
This is the FIRST interaction that the script will ask
"""
from fmglogin import sess
from rich.console import Console
from rich.table import Table
from rich import box
from rich.style import Style
"""
NETADDR: Library that converts a string into an IP.
once you pass the string containing a valid ip it can extract the 
subnet, mask, network ip, broadcast ip and other stuff.
"""
from netaddr import *
"""
YAML: Library to interpret yaml file
"""
import yaml
"""
DEF-GET-OBJECT: Script created on the side to perform the api calls.
This was done to maitain the script as clean as possible...lol
"""
import DefGetObject
"""
URLLIB3: to dismiss the certificate warning of api
"""
import urllib3
"""
OS: library to get information from the OS, such as: 
username and folder structure
"""
import os
"""
GETPASS: library conceal the password when the user is typing it
"""
import getpass
"""
PRETTYTABLE: Library to generate the tables
"""
from prettytable import PrettyTable as pt
"""
DATETIME: Library to get the current date from system.
"""
from datetime import datetime
"""
DEF-GET-Policy-By-Object-Name: Script created to get where the object is user on policy rules
"""
import DefGetPolicyByObjectName


"""
Script created to access the FortiManager and retrieve where specific objects are used
withing the device across several devices and adoms
"""


#Used to get the current date
today = datetime.today().strftime("%d-%m-%Y")

#Used to get the user logged into the server at the moment
directory = str(getpass.getuser())
#Get the directory where the script is running
root_dir = os.getcwd()

#Used to create the folder with the username
path = os.path.join(root_dir, directory)
if not os.path.exists(path):
    os.makedirs(path)

#Used to create the folder date inside the username folder
path_date = os.path.join(path, today)
if not os.path.exists(path_date):
    os.makedirs(path_date)

#dismiss the certificate warning of the api
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session_info = sess

"""
This is the SECOND interaction of the script
option to choose if want to check only one IP by passing it to the script
or
choose the script to read from a file, a yaml file in this case.
Improvements: under each user folder define a default name of the file and we dont need to ask the file name
"""
print("Chose an option")
print("1 - for a single IP")
option = input("2 - for file check (ticket.yaml): ")
option: int = int(option)

"""
First we try to open the file using 'with' then using yaml function 'yaml.safe_load' to
read the file
the else/if statement is checking if the file name entered exists or not.
"""

if option == 1:
    decom_tkt = input("Ticket Number: ")
    ip_input = input("Object IP you want to find (ip/mask): ")
    ip_input = IPNetwork(ip_input)

elif option == 2:
    file = input("Whats the file name in .yaml format (name.yaml): ")
    with open(file, "r") as streamb:
        yaml_ticket = yaml.safe_load(streamb)
else:
    print("Option not available")

"""
We are using the same method to open a file named 'inventory.yaml'
This file contains the:
FortiManager IP
ADOMS
PolicyPackages Name

This information is going to be used to perform the calls.
"""
with open("inventory.yaml", "r") as stream:
    yaml_inv = yaml.safe_load(stream)


#Base url for the API calls, from the file we loaded with yaml
base_url = f"https://{yaml_inv['fmg']}/jsonrpc"

empty_list = []
result_dict = {}
obj_range_found_list = []
"""
Here we are initializing all the tables we are going to print on the .txt
"""
tb = pt()
tb.field_names = ["ADOM", "Object Searched", "Result", "Object Name", "Member Of Group"]

tb_adom_fwint = pt()
tb_adom_fwint.field_names = ["Object Searched", "Result", "Object Name", "Member Of Group"]

tb_adom_fwcorp = pt()
tb_adom_fwcorp.field_names = ["Object Searched", "Result", "Object Name", "Member Of Group"]

tb_adom_cloud = pt()
tb_adom_cloud.field_names = ["Object Searched", "Result", "Object Name", "Member Of Group"]

tb_adom_mills_62 = pt()
tb_adom_mills_62.field_names = ["Object Searched", "Result", "Object Name", "Member Of Group"]

tb_adom_mills_70 = pt()
tb_adom_mills_70.field_names = ["Object Searched", "Result", "Object Name", "Member Of Group"]

tb_adom_dev = pt()
tb_adom_dev.field_names = ["Object Searched", "Result", "Object Name", "Member Of Group"]

tb_iprange = pt()
tb_iprange.field_names = ["ADOM", "Object Searched", "Result", "Ip Range Object Found"]

tb_policy_srcaddr = pt()
tb_policy_srcaddr.field_names = ['ADOM', 'Firewall Policy', 'Policy ID','SRC Int', 'DST INT', 'SRC ADDR', 'DST ADDR', ' ACTION']

tb_policy_dstaddr = pt()
tb_policy_dstaddr.field_names = ['ADOM', 'Firewall Policy', 'Policy ID','SRC Int', 'DST INT', 'SRC ADDR', 'DST ADDR', ' ACTION']

tb_object_group = pt()
tb_object_group. field_names =['ADOM', 'IP','Object Name', 'Member Of Object Group']
"""
Here we start our 'logic'
If the user entered 2 to use a file containing the ips
"""
if option == 2:
    """
    we loop all the keys of the file
    the keys are the ticket name
    it means we are iterating a single ticket at a time
    """
    for ticket in yaml_ticket:
        for key in ticket:
            #Create the txt file with name
            file_name = str(key) + ".txt"
            #Clear the row since we are iterating several time over the same table
            tb.clear_rows()
            tb_iprange.clear_rows()
            """
            Since we iterated with the ticket name(key) above
            Now we need to iterate over all ips under the same ticket
            Because we need to check each one of them
            """
            for ip in ticket[key]:
                #transforming the string into an ip
                ip_input = IPNetwork(ip)
                """
                Now we have the IP
                We need to check each ADOM.
                To create a single table for each adom, a if structure was created to match the ADOM
                """
                for adomm in yaml_inv['adoms']:
                    """
                    The 'parsed_objs' receives the result of the API call we are performing
                    using 'DefGetObject.get_object_from_subnet'
                    This first part is to check if the objects exists or not, if nothing is returned
                    We add a row saying that the object is not found
                    """
                    parsed_objs = DefGetObject.get_object_from_subnet(base_url, session_info, adomm, ip_input)
                    if parsed_objs['result'][0]['data'] == empty_list:
                        if adomm == "FWINT-62":
                            tb_adom_fwint.add_row([adomm, ip_input.cidr, "Object Not Found", " - ", " - "])
                        elif adomm == "FWCORP-62":
                            tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Not Found", " - ", " - "])
                        elif adomm == "CLOUD-62":
                            tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Not Found", " - ", " - "])
                        elif adomm == "MILSS-62":
                            tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Not Found", " - ", " - "])
                        elif adomm == "MILSS-70":
                            tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Not Found", " - ", " - "])
                        elif adomm == "dev":
                            tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Not Found", " - ", " - "])
                    else:
                        """
                        If something is found we match the adom and then
                        """
                        for objects in parsed_objs['result'][0]['data']:
                            if adomm == "FWINT-62":
                                tb_adom_fwint.add_row([adomm, ip_input.cidr, "Object Found", " - ", " - "])
                            elif adomm == "FWCORP-62":
                                tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Found", " - ", " - "])
                            elif adomm == "CLOUD-62":
                                tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Found", " - ", " - "])
                            elif adomm == "MILSS-62":
                                tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Found", " - ", " - "])
                            elif adomm == "MILSS-70":
                                tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Found", " - ", " - "])
                            elif adomm == "dev":
                                tb_adom_fwcorp.add_row([adomm, ip_input.cidr, "Object Found", " - ", " - "])

                            obj_group_result = DefGetObject.get_object_group(base_url, session_info, adomm,objects['name'])
                            parsed_obj_group = obj_group_result['result'][0]['data']
                            for members in parsed_obj_group:
                                tb_object_group.add_row([adomm, ip_input.cidr, objects['name'], members['name']])
                        for policies_pkg in yaml_inv['firewall-policies']:
                            for key, value in policies_pkg.items():
                                if key == adomm:
                                    for policy in value:
                                        parsed_policy = DefGetPolicyByObjectName.get_policy_by_source(base_url,
                                                                                                      session_info, adomm,
                                                                                                      objects['name'],
                                                                                                      policy)
                                        parsed_policy = parsed_policy['result'][0]['data']
                                        for policies in parsed_policy:
                                            tb_policy_srcaddr.add_row(
                                                [adomm, policy, policies['obj seq'], policies['srcintf'][0],
                                                 policies['dstintf'][0], policies['srcaddr'][0], policies['dstaddr'][0],
                                                 policies['action']])

                                        parsed_policy = DefGetPolicyByObjectName.get_policy_by_destination(base_url,
                                                                                                           session_info,
                                                                                                           adomm,
                                                                                                           objects['name'],
                                                                                                           policy)
                                        parsed_policy = parsed_policy['result'][0]['data']
                                        for policies in parsed_policy:
                                            tb_policy_dstaddr.add_row(
                                                [adomm, policy, policies['obj seq'], policies['srcintf'][0],
                                                 policies['dstintf'][0], policies['srcaddr'][0],
                                                 policies['dstaddr'][0], policies['action']])


                    parsed_objs_range = DefGetObject.get_object_range(base_url, session_info, adomm)
                    result_objs_range = parsed_objs_range['result'][0]['data']

                    for objects in result_objs_range:
                        object_ip_range = iter_iprange(objects['start-ip'], objects['end-ip'], step=1)
                        for curr_ip in object_ip_range:
                            if IPAddress(curr_ip) == IPAddress(ip_input):
                                obj_range_found_list.append(str(ip_input))
                                tb_iprange.add_row([adomm, str(ip_input), "IP Found in Range Object", objects['name']])
                                obj_group_result = DefGetObject.get_object_group(base_url, session_info, adomm,
                                                                                 objects['name'])
                                parsed_obj_group = obj_group_result['result'][0]['data']
                                for members in parsed_obj_group:
                                    tb_object_group.add_row([adomm, ip_input.cidr, objects['name'], members['name']])
                                for policies_pkg in yaml_inv['firewall-policies']:
                                    for key, value in policies_pkg.items():
                                        if key == adomm:
                                            for policy in value:
                                                parsed_policy = DefGetPolicyByObjectName.get_policy_by_source(base_url,
                                                                                                              session_info,
                                                                                                              adomm,
                                                                                                              objects[
                                                                                                                  'name'],
                                                                                                              policy)
                                                parsed_policy = parsed_policy['result'][0]['data']
                                                for policies in parsed_policy:
                                                    tb_policy_srcaddr.add_row(
                                                        [adomm, policy, policies['obj seq'], policies['srcintf'][0],
                                                         policies['dstintf'][0], policies['srcaddr'][0],
                                                         policies['dstaddr'][0], policies['action']])

                                                parsed_policy = DefGetPolicyByObjectName.get_policy_by_destination(
                                                    base_url, session_info, adomm,
                                                    objects['name'], policy)
                                                parsed_policy = parsed_policy['result'][0]['data']
                                                for policies in parsed_policy:
                                                    tb_policy_dstaddr.add_row(
                                                        [adomm, policy, policies['obj seq'], policies['srcintf'][0],
                                                         policies['dstintf'][0], policies['srcaddr'][0],
                                                         policies['dstaddr'][0], policies['action']])

                if len(obj_range_found_list) == 0:
                    tb_iprange.add_row(["-", str(ip_input), "IP Not Found in any Range Object", " - "])

                tb_string = tb.get_string(title="Object Checker")
                tb_adom_fwint_string = tb_adom_fwint.get_string(title="FWINT")
                tb_adom_fwcorp_string = tb_adom_fwcorp.get_string(title="FWCORP")
                tb_adom_cloud_string = tb_adom_cloud.get_string(title="CLOUD")
                tb_adom_mills_62_string = tb_adom_mills_62.get_string(title="MILLS-62")
                tb_adom_mills_70_string = tb_adom_mills_70.get_string(title="MILLS-70")
                tb_adom_dev_string = tb_adom_dev.get_string(title="MILLS-70")
                tb_iprange_string = tb_iprange.get_string(title="IP Range Object Checker")
                tb_policy_srcaddr_string = tb_policy_srcaddr.get_string(title="Policy Source Object")
                tb_policy_dstaddr_string = tb_policy_dstaddr.get_string(title="Policy Destination Object")
                tb_object_group_string = tb_object_group.get_string(title='Object Group Member')

            if os.path.isfile(os.path.join(path_date, file_name)):
                with open(os.path.join(path_date, file_name), "a+") as fa:
                    fa.write("\n\n")
                    fa.write("*" * 100)
                    fa.write("\n\n")
                    fa.write(tb_adom_fwint_string)
                    fa.write("\n\n\n")
                    fa.write(tb_adom_fwcorp_string)
                    fa.write("\n\n\n")
                    fa.write(tb_adom_cloud_string)
                    fa.write("\n\n\n")
                    fa.write(tb_adom_mills_62_string)
                    fa.write("\n\n\n")
                    fa.write(tb_adom_mills_70_string)
                    fa.write("\n\n\n")
                    fa.write(tb_adom_dev_string)
                    fa.write("\n\n\n")
                    fa.write(tb_iprange_string)
                    fa.write("\n\n\n")
                    fa.write(tb_object_group_string)
                    fa.write("\n\n\n")
                    fa.write(tb_policy_srcaddr_string)
                    fa.write("\n\n")
                    fa.write(tb_policy_dstaddr_string)
                    fa.write("\n\n")
                    fa.write(f"File written at: {datetime.now()}")
            else:
                with open(os.path.join(path_date, file_name), "w") as f:
                    f.write(tb_adom_fwint_string)
                    f.write("\n\n\n")
                    f.write(tb_adom_fwcorp_string)
                    f.write("\n\n\n")
                    f.write(tb_adom_cloud_string)
                    f.write("\n\n\n")
                    f.write(tb_adom_mills_62_string)
                    f.write("\n\n\n")
                    f.write(tb_adom_mills_70_string)
                    f.write("\n\n\n")
                    f.write(tb_adom_dev_string)
                    f.write("\n\n\n")
                    f.write(tb_iprange_string)
                    f.write("\n\n\n")
                    f.write(tb_object_group_string)
                    f.write("\n\n\n")
                    f.write(tb_policy_srcaddr_string)
                    f.write("\n\n")
                    f.write(tb_policy_dstaddr_string)
                    f.write("\n\n")
                    f.write(f"File written at: {datetime.now()}")


elif option == 1:
    for adomm in yaml_inv['adoms']:
        parsed_objs = DefGetObject.get_object_from_subnet(base_url, session_info, adomm, ip_input)
        if parsed_objs['result'][0]['data'] == empty_list:
            tb.add_row([adomm, ip_input.cidr, "Object Not Found", " - ", " - "])
        else:
            for objects in parsed_objs['result'][0]['data']:

                obj_group_result = DefGetObject.get_object_group(base_url, session_info, adomm, objects['name'])
                parsed_obj_group = obj_group_result['result'][0]['data']
                for members in parsed_obj_group:
                    tb_object_group.add_row([adomm,ip_input.cidr ,objects['name'], members['name']])
                    tb.add_row([adomm, ip_input.cidr, "Object Found", objects["name"], members['name']])
                for policies_pkg in yaml_inv['firewall-policies']:
                    for key, value in policies_pkg.items():
                        if key == adomm:
                            for policy in value:
                                parsed_policy = DefGetPolicyByObjectName.get_policy_by_source(base_url, session_info, adomm,
                                                                                    objects['name'],policy)
                                parsed_policy = parsed_policy['result'][0]['data']
                                for policies in parsed_policy:
                                    tb_policy_srcaddr.add_row([adomm, policy, policies['obj seq'], policies['srcintf'][0],
                                            policies['dstintf'][0], policies['srcaddr'][0], policies['dstaddr'][0], policies['action']])

                                parsed_policy = DefGetPolicyByObjectName.get_policy_by_destination(base_url, session_info, adomm,
                                                                                              objects['name'], policy)
                                parsed_policy = parsed_policy['result'][0]['data']
                                for policies in parsed_policy:
                                    tb_policy_dstaddr.add_row([adomm, policy, policies['obj seq'], policies['srcintf'][0],
                                                               policies['dstintf'][0], policies['srcaddr'][0],
                                                               policies['dstaddr'][0], policies['action']])

        parsed_objs_range = DefGetObject.get_object_range(base_url, session_info, adomm)
        result_objs_range = parsed_objs_range['result'][0]['data']

        for objects in result_objs_range:
            object_ip_range = iter_iprange(objects['start-ip'], objects['end-ip'], step=1)
            for curr_ip in object_ip_range:
                if IPAddress(curr_ip) == IPAddress(ip_input):
                    obj_range_found_list.append(str(ip_input))
                    tb_iprange.add_row([adomm, str(ip_input), "IP Found in Range Object", objects['name']])
                    obj_group_result = DefGetObject.get_object_group(base_url, session_info, adomm, objects['name'])
                    parsed_obj_group = obj_group_result['result'][0]['data']
                    for members in parsed_obj_group:
                        tb_object_group.add_row([adomm, ip_input.cidr, objects['name'], members['name']])
                    for policies_pkg in yaml_inv['firewall-policies']:
                        for key, value in policies_pkg.items():
                            if key == adomm:
                                for policy in value:
                                    parsed_policy = DefGetPolicyByObjectName.get_policy_by_source(base_url,
                                                                                                  session_info, adomm,
                                                                                                  objects['name'],
                                                                                                  policy)
                                    parsed_policy = parsed_policy['result'][0]['data']
                                    for policies in parsed_policy:
                                        tb_policy_srcaddr.add_row(
                                            [adomm, policy, policies['obj seq'], policies['srcintf'][0],
                                             policies['dstintf'][0], policies['srcaddr'][0], policies['dstaddr'][0],
                                             policies['action']])

                                    parsed_policy = DefGetPolicyByObjectName.get_policy_by_destination(base_url,
                                                                                                       session_info,
                                                                                                       adomm,
                                                                                                       objects['name'],
                                                                                                       policy)
                                    parsed_policy = parsed_policy['result'][0]['data']
                                    for policies in parsed_policy:
                                        tb_policy_dstaddr.add_row(
                                            [adomm, policy, policies['obj seq'], policies['srcintf'][0],
                                             policies['dstintf'][0], policies['srcaddr'][0],
                                             policies['dstaddr'][0], policies['action']])

    if len(obj_range_found_list) == 0:
        tb_iprange.add_row(["-", str(ip_input), "IP Not Found in any Range Object", " - "])

    tb_string = tb.get_string(title="Object Checker")
    tb_adom_fwint_string = tb_adom_fwint.get_string(title="FWINT")
    tb_adom_fwcorp_string = tb_adom_fwcorp.get_string(title="FWCORP")
    tb_adom_cloud_string = tb_adom_cloud.get_string(title="CLOUD")
    tb_adom_mills_62_string = tb_adom_mills_62.get_string(title="MILLS-62")
    tb_adom_mills_70_string = tb_adom_mills_70.get_string(title="MILLS-70")
    tb_adom_dev_string = tb_adom_dev.get_string(title="MILLS-70")
    tb_iprange_string = tb_iprange.get_string(title="IP Range Object Checker")
    tb_policy_srcaddr_string= tb_policy_srcaddr.get_string(title="Policy Source Object")
    tb_policy_dstaddr_string = tb_policy_dstaddr.get_string(title="Policy Destination Object")
    tb_object_group_string = tb_object_group.get_string(title='Object Group Member')

    open
    file_name = decom_tkt + ".txt"
    if os.path.isfile(os.path.join(path_date, file_name)):
        with open(os.path.join(path_date, file_name), "a+") as fa:
            fa.write("\n\n")
            fa.write("*" * 100)
            fa.write("\n\n")
            fa.write(tb_adom_fwint_string)
            fa.write("\n\n\n")
            fa.write(tb_adom_fwcorp_string)
            fa.write("\n\n\n")
            fa.write(tb_adom_cloud_string)
            fa.write("\n\n\n")
            fa.write(tb_adom_mills_62_string)
            fa.write("\n\n\n")
            fa.write(tb_adom_mills_70_string)
            fa.write("\n\n\n")
            fa.write(tb_adom_dev_string)
            fa.write("\n\n\n")
            fa.write(tb_iprange_string)
            fa.write("\n\n\n")
            fa.write(tb_object_group_string)
            fa.write("\n\n\n")
            fa.write(tb_policy_srcaddr_string)
            fa.write("\n\n")
            fa.write(tb_policy_dstaddr_string)
            fa.write("\n\n")
            fa.write(f"File written at: {datetime.now()}")
    else:
        with open(os.path.join(path_date, file_name), "w") as f:
            f.write(tb_adom_fwint_string)
            f.write("\n\n\n")
            f.write(tb_adom_fwcorp_string)
            f.write("\n\n\n")
            f.write(tb_adom_cloud_string)
            f.write("\n\n\n")
            f.write(tb_adom_mills_62_string)
            f.write("\n\n\n")
            f.write(tb_adom_mills_70_string)
            f.write("\n\n\n")
            f.write(tb_adom_dev_string)
            f.write("\n\n\n")
            f.write(tb_iprange_string)
            f.write("\n\n\n")
            f.write(tb_object_group_string)
            f.write("\n\n\n")
            f.write(tb_policy_srcaddr_string)
            f.write("\n\n")
            f.write(tb_policy_dstaddr_string)
            f.write("\n\n")
            f.write(f"File written at: {datetime.now()}")

from fmglogout import logout_sess

logout_sess
