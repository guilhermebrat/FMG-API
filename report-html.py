import json
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import GetFirewallObjectBYSubnet

env = Environment(loader=FileSystemLoader('template'))
template = env.get_template('result_template.html')

adom_list =[]
object_check_list =[]

f = open("demo2.txt", "r")
result = json.loads(f.read())


for key in result:
    adom_list.append(key)
    object_check_list.append(result[key])

df = pd.DataFrame({'ADOM': adom_list,
                   'Status': object_check_list
})


html = template.render(
    title_text='Resolute FP',
    text='Object Checker',
    result_text='Result:',
    object_result=df
)

with open('html_report_jinja.html', 'w') as f:
    f.write(html)


#df.to_excel(writer, sheet_name='Object Check1', index=False)
#writer.save()

df.to_html
