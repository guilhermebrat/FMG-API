import markdown
from markdown.extensions.tables import TableExtension
import json

f = open("demo2.txt", "r")
result = json.loads(f.read())

with open('test.md', 'bw+') as mmde:
    mmde.write('# Resolute FP\n'.encode())
    mmde.write('---\n'.encode())
    mmde.write('## FMG Object Check\n'.encode())
    mmde.write('---\n'.encode())

    mmde.write('|**ADOM** |    `----->`     | **Status** |\n'.encode('utf-8'))
    mmde.write('|:--- | :---: |:---- |\n'.encode())
    for key in result:
        mmde.write('| {} '.format(key).encode('utf-8'))
        mmde.write('| '.encode('utf-8'))
        mmde.write('|{}|\n'.format(result[key]).encode())
    mmde.seek(0)
    extensions = ['markdown.extensions.extra', 'markdown.extensions.smarty', 'tables']
    markdown.markdownFromFile(input=mmde, output='test.html', extensions=extensions)
