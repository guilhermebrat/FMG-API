import markdown

with open ('Example_Markdown.md', 'r' ) as f:
    text = f.read()
    html = markdown.markdown(text)

with open ('mdutls.html', 'w') as f:
    f.write(html)