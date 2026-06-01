import re

with open("app_v2.py", "r", encoding="utf-8") as f:
    code = f.read()

with open("new_html.html", "r", encoding="utf-8") as f:
    new_html = f.read()

# Find the block HTML = r"""<!DOCTYPE html> ... """
# We'll use a regex
pattern = re.compile(r'HTML\s*=\s*r"""<!DOCTYPE html>.*?"""', re.DOTALL)
match = pattern.search(code)
if match:
    # Replace
    replacement = 'HTML = r"""' + new_html + '"""'
    new_code = code[:match.start()] + replacement + code[match.end():]
    with open("app_v2.py", "w", encoding="utf-8") as f:
        f.write(new_code)
    print("Replaced successfully!")
else:
    print("HTML string not found!")
