"""Turns the findings list into something readable, either on screen or as
a small HTML file you can forward to someone."""

CATEGORY_COLOUR = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#c62828"}


def print_console_report(subject, sender, findings, score, category):
    print("=" * 60)
    print("Phishing Email Analyser")
    print("=" * 60)
    print(f"Subject : {subject}")
    print(f"From    : {sender}")
    print(f"Risk    : {category} ({score}/100)")
    print("-" * 60)

    if not findings:
        print("No red flags found by these checks. That's not the same as safe,")
        print("it just means nothing here tripped an automated rule.")
    else:
        for description, weight in sorted(findings, key=lambda f: -f[1]):
            print(f"  [+{weight:>2}] {description}")

    print("=" * 60)


def write_html_report(path, subject, sender, findings, score, category):
    rows = "".join(
        f"<tr><td>{weight}</td><td>{description}</td></tr>"
        for description, weight in sorted(findings, key=lambda f: -f[1])
    )
    colour = CATEGORY_COLOUR[category]

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Phishing analysis report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
h1 {{ color: {colour}; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
td, th {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f4f4f4; }}
</style>
</head>
<body>
<h1>Risk: {category} ({score}/100)</h1>
<p><strong>Subject:</strong> {subject}</p>
<p><strong>From:</strong> {sender}</p>
<table>
<tr><th>Weight</th><th>Finding</th></tr>
{rows}
</table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
