"""Extract from SSG datastreams: every rule's title, references (STIG ID, SV rule id, SRG, CIS...) and
CCE idents, plus each profile's selected rules. Runs on the client with the platform python
(no third-party modules). Output: JSON on stdout.

Usage (on the client): /usr/libexec/platform-python ds_extract.py /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml [...] > ds.json
"""
import sys, json, xml.etree.ElementTree as ET
X = "{http://checklists.nist.gov/xccdf/1.2}"
out = {}
for ds in sys.argv[1:]:
    root = ET.parse(ds).getroot()
    bench = root.find(".//" + X + "Benchmark")
    rules = {}
    for r in bench.iter(X + "Rule"):
        rules[r.get("id")] = {
            "title": (r.findtext(X + "title") or "").strip(),
            "refs": [(e.get("href"), (e.text or "").strip()) for e in r.findall(X + "reference")],
            "idents": [(e.get("system"), (e.text or "").strip()) for e in r.findall(X + "ident")],
        }
    profiles = {}
    for p in bench.findall(X + "Profile"):
        profiles[p.get("id")] = {"title": p.findtext(X + "title"), "selected": [s.get("idref") for s in p.findall(X + "select") if s.get("selected") == "true"]}
    out[ds] = {"rules": rules, "profiles": profiles}
json.dump(out, sys.stdout)
