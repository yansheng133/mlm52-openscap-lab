"""Build an autotailor JSON that evaluates ONLY the chosen SSG rules.

autotailor (openscap-utils) requires a base profile, so the tailored profile extends the STIG
profile, unselects every other rule the STIG profile selects, and selects the chosen ones
(including rules that are not in the STIG profile at all).

Usage:
  python3 make_tailoring.py --ds ds.json --rules mapping.csv [--var var_password_pam_remember=8 ...] > t.json
  # on the client:
  autotailor -j t.json -o /opt/lab-scap/tailoring.xml /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
  oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_lab_selected \
        --tailoring-file /opt/lab-scap/tailoring.xml <datastream>     # expect exactly N results
--rules: CSV from stig_map.py (column rhel8_rule, ';'-separated) or a plain text file, one rule per line.
"""
import argparse, csv, json

P = "xccdf_org.ssgproject.content_rule_"
ap = argparse.ArgumentParser()
ap.add_argument("--ds", required=True); ap.add_argument("--rules", required=True)
ap.add_argument("--datastream", default="ssg-rhel8-ds.xml"); ap.add_argument("--var", action="append", default=[])
ap.add_argument("--profile-id", default="lab_selected")
a = ap.parse_args()

if a.rules.endswith(".csv"):
    want = sorted({r for row in csv.DictReader(open(a.rules, encoding="utf-8-sig")) for r in row["rhel8_rule"].split(";") if r})
else:
    want = sorted({l.strip().replace(P, "") for l in open(a.rules) if l.strip()})
ds = next(v for k, v in json.load(open(a.ds)).items() if k.endswith(a.datastream))
stig = [r.replace(P, "") for r in ds["profiles"]["xccdf_org.ssgproject.content_profile_stig"]["selected"]]
rules = {r: {"evaluate": False} for r in stig if r not in want}
rules.update({r: {"evaluate": True} for r in want})
variables = {k: {"value": v} for k, v in (x.split("=", 1) for x in a.var)}
json.dump({"profiles": [{"id": a.profile_id, "title": "selected rules", "base_profile_id": "stig",
                         "rules": rules, "variables": variables}]}, __import__("sys").stdout, indent=1)
__import__("sys").stderr.write(f"selected {len(want)}, unselected {sum(not v['evaluate'] for v in rules.values())}\n")
