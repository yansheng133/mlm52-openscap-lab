"""Schedule OpenSCAP XCCDF scans through the MLM API (optionally at a future time, optionally tailored).

Verified on MLM 5.2.0:
  * system.scap.scheduleXccdfScan(sid, xccdfPath, oscapParams, date) — the scan started at/after
    `date` and its rule results came back to MLM;
  * `oscapParams` works, the `oscapPrams` spelling returns "No method exists with the matching parameters";
  * `--tailoring-file` + tailored `--profile` inside oscapParams is honoured (only selected rules evaluated);
  * there is no Recurring Action type for OpenSCAP (only Highstate / Custom state), so periodic scans need
    an external scheduler (cron, CI) calling this script.
The tailoring file must already exist at that path on every client; MLM does not distribute it.

Usage: python3 schedule_scan.py --group <system-group> [--at HH:MM] [--profile ID] [--tailoring /path/on/client]
Env: see mlmapi.py
"""
import argparse, datetime, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mlmapi import API

DS = {"8": "/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml", "9": "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"}
ap = argparse.ArgumentParser()
ap.add_argument("--group", required=True); ap.add_argument("--at")
ap.add_argument("--profile", default="xccdf_org.ssgproject.content_profile_stig"); ap.add_argument("--tailoring")
a = ap.parse_args()
when = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
if a.at:
    hh, mm = map(int, a.at.split(":")); when = when.replace(hour=hh, minute=mm, second=0)
params = f"--profile {a.profile}" + (f" --tailoring-file {a.tailoring}" if a.tailoring else "")
api = API()
try:
    for s in api.get("systemgroup/listSystemsMinimal", systemGroupName=a.group)["result"]:
        rel = api.get("system/getDetails", sid=s["id"])["result"].get("release", "")
        ds = DS.get(rel[:1])
        if not ds:
            print(f"skip {s['name']}: release {rel!r}"); continue
        r = api.post("system/scap/scheduleXccdfScan", {"sid": s["id"], "xccdfPath": ds, "oscapParams": params,
                                                       "date": when.strftime("%Y-%m-%dT%H:%M:%SZ")})
        print(s["name"], when.isoformat(), r)
finally:
    api.logout()
