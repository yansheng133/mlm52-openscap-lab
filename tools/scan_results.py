"""Show the XCCDF scans of a system, or the rule-result counts of one scan.

Usage: python3 scan_results.py <sid>            # list scans
       python3 scan_results.py <sid> <xid>      # counts + rules that were actually evaluated
A tailored scan is effective only if the number of non-"notselected" results equals the number of
rules the tailoring selected; more than that means the parameters were accepted but ignored.
"""
import collections, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mlmapi import API

api = API()
try:
    sid = int(sys.argv[1])
    if len(sys.argv) == 2:
        for s in api.get("system/scap/listXccdfScans", sid=sid)["result"]:
            print(json.dumps(s))
    else:
        xid = int(sys.argv[2])
        d = api.get("system/scap/getXccdfScanDetails", xid=xid)["result"]
        rr = api.get("system/scap/getXccdfScanRuleResults", xid=xid)["result"]
        print(json.dumps({k: d.get(k) for k in ("profile", "start_time", "end_time", "oscap_parameters", "action_id")}))
        print("results:", dict(collections.Counter(r["result"] for r in rr)))
        for r in rr:
            if r["result"] != "notselected":
                print(f"  {r['result']:14} {r['idref']}")
finally:
    api.logout()
