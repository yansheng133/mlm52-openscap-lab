"""Map baseline items that carry DISA RHEL 8 STIG Vuln IDs (V-xxxxxx) onto SSG rule ids.

Why this is needed: SSG datastreams do NOT carry Vuln IDs. Each rule carries the STIG ID
(RHEL-08-xxxxxx) and the DISA Rule ID (SV-xxxxxx rNNN_rule). The DISA XCCDF maps Vuln ID ->
Rule ID -> STIG ID; in the RHEL 8 STIG V2R8 every V-number equals its SV-number.
Two independent paths are computed (via STIG ID and via SV number) and both are reported.

Items whose Vuln ID is missing, or no longer present in the DISA file (withdrawn items), fall back to
a keyword search over rule titles (column `title_keywords`, `|`-separated); those matches are
candidates for a human to confirm, not facts.

Inputs:
  --disa   DISA manual XCCDF (U_RHEL_8_STIG_V2R8_Manual-xccdf.xml, from dl.dod.cyber.mil)
  --ds     JSON from ds_extract.py (must contain the rhel8 and rhel9 datastreams)
  --items  CSV with columns: item_id,title,stig_vuln_id,title_keywords
  --scan8/--scan9  optional JSON lists from system.scap.getXccdfScanRuleResults (idref/result)
Output: CSV on stdout.
"""
import argparse, csv, json, sys, xml.etree.ElementTree as ET

N = "{http://checklists.nist.gov/xccdf/1.1}"
P = "xccdf_org.ssgproject.content_rule_"
PROFILE = "xccdf_org.ssgproject.content_profile_stig"


def load_disa(path):
    root = ET.parse(path).getroot()
    out = {}
    for g in root.findall(N + "Group"):
        r = g.find(N + "Rule")
        out[g.get("id")] = {"sv": r.get("id"), "stig_id": r.findtext(N + "version")}
    sys.stderr.write(f"DISA: {root.findtext(N + 'title')} | {root.findtext(N + 'plain-text')} | {len(out)} items\n")
    return out


def pick(ds, suffix):
    for k, v in ds.items():
        if k.endswith(suffix):
            return v
    raise SystemExit(f"datastream {suffix} not in --ds json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--disa", required=True); ap.add_argument("--ds", required=True); ap.add_argument("--items", required=True)
    ap.add_argument("--scan8"); ap.add_argument("--scan9")
    a = ap.parse_args()
    disa = load_disa(a.disa)
    ds = json.load(open(a.ds))
    r8, r9 = pick(ds, "ssg-rhel8-ds.xml"), pick(ds, "ssg-rhel9-ds.xml")
    s8, s9 = set(r8["profiles"][PROFILE]["selected"]), set(r9["profiles"][PROFILE]["selected"])
    res8 = {x["idref"]: x["result"] for x in json.load(open(a.scan8))} if a.scan8 else {}
    res9 = {x["idref"]: x["result"] for x in json.load(open(a.scan9))} if a.scan9 else {}

    w = csv.writer(sys.stdout)
    w.writerow(["item_id", "stig_vuln_id", "method", "stig_id", "rhel8_rule", "rhel8_in_stig_profile",
                "rhel8_result", "rhel9_rule_exists", "rhel9_in_stig_profile", "rhel9_result", "note"])
    for it in csv.DictReader(open(a.items, encoding="utf-8-sig")):
        v = (it.get("stig_vuln_id") or "").strip()
        d = disa.get(v)
        rules, method, note = [], "", ""
        if d:
            by_id = [k for k, r in r8["rules"].items() if any(val == d["stig_id"] for _, val in r["refs"])]
            by_sv = [k for k, r in r8["rules"].items()
                     if any(val.startswith("SV-") and val.split("r")[0] == "SV-" + v[2:] for _, val in r["refs"])]
            rules, method = by_id or by_sv, "STIG ID"
            if sorted(by_id) != sorted(by_sv):
                note = f"STIG-ID path {by_id} != SV path {by_sv}"
        if not rules:
            kws = [k.strip().lower() for k in (it.get("title_keywords") or "").split("|") if k.strip()]
            rules = [k for k, r in r8["rules"].items() if kws and all(kw in r["title"].lower() for kw in kws)]
            method = "title keywords (confirm manually)"
            note = (f"{v} not in DISA file; " if v else "no Vuln ID; ") + note
        short = [x.replace(P, "") for x in rules]
        w.writerow([it["item_id"], v, method, (d or {}).get("stig_id", ""), ";".join(short),
                    ";".join("Y" if x in s8 else "N" for x in rules),
                    ";".join(res8.get(x, "") for x in rules),
                    ";".join("Y" if x in r9["rules"] else "N" for x in rules),
                    ";".join("Y" if x in s9 else "N" for x in rules),
                    ";".join(res9.get(x, "") for x in rules), note])


if __name__ == "__main__":
    main()
