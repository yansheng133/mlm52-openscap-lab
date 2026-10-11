#!/usr/bin/env python3
"""在用戶端查 datastream：規則是否存在、標題、是否在 STIG profile；變數的選項值。輸出 JSON。
用法：python3 ds_lookup.py DS rules.txt vars.txt"""
import sys, json, xml.etree.ElementTree as ET
P = "xccdf_org.ssgproject.content_"; X = "{http://checklists.nist.gov/xccdf/1.2}"
ds, rf, vf = sys.argv[1:4]
root = ET.parse(ds).getroot()
rules = {r.get("id")[len(P+"rule_"):]: r for r in root.iter(X+"Rule")}
vals = {v.get("id")[len(P+"value_"):]: v for v in root.iter(X+"Value")}
stig = [p for p in root.iter(X+"Profile") if p.get("id") == P+"profile_stig"][0]
stig_sel = {s.get("idref")[len(P+"rule_"):] for s in stig.findall(X+"select") if s.get("selected") == "true"}
stig_vals = {s.get("idref")[len(P+"value_"):]: (s.text or "").strip() for s in stig.findall(X+"refine-value")+stig.findall(X+"set-value")}
out = {"rules": {}, "values": {}}
for name in [l.split("#")[0].strip() for l in open(rf) if l.split("#")[0].strip()]:
    r = rules.get(name)
    out["rules"][name] = None if r is None else {"title": (r.find(X+"title").text or "").strip(), "in_stig": name in stig_sel}
for name in [l.split("#")[0].strip() for l in open(vf) if l.split("#")[0].strip()]:
    v = vals.get(name)
    if v is None: out["values"][name] = None; continue
    opts = {(e.get("selector") or "default"): (e.text or "").strip() for e in v.findall(X+"value")}
    out["values"][name] = {"options": opts, "type": v.get("type"), "stig_refine": stig_vals.get(name)}
print(json.dumps(out, ensure_ascii=False, indent=1))
