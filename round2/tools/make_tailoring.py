#!/usr/bin/env python3
"""在用戶端產生「只選指定規則」的 tailoring 檔。

做法：讀 datastream 裡基底 profile 選取的全部規則 → 不在清單內的一律 evaluate:false，
清單內的一律 evaluate:true（基底 profile 沒有的也會被加進來）→ 交給 autotailor 產生 XCCDF tailoring。

用法（在用戶端執行）：
  python3 make_tailoring.py --ds DS --base stig --id lab_selected --title T --rules rules.txt \
      [--var name=value ...] --out out.xml
rules.txt：每行一個規則短名（不含 xccdf_org.ssgproject.content_rule_ 前綴），# 開頭為註解。
"""
import argparse, json, subprocess, sys, tempfile
import xml.etree.ElementTree as ET

P = "xccdf_org.ssgproject.content_"
NS = {"x": "http://checklists.nist.gov/xccdf/1.2"}

ap = argparse.ArgumentParser()
ap.add_argument("--ds", required=True)
ap.add_argument("--base", required=True)
ap.add_argument("--id", required=True)
ap.add_argument("--title", required=True)
ap.add_argument("--rules", required=True)
ap.add_argument("--var", action="append", default=[])
ap.add_argument("--out", required=True)
a = ap.parse_args()

want = [l.split("#")[0].strip() for l in open(a.rules) if l.split("#")[0].strip()]
root = ET.parse(a.ds).getroot()
X = "{%s}" % NS["x"]
rule_el = {r.get("id")[len(P + "rule_"):]: r for r in root.iter(X + "Rule")}
all_rules = set(rule_el)
parent = {c: p for p in root.iter() for c in p}
prof = [p for p in root.iter("{%s}Profile" % NS["x"]) if p.get("id") == P + "profile_" + a.base]
if not prof:
    sys.exit("base profile not found: " + a.base)
base_sel = {s.get("idref")[len(P + "rule_"):] for s in prof[0].findall("x:select", NS)
            if s.get("selected") == "true" and s.get("idref", "").startswith(P + "rule_")}

missing = [r for r in want if r not in all_rules]
if missing:
    sys.exit("rules not in datastream: " + ", ".join(missing))
# 規則的 requires 相依：被要求的規則沒選，這條也不會被評估 → 一併選入
added_requires = []
for r in list(want):
    for q in rule_el[r].findall(X + "requires"):
        dep = q.get("idref", "")[len(P + "rule_"):]
        if dep and dep in all_rules and dep not in want:
            want.append(dep); added_requires.append(f"{dep} (required by {r})")
# 基底 profile 取消選取的上層群組：群組沒選，裡面的規則也不會被評估 → 重新選回
prof_group_sel = {s.get("idref"): s.get("selected") for s in prof[0].findall("x:select", NS)
                  if s.get("idref", "").startswith(P + "group_")}
reselect_groups = []
for r in want:
    e = rule_el[r]
    while e in parent:
        e = parent[e]
        if e.tag == X + "Group" and (prof_group_sel.get(e.get("id")) == "false" or
                                     (e.get("id") not in prof_group_sel and e.get("selected") == "false")):
            if e.get("id") not in reselect_groups: reselect_groups.append(e.get("id"))

rules = {r: {"evaluate": False} for r in sorted(base_sel - set(want))}
rules.update({r: {"evaluate": True} for r in want})
variables = {}
for v in a.var:
    k, _, val = v.partition("=")
    variables[k] = {"value": val}
doc = {"profiles": [{"id": a.id, "title": a.title, "base_profile_id": a.base,
                     "rules": rules, "variables": variables}]}
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    json.dump(doc, f, indent=1)
    jpath = f.name
subprocess.run(["autotailor", "-j", jpath, "-o", a.out, a.ds], check=True)
if reselect_groups:
    txt = open(a.out, encoding="utf-8").read()
    i = txt.rfind('selected="'); i = txt.index(">", i) + 1
    ins = "".join(f'\n    <xccdf-1.2:select idref="{g}" selected="true"/>' for g in reselect_groups)
    open(a.out, "w", encoding="utf-8").write(txt[:i] + ins + txt[i:])
print(json.dumps({
    "ds": a.ds, "base_profile": a.base, "base_selected": len(base_sel), "wanted": len(want),
    "wanted_not_in_base": sorted(set(want) - base_sel), "deselected": len(base_sel - set(want)),
    "profile_id": P + "profile_" + a.id, "added_requires": added_requires,
    "reselected_groups": [g[len(P + "group_"):] for g in reselect_groups], "out": a.out, "json": jpath}, ensure_ascii=False, indent=1))
