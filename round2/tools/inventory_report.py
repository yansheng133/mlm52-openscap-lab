#!/usr/bin/env python3
"""基準盤點報告產生器（原型）。

從 MLM API 取指定系統群組內每台主機「最新一次、profile 為 lab_selected」的 OpenSCAP 掃描結果，
用對照表（項目 ID ↔ SSG 規則 idref）把規則結果對回項目編號，產出：
  1. CSV：主機、OS、項目 ID、項目標題、規則 idref、規則結果、項目判定、掃描時間、xid
  2. 一頁 HTML：每台合規率、fail 清單、掃描時間
  3. 不符規清單（純文字，模擬寄給管理者的內容；本程式不寄信）

項目判定規則（一條項目對多條規則時，例如 ITEM-15）：
  - 任一條規則 fail／error／unknown → 不符合
  - 其餘至少一條 pass → 符合（pass 與 notapplicable 混合仍算符合）
  - 全部 notapplicable → 不適用（不列入合規率分母）
  - 找不到結果（notselected 或沒有該規則）→ 未檢查（列入分母、視為不符合，避免漏掃被當成合規）
合規率＝符合的項目數 ÷（項目總數 − 不適用數）。

帳密：從 --cred 指定的檔案讀取（兩行「user name: …」「password: …」，權限 600），只在記憶體，不寫入任何檔案。
TLS：用 MLM CA 驗證伺服器憑證與主機名稱（只放寬 Python 3.13+ 的 VERIFY_X509_STRICT：自簽 CA 的 Basic Constraints 沒標 critical）。

用法：
  python3 inventory_report.py --ip 192.0.2.10 --fqdn mlm.example.com --cred ./mlm-cred --ca ./RHN-ORG-TRUSTED-SSL-CERT \
      --mapping ../examples/items-rules.csv --group lab-group --out-prefix out/report
產出：<out-prefix>.csv、<out-prefix>.html、<out-prefix>-noncompliant.txt
"""
import argparse, csv, datetime, html, http.client, json, re, socket, ssl, sys
from urllib.parse import urlencode

PROFILE = "xccdf_org.ssgproject.content_profile_lab_selected"
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
BAD = {"fail", "error", "unknown"}


class Mlm:
    def __init__(self, ip, fqdn, ca, cred_file):
        self.ip, self.fqdn, self.cookie = ip, fqdn, None
        self.ctx = ssl.create_default_context(cafile=ca)
        self.ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        cred = {}
        for line in open(cred_file, encoding="utf-8"):
            k, _, v = line.partition(":")
            cred[k.strip().lower()] = v.strip()
        self.post("auth.login", login=cred["user name"], password=cred["password"])
        cred.clear()

    def _req(self, verb, method, kw):
        sock = socket.create_connection((self.ip, 443), 60)
        c = http.client.HTTPSConnection(self.fqdn, 443, context=self.ctx, timeout=120)
        c.sock = self.ctx.wrap_socket(sock, server_hostname=self.fqdn)
        url = "/rhn/manager/api/" + method.replace(".", "/")
        h, body = {"Host": self.fqdn}, None
        if verb == "GET" and kw:
            url += "?" + urlencode(kw)
        elif verb == "POST":
            h["Content-Type"], body = "application/json", json.dumps(kw)
        if self.cookie:
            h["Cookie"] = self.cookie
        c.request(verb, url, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie" and v.startswith("pxt-session-cookie=") and not v.startswith("pxt-session-cookie=;"):
                self.cookie = v.split(";")[0]
        if r.status != 200:
            raise RuntimeError(f"{method}: HTTP {r.status}")
        d = json.loads(data)
        if not d.get("success", True):
            raise RuntimeError(f"{method}: {d.get('message')}")
        return d.get("result")

    def get(self, method, **kw):
        return self._req("GET", method, kw)

    def post(self, method, **kw):
        return self._req("POST", method, kw)

    def logout(self):
        try:
            self.post("auth.logout")
        except Exception:
            pass


def load_mapping(path):
    """回傳 [(item_id, title, [rule, ...])]；CSV 欄位 item_id,title,rules（rules 以分號分隔）。"""
    out = []
    with open(path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            rules = [r.strip() for r in row["rules"].split(";") if r.strip()]
            out.append((row["item_id"], row.get("title", ""), rules))
    return out


def item_verdict(results):
    vals = list(results.values())
    if any(v is None or v == "notselected" for v in vals):
        return "未檢查"
    if any(v in BAD for v in vals):
        return "不符合"
    if all(v == "notapplicable" for v in vals):
        return "不適用"
    if any(v == "pass" for v in vals):
        return "符合"
    return "不符合"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.0.2.10")
    ap.add_argument("--fqdn", default="mlm.example.com")
    ap.add_argument("--ca", required=True)
    ap.add_argument("--cred", required=True)
    ap.add_argument("--mapping", required=True)
    ap.add_argument("--group", required=True)
    ap.add_argument("--profile", default=PROFILE)
    ap.add_argument("--out-prefix", required=True)
    a = ap.parse_args()

    mapping = load_mapping(a.mapping)
    titles = {i: title for i, title, _ in mapping}

    m = Mlm(a.ip, a.fqdn, a.ca, a.cred)
    hosts, rows = [], []
    try:
        for s in sorted(m.get("systemgroup.listSystemsMinimal", systemGroupName=a.group), key=lambda x: x["name"]):
            sid, name = s["id"], s["name"]
            det = m.get("system.getDetails", sid=sid)
            os_name = f"{det.get('os', '') or ''} {det.get('release', '')}".strip() or "-"
            scans = [x for x in m.get("system.scap.listXccdfScans", sid=sid) if x.get("profile") == a.profile]
            if not scans:
                hosts.append({"name": name, "os": os_name, "xid": None, "time": None, "items": []})
                continue
            latest = max(scans, key=lambda x: x["xid"])
            xid = latest["xid"]
            d = m.get("system.scap.getXccdfScanDetails", xid=xid)
            when = d.get("end_time") or d.get("start_time")
            res = {r["idref"].replace(RULE_PREFIX, ""): r["result"] for r in m.get("system.scap.getXccdfScanRuleResults", xid=xid)}
            rule_counts = {}
            for v in res.values():
                if v != "notselected":
                    rule_counts[v] = rule_counts.get(v, 0) + 1
            items = []
            for item, note, rules in mapping:
                rr = {r: res.get(r) for r in rules}
                verdict = item_verdict(rr)
                items.append((item, verdict, rr))
                for r, v in rr.items():
                    rows.append({"主機": name, "OS": os_name, "項目 ID": item, "項目標題": titles.get(item, ""),
                                 "規則 idref": r, "規則結果": v or "（無結果）", "項目判定": verdict,
                                 "掃描時間(UTC)": when, "xid": xid})
            hosts.append({"name": name, "os": os_name, "xid": xid, "time": when, "items": items, "rule_counts": rule_counts})
    finally:
        m.logout()

    # 1. CSV
    with open(a.out_prefix + ".csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["主機", "OS", "項目 ID", "項目標題", "規則 idref", "規則結果", "項目判定", "掃描時間(UTC)", "xid"])
        w.writeheader()
        w.writerows(rows)

    # 合規率
    for h in hosts:
        v = [i[1] for i in h["items"]]
        denom = len(v) - v.count("不適用")
        h["ok"], h["denom"] = v.count("符合"), denom
        h["rate"] = (100.0 * v.count("符合") / denom) if denom else None
        h["fails"] = [i for i in h["items"] if i[1] in ("不符合", "未檢查")]

    gen = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    # 2. HTML
    e = html.escape
    parts = [f"<!doctype html><meta charset='utf-8'><title>基準盤點報告</title>",
             "<style>body{font-family:sans-serif;margin:24px;max-width:960px}table{border-collapse:collapse;margin:8px 0 20px}"
             "td,th{border:1px solid #bbb;padding:4px 8px;font-size:14px}th{background:#eee}.bad{color:#b00020}.ok{color:#1b5e20}</style>",
             f"<h1>基準合規盤點報告</h1><p>產生時間：{gen}　資料來源：MLM API（每台主機最新一次 {e(a.profile)} 掃描）　系統群組：{e(a.group)}</p>",
             "<p>判定規則：一條項目對多條 SSG 規則時，任一條 fail 即不符合；全部 notapplicable 為不適用（不計入分母）；沒有結果為未檢查（計為不符合）。</p>",
             "<h2>各主機合規率</h2><table><tr><th>主機</th><th>OS</th><th>掃描時間(UTC)</th><th>xid</th><th>項目符合／應檢查</th><th>合規率</th><th>規則層級 pass／fail</th></tr>"]
    for h in hosts:
        rc = h.get("rule_counts", {})
        rate = "-" if h["rate"] is None else f"{h['rate']:.1f}%"
        parts.append(f"<tr><td>{e(h['name'])}</td><td>{e(h['os'])}</td><td>{e(str(h['time']))}</td><td>{h['xid']}</td>"
                     f"<td>{h['ok']} / {h['denom']}</td><td>{rate}</td><td>{rc.get('pass', 0)} / {rc.get('fail', 0)}</td></tr>")
    parts.append("</table><h2>不符合清單</h2>")
    for h in hosts:
        parts.append(f"<h3>{e(h['name'])}（{len(h['fails'])} 項）</h3>")
        if not h["fails"]:
            parts.append("<p class='ok'>全部符合</p>")
            continue
        parts.append("<table><tr><th>項目 ID</th><th>判定</th><th>規則結果</th></tr>")
        for item, verdict, rr in h["fails"]:
            parts.append(f"<tr><td>{e(item)}</td><td class='bad'>{e(verdict)}</td><td>{e('; '.join(f'{k}={v}' for k, v in rr.items()))}</td></tr>")
        parts.append("</table>")
    open(a.out_prefix + ".html", "w", encoding="utf-8").write("\n".join(parts))

    # 3. 不符規清單（模擬通知內容，不寄出）
    lines = [f"主旨：[基準合規] {sum(1 for h in hosts if h['fails'])} 台主機有不符合項目（{gen}）", "",
             "以下為各主機最新一次基準掃描的不符合項目：", ""]
    for h in hosts:
        if not h["fails"]:
            continue
        rate = "-" if h["rate"] is None else f"{h['rate']:.1f}%"
        lines.append(f"■ {h['name']}（{h['os']}）掃描時間 {h['time']}　合規率 {rate}")
        for item, verdict, rr in h["fails"]:
            bad = ", ".join(k for k, v in rr.items() if v in BAD or v in (None, "notselected"))
            lines.append(f"   - {item}　{verdict}　規則：{bad}")
        lines.append("")
    open(a.out_prefix + "-noncompliant.txt", "w", encoding="utf-8").write("\n".join(lines))

    for h in hosts:
        rc = h.get("rule_counts", {})
        print(f"{h['name']}: xid={h['xid']} items {h['ok']}/{h['denom']} rate={h['rate']} rules pass={rc.get('pass', 0)} fail={rc.get('fail', 0)}")


if __name__ == "__main__":
    main()
