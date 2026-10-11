# -*- coding: utf-8 -*-
"""lab_accounts：自訂 grain。只回報本機帳號的名稱、uid、gid、shell、家目錄，
以及 /etc/passwd、/etc/group 的修改時間。不讀 /etc/shadow，不碰任何密碼雜湊。
防護：minion ID 不是 lab- 開頭時回傳空 dict（避免同步到其他系統時產生任何資料）。"""
import os


def lab_accounts():
    mid = (__opts__.get("id") or "") if "__opts__" in globals() else ""
    if not mid.startswith("lab-"):
        return {}
    accounts = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                p = line.rstrip("\n").split(":")
                if len(p) >= 7 and not line.startswith("#"):
                    accounts.append({"name": p[0], "uid": int(p[2]), "gid": int(p[3]), "home": p[5], "shell": p[6]})
    except (IOError, OSError, ValueError):
        return {"lab_local_accounts_error": "cannot read /etc/passwd"}

    def mtime(path):
        try:
            return int(os.stat(path).st_mtime)
        except OSError:
            return None
    return {
        "lab_local_accounts": accounts,
        "lab_local_accounts_count": len(accounts),
        "lab_passwd_mtime": mtime("/etc/passwd"),
        "lab_group_mtime": mtime("/etc/group"),
    }
