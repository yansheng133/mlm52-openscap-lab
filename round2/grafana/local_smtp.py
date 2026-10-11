#!/usr/bin/env python3
"""只收不轉的本機收信程式（Python 3.6 內建 smtpd，不需安裝套件）。
綁定 127.0.0.1:2525（Grafana 容器用 host network，只有本機連得到），每封信存成 /tmp/lab-mail/<時間>.eml。
用法（在 MLM 主機以一般使用者執行）：nohup python3 local_smtp.py >/tmp/lab-smtp.log 2>&1 &"""
import asyncore, datetime, os, smtpd
OUT = "/tmp/lab-mail"
os.makedirs(OUT, exist_ok=True)
class Sink(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kw):
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S.%fZ")
        with open(os.path.join(OUT, ts + ".eml"), "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        print(ts, "from", mailfrom, "to", rcpttos, "bytes", len(data), flush=True)
        return None  # 收下，不轉寄
Sink(("127.0.0.1", 2525), None, decode_data=False)
print(datetime.datetime.utcnow().isoformat(), "listening 127.0.0.1:2525", flush=True)
asyncore.loop()
