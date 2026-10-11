# 第二輪：修正閉環、漂移、盤點、Grafana 告警

第二輪實測用到的工具。實測結果與完整說明：https://hackmd.io/@yansheng133/ryy9fctoGg

> 驗證環境：MLM 5.2.0（podman，aarch64 主機）、RHEL 8.10 與 RHEL 9.8（AWS 隨用量計費 AMI，UEFI 開機）、scap-security-guide-redhat 0.1.80、openscap 1.3.14、Grafana 13.2.3 開源版。
> 文中與範例的位址都是文件用位址（RFC 5737）。範例基準沿用第一輪的 16 條公開 DISA STIG 條目（`ITEM-01`～`ITEM-16`）。

## 內容

| 路徑 | 用途 |
|---|---|
| `tools/make_tailoring.py` | 第一輪產生器的改良版，直接在用戶端產生 tailoring XML。**會自動重新選回被 STIG profile 取消選取的上層群組，並加入規則的 `requires` 相依**；不處理這兩件事，tailoring 選了的規則會無聲地變成 notselected |
| `tools/ds_lookup.py` | 在用戶端查 datastream：規則存不存在、標題、在不在 STIG profile、變數有哪些選項 |
| `tools/inventory_report.py` | 從 MLM API 撈群組內每台主機最新一次掃描，輸出「主機 × 項目 × 規則 × 結果」的 CSV、HTML 與不合規清單 |
| `examples/items-rules.csv` | 16 條範例項目對到的 SSG 規則（RHEL 8） |
| `states/lab-baseline/` | 非登入相關項目的 Salt state（auditd、chrony、核心模組、Ctrl-Alt-Del），可放進 MLM state channel |
| `states/lab-baseline-login/` | 登入相關項目（sudoers、authselect 的 `without-nullok`／`with-pwhistory`、密碼期限）。**最後才套用，套用前先開一條保持不關的 SSH 連線當救援通道** |
| `states/_grains/lab_accounts.py` | 回報本機帳號清單的自訂 grain（不讀 `/etc/shadow`；minion ID 不是 `lab-` 開頭就回傳空值） |
| `sql/cve_severity.sql` | 報表資料庫：主機 × advisory × 嚴重度 × CVE |
| `grafana/compliance-dashboard.json` | Grafana 儀表板（各主機合規率、不合規清單、每項不符合主機數、漏洞統計、資料新舊） |
| `grafana/local_smtp.py` | 只收不轉的本機 SMTP（Python 3.6 內建 `smtpd`），測告警寄信用 |

## 用法

```bash
# 1. 在用戶端產生 tailoring（輸出會列出 reselected_groups 與 added_requires）
python3 make_tailoring.py --ds /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml --base stig \
  --id lab_selected --title "lab selected rules" --rules rules.txt \
  --var var_password_pam_remember=8 --var var_accounts_maximum_age_login_defs=90 \
  --out /opt/lab-scap/lab-tailoring-rhel8.xml
#    rules.txt：每行一個規則短名，例如 chronyd_client_only

# 2. 掃完後一定要檢查「選取數＝評估數」（第一輪的 tools/scan_results.py 會列出 notselected 的數量）

# 3. 盤點報告
python3 tools/inventory_report.py --ip 192.0.2.10 --fqdn mlm.example.com \
  --cred ./mlm-cred --ca ./RHN-ORG-TRUSTED-SSL-CERT \
  --mapping examples/items-rules.csv --group lab-group --out-prefix out/report
```

Grafana 儀表板：匯入 `grafana/compliance-dashboard.json` 前，把 `${DS_REPORTDB}` 換成你連到 MLM 報表資料庫的 PostgreSQL 資料來源 UID。SQL 裡的 profile 是 `xccdf_org.ssgproject.content_profile_lab_selected`，項目與規則的對照寫在每個查詢的 `map(item, rule)`，換基準時要一起改。報表資料庫預設每天才同步一次，所以儀表板不是即時的。

`mlm-cred` 的格式是兩行 `user name: ...`、`password: ...`，權限設 600，不要放進 repo。

## 第二輪踩到的坑

- **STIG profile 會整個群組取消選取**（例：`permissions_important_account_files`、`cron_and_at`、`uefi`），規則還有 `requires` 相依。兩者都會讓 tailoring 選了的規則無聲地不被評估。
- **用戶端更新 `scap-security-guide-redhat` 後，profile 內容會變**（0.1.79 → 0.1.80，RHEL 8 STIG 從 404 條變成 391 條）。tailoring 要重新產生，選取數要重新檢查。
- **完整 STIG 會把 MLM 通道下載 token 寫進掃描報告**，元兇是 `enable_gpgcheck_for_all_repositories`。關掉 detailed upload 沒有用，要在 tailoring 拿掉這一條。
- **換頻道（含 Content Lifecycle 切換）會清掉系統的 `custom_info` pillar**，`mgr_disable_local_repos: False` 跟著消失，RHUI 會被停用。
- **highstate 和 `system.config.deployAll` 會無聲地把組態頻道管理的檔案蓋回去**。
- **SSG 產生的 bash 修正腳本不完全冪等**：`disable_ctrlaltdel_burstaction` 每跑一次就多寫兩行。中間一條失敗時，整支腳本仍回傳 0。
- **AMI 已經有 `ctrl-alt-del.target → reboot.target` 的連結**，`systemctl mask` 會失敗，所以 state 改用 `file.symlink` 加 `force`。
- **RHEL 的 auditd 不接受 `systemctl restart`**，要用 `service auditd restart`。
- **MLM API 的 HTTP 方法**：讀取類多為 GET、寫入類 POST，用錯會回 403。每個方法用哪個，以 MLM 內建的 `/rhn/apidoc/handlers/*.jsp` 為準。
