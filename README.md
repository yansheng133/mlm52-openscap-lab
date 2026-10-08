# mlm52-openscap-lab

實測 SUSE Multi-Linux Manager（MLM）5.2 的合規相關功能時用到的腳本與工具：讓雲端 RHEL 用戶端經反向 SSH 通道註冊到一台不對外開放的 MLM、把帶 DISA STIG Vuln ID 的組態基準對到 SSG 規則、產生只含指定規則的 tailoring、經 API 排定（定時）OpenSCAP 掃描並檢查結果。

實測結果與完整說明：https://hackmd.io/@yansheng133/Hk1iJR4ozg

> 驗證環境：MLM 5.2.0（podman，aarch64 主機）、RHEL 8.10 與 RHEL 9.8（AWS 隨用量計費 AMI）、scap-security-guide-redhat 0.1.79、openscap 1.3.14、DISA RHEL 8 STIG V2R8。
> 文中與範例的位址都是文件用位址（RFC 5737）。

## 內容

| 路徑 | 用途 |
|---|---|
| `scripts/aws-create.sh` | 建兩台 RHEL 用戶端（t3.medium、20 GB gp3、EIP），所有資源加 `Project` 標籤；安全群組只開 22 給你的 IP |
| `scripts/client-prep.sh` | 在用戶端設定：主機名稱、允許一般帳號綁 443、把 MLM FQDN 指到 127.0.0.1 |
| `scripts/tunnel.sh` | 工作站對用戶端開反向通道（4505／4506／443），斷線 10 秒後自動重連 |
| `scripts/verify-tunnel.sh` | 在用戶端確認三個監聽存在、TLS 名稱對得上（不加 `-k`） |
| `tools/mlmapi.py` | 只用標準函式庫的 MLM JSON API 客戶端；帳密從檔案讀，不進指令列 |
| `tools/ds_extract.py` | 在用戶端抽出 SSG datastream 的規則、reference、profile 選取清單 |
| `tools/stig_map.py` | Vuln ID → DISA STIG ID／SV Rule ID → SSG 規則；已移除的 Vuln ID 改用標題關鍵字找候選 |
| `tools/make_tailoring.py` | 產生 `autotailor` 的 JSON：以 STIG 為基底，只保留指定規則 |
| `tools/schedule_scan.py` | 經 API 對系統群組排定（可指定時間、可帶 tailoring）掃描 |
| `tools/scan_results.py` | 列出掃描、統計規則結果、檢查 tailoring 是否生效 |
| `examples/items-sample.csv` | 16 條範例基準（公開的 DISA STIG 條目） |
| `examples/lab-chrony-state.sls` | 測 Recurring Action test mode 用的 state |

## 流程

```bash
# 1. 建用戶端（參數見腳本開頭）
AWS_PROFILE=... AWS_REGION=... VPC_ID=... SUBNET_ID=... MY_IP=203.0.113.5/32 \
AMI_RHEL8=ami-... AMI_RHEL9=ami-... bash scripts/aws-create.sh

# 2. 在每台用戶端
sudo bash client-prep.sh lab-rhel8 mlm.example.com

# 3. 在工作站，每台各開一個視窗
MLM_IP=192.0.2.10 SSH_KEY=~/.ssh/lab-mlm-key caffeinate -i bash scripts/tunnel.sh 198.51.100.11

# 4. 在用戶端確認，再用 MLM 的 bootstrap script 註冊（經通道下載）
bash verify-tunnel.sh mlm.example.com /tmp/RHN-ORG-TRUSTED-SSL-CERT
curl -Ss --cacert /tmp/RHN-ORG-TRUSTED-SSL-CERT -o /tmp/bootstrap.sh https://mlm.example.com/pub/bootstrap/bootstrap.sh
sudo ACTIVATION_KEYS=1-lab-rhel8 bash /tmp/bootstrap.sh

# 5. 對照與 tailoring
/usr/libexec/platform-python ds_extract.py /usr/share/xml/scap/ssg/content/ssg-rhel{8,9}-ds.xml > ds.json   # 用戶端
python3 tools/stig_map.py --disa U_RHEL_8_STIG_V2R8_Manual-xccdf.xml --ds ds.json --items examples/items-sample.csv > map.csv
python3 tools/make_tailoring.py --ds ds.json --rules map.csv --var var_password_pam_remember=8 > t.json
autotailor -j t.json -o /opt/lab-scap/tailoring.xml /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml          # 用戶端

# 6. 排掃描並檢查
export MLM_FQDN=mlm.example.com MLM_HOST=192.0.2.10 MLM_CA=./RHN-ORG-TRUSTED-SSL-CERT MLM_CRED_FILE=./mlm-cred
python3 tools/schedule_scan.py --group lab-group --at 02:30 \
  --profile xccdf_org.ssgproject.content_profile_lab_selected --tailoring /opt/lab-scap/tailoring.xml
python3 tools/scan_results.py <sid> <xid>
```

`MLM_CRED_FILE` 的格式是兩行 `user name: ...`、`password: ...`，權限設 600，不要放進 repo（`.gitignore` 是白名單，預設什麼都不收）。

## 實測時踩到的坑

- **Client Tools 不能單獨加**：它掛在「RHEL and Liberty 8/9 Base」底下。Base 只會建空的父通道，不會同步 RHEL 套件。
- **註冊後 RHUI 套件庫會被停用**：把系統 pillar `mgr_disable_local_repos` 設為 `False`，再把套件庫開回來。
- **`mgr-create-bootstrap-repo` 要用 `LC_ALL=C.UTF-8`**：用 `LC_ALL=C` 會噴 `UnicodeDecodeError`。
- **用 `dnf` 自己裝 openscap 之後，要先更新套件清單**，Web UI 才會出現排掃描的表單。
- **`system.getScriptResults` 要用 POST**：用 GET 會回 HTTP 403。
- **掃描參數只有 `oscapParams` 這個拼法有效**，`oscapPrams` 會被拒絕。
- **斷線時動作不會卡住**：MLM 約 4 秒內就判定 Failed（「Minion is down」）。
- **`autotailor` 一定要指定 base profile。**
- **自簽 CA 會被 Python 3.13 以後的版本拒絕**：因為 Basic Constraints 沒標 critical。`mlmapi.py` 只關掉嚴格模式這一項檢查。

## 授權

Apache License 2.0
