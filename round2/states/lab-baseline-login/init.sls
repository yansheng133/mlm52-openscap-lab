# lab-baseline-login：基準中登入／權限相關項目的修正（最後才套用，先留救援用的 SSH 連線）
# 刻意避開：chage（不改既有帳號的密碼期限）、不移除 ec2-user 的 NOPASSWD、不直接手改 authselect 管理的 PAM 檔

# ITEM-12 sudoers_validate_passwd：要求以「使用者自己的密碼」驗證，不改既有 NOPASSWD 規則
lab_item_12_sudoers_validate_passwd:
  file.managed:
    - name: /etc/sudoers.d/lab-item-12
    - contents: |
        # managed by MLM state channel lab-baseline-login (ITEM-12)
        Defaults !targetpw
        Defaults !rootpw
        Defaults !runaspw
    - user: root
    - group: root
    - mode: '0440'
    - check_cmd: /usr/sbin/visudo -cf

# ITEM-13 no_empty_passwords：用 authselect 拿掉 nullok（不直接改 PAM 檔）
# ITEM-15 密碼歷程：authselect 開 with-pwhistory，remember 寫在 /etc/security/pwhistory.conf
{% set want = ['without-nullok', 'with-pwhistory'] %}
{% for feat in want %}
lab_authselect_{{ feat }}:
  cmd.run:
    - name: authselect enable-feature {{ feat }}
    - unless: authselect current | grep -qx -- '- {{ feat }}'
{% endfor %}

lab_item_15_pwhistory_remember:
  file.replace:
    - name: /etc/security/pwhistory.conf
    - pattern: '^\s*#?\s*remember\s*=.*$'
    - repl: 'remember = 8'
    - append_if_not_found: True
    - require:
      - cmd: lab_authselect_with-pwhistory

# ITEM-16 accounts_maximum_age_login_defs：只改 login.defs（只影響之後新建的帳號），不對既有帳號跑 chage
lab_item_16_pass_max_days:
  file.replace:
    - name: /etc/login.defs
    - pattern: '^\s*PASS_MAX_DAYS\s+.*$'
    - repl: 'PASS_MAX_DAYS	90'
    - append_if_not_found: True
