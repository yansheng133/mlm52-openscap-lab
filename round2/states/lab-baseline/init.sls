# lab-baseline：基準中非登入相關項目的修正
# 只改設定檔，不跑 chage／authselect，不碰 PAM、sudoers、sshd。
# 對應 SSG 0.1.80 規則：見每段註解。

# ITEM-02 auditd_name_format（var_auditd_name_format：STIG 允許 hostname）
lab_item_02_auditd_name_format:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*name_format\s*=.*$'
    - repl: 'name_format = hostname'
    - append_if_not_found: True

# ITEM-03 auditd_data_retention_space_left_percentage（剩 25% 時動作＝用量 75%）
lab_item_03_auditd_space_left:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*space_left\s*=.*$'
    - repl: 'space_left = 25%'
    - append_if_not_found: True

lab_auditd_restart:
  cmd.run:
    # RHEL 的 auditd 不接受 systemctl restart，要用 service
    - name: service auditd restart
    - onchanges:
      - file: lab_item_02_auditd_name_format
      - file: lab_item_03_auditd_space_left

# ITEM-04 chronyd_client_only
lab_item_04_chrony_port0:
  file.replace:
    - name: /etc/chrony.conf
    - pattern: '^\s*port\s+\S+.*$'
    - repl: 'port 0'
    - append_if_not_found: True

# ITEM-05 chronyd_no_chronyc_network
lab_item_05_chrony_cmdport0:
  file.replace:
    - name: /etc/chrony.conf
    - pattern: '^\s*cmdport\s+\S+.*$'
    - repl: 'cmdport 0'
    - append_if_not_found: True

lab_chronyd_restart:
  service.running:
    - name: chronyd
    - watch:
      - file: lab_item_04_chrony_port0
      - file: lab_item_05_chrony_cmdport0

# ITEM-07／08／09 kernel_module_{uvcvideo,firewire-core,bluetooth}_disabled
{% for mod in ['uvcvideo', 'firewire-core', 'bluetooth'] %}
lab_item_module_{{ mod }}:
  file.managed:
    - name: /etc/modprobe.d/{{ mod }}.conf
    - contents: |
        # managed by MLM state channel lab-baseline
        install {{ mod }} /bin/false
        blacklist {{ mod }}
    - user: root
    - group: root
    - mode: '0644'
{% endfor %}

# ITEM-10 disable_ctrlaltdel_reboot
# AMI 在 /etc/systemd/system 已有指向 reboot.target 的連結，systemctl mask 會因檔案已存在失敗，所以直接改連結
lab_item_10_ctrlaltdel_masked:
  file.symlink:
    - name: /etc/systemd/system/ctrl-alt-del.target
    - target: /dev/null
    - force: True

# ITEM-11 disable_ctrlaltdel_burstaction
lab_item_11_ctrlaltdel_burst:
  file.replace:
    - name: /etc/systemd/system.conf
    - pattern: '^\s*#?\s*CtrlAltDelBurstAction\s*=.*$'
    - repl: 'CtrlAltDelBurstAction=none'
    - append_if_not_found: True

lab_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: lab_item_10_ctrlaltdel_masked
      - file: lab_item_11_ctrlaltdel_burst
