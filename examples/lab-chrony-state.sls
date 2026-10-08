# lab-chrony-state: chrony client-only (port 0) and no network management (cmdport 0)
lab_chrony_port0:
  file.replace:
    - name: /etc/chrony.conf
    - pattern: '^\s*#?\s*port\s+.*$'
    - repl: 'port 0'
    - append_if_not_found: True

lab_chrony_cmdport0:
  file.replace:
    - name: /etc/chrony.conf
    - pattern: '^\s*#?\s*cmdport\s+.*$'
    - repl: 'cmdport 0'
    - append_if_not_found: True
