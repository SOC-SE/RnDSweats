# CCDC Persistence Hunter State
# Scans for and reports common persistence mechanisms
# Compatible with: Ubuntu, Debian, RHEL, Fedora, CentOS, Oracle Linux, Devuan

# Create output directory
/var/log/ccdc-persistence:
  file.directory:
    - user: root
    - group: root
    - mode: 700
    - makedirs: True

# Scan crontabs
scan-crontabs:
  cmd.run:
    - name: |
        echo "=== System Crontabs ===" > /var/log/ccdc-persistence/crontabs.log
        echo "--- /etc/crontab ---" >> /var/log/ccdc-persistence/crontabs.log
        cat /etc/crontab 2>/dev/null >> /var/log/ccdc-persistence/crontabs.log
        echo "" >> /var/log/ccdc-persistence/crontabs.log
        echo "--- /etc/cron.d/* ---" >> /var/log/ccdc-persistence/crontabs.log
        ls -la /etc/cron.d/ 2>/dev/null >> /var/log/ccdc-persistence/crontabs.log
        for f in /etc/cron.d/*; do echo "==$f==" >> /var/log/ccdc-persistence/crontabs.log; cat "$f" 2>/dev/null >> /var/log/ccdc-persistence/crontabs.log; done
        echo "" >> /var/log/ccdc-persistence/crontabs.log
        echo "--- User Crontabs ---" >> /var/log/ccdc-persistence/crontabs.log
        for user in $(cut -d: -f1 /etc/passwd); do
          crontab -u "$user" -l 2>/dev/null && echo "^^^ $user crontab ^^^" >> /var/log/ccdc-persistence/crontabs.log
        done
        echo "--- /etc/cron.{hourly,daily,weekly,monthly} ---" >> /var/log/ccdc-persistence/crontabs.log
        ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null >> /var/log/ccdc-persistence/crontabs.log
    - shell: /bin/bash

# Scan systemd services and timers
scan-systemd:
  cmd.run:
    - name: |
        echo "=== Enabled Systemd Services ===" > /var/log/ccdc-persistence/systemd.log
        systemctl list-unit-files --type=service --state=enabled 2>/dev/null >> /var/log/ccdc-persistence/systemd.log
        echo "" >> /var/log/ccdc-persistence/systemd.log
        echo "=== Running Services ===" >> /var/log/ccdc-persistence/systemd.log
        systemctl list-units --type=service --state=running 2>/dev/null >> /var/log/ccdc-persistence/systemd.log
        echo "" >> /var/log/ccdc-persistence/systemd.log
        echo "=== User Services ===" >> /var/log/ccdc-persistence/systemd.log
        find /home -name "*.service" 2>/dev/null >> /var/log/ccdc-persistence/systemd.log
        find /etc/systemd/system -name "*.service" -newer /var/log/installer 2>/dev/null >> /var/log/ccdc-persistence/systemd.log || true
        echo "" >> /var/log/ccdc-persistence/systemd.log
        echo "=== Timers ===" >> /var/log/ccdc-persistence/systemd.log
        systemctl list-timers --all 2>/dev/null >> /var/log/ccdc-persistence/systemd.log
    - shell: /bin/bash
    - onlyif: which systemctl

# Scan init.d (for non-systemd systems like Devuan)
scan-initd:
  cmd.run:
    - name: |
        echo "=== Init.d Services ===" > /var/log/ccdc-persistence/initd.log
        ls -la /etc/init.d/ 2>/dev/null >> /var/log/ccdc-persistence/initd.log
        echo "" >> /var/log/ccdc-persistence/initd.log
        echo "=== RC Symlinks ===" >> /var/log/ccdc-persistence/initd.log
        ls -la /etc/rc*.d/ 2>/dev/null >> /var/log/ccdc-persistence/initd.log
    - shell: /bin/bash

# Scan SSH authorized_keys
scan-ssh-keys:
  cmd.run:
    - name: |
        echo "=== SSH Authorized Keys ===" > /var/log/ccdc-persistence/ssh-keys.log
        for home in /root /home/*; do
          if [ -f "$home/.ssh/authorized_keys" ]; then
            echo "--- $home/.ssh/authorized_keys ---" >> /var/log/ccdc-persistence/ssh-keys.log
            cat "$home/.ssh/authorized_keys" >> /var/log/ccdc-persistence/ssh-keys.log
            echo "" >> /var/log/ccdc-persistence/ssh-keys.log
          fi
        done
        echo "=== SSH Keys in /etc ===" >> /var/log/ccdc-persistence/ssh-keys.log
        find /etc -name "authorized_keys" -o -name "*.pub" 2>/dev/null >> /var/log/ccdc-persistence/ssh-keys.log
    - shell: /bin/bash

# Scan bashrc/profile files
scan-shell-configs:
  cmd.run:
    - name: |
        echo "=== Shell Config Files ===" > /var/log/ccdc-persistence/shell-configs.log
        for file in /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
          if [ -f "$file" ]; then
            echo "--- $file ($(stat -c%Y "$file" | xargs -I{} date -d @{})) ---" >> /var/log/ccdc-persistence/shell-configs.log
          fi
        done
        echo "" >> /var/log/ccdc-persistence/shell-configs.log
        echo "=== User RC Files ===" >> /var/log/ccdc-persistence/shell-configs.log
        for home in /root /home/*; do
          for rc in .bashrc .bash_profile .profile .zshrc; do
            if [ -f "$home/$rc" ]; then
              echo "--- $home/$rc ---" >> /var/log/ccdc-persistence/shell-configs.log
              grep -E '(curl|wget|nc|bash|sh|python|perl|ruby|exec|eval|source)' "$home/$rc" 2>/dev/null >> /var/log/ccdc-persistence/shell-configs.log
            fi
          done
        done
    - shell: /bin/bash

# Scan for suspicious SUID/SGID binaries
scan-suid:
  cmd.run:
    - name: |
        echo "=== SUID Binaries ===" > /var/log/ccdc-persistence/suid.log
        find / -perm -4000 -type f 2>/dev/null >> /var/log/ccdc-persistence/suid.log
        echo "" >> /var/log/ccdc-persistence/suid.log
        echo "=== SGID Binaries ===" >> /var/log/ccdc-persistence/suid.log
        find / -perm -2000 -type f 2>/dev/null >> /var/log/ccdc-persistence/suid.log
    - shell: /bin/bash

# Scan for network listeners
scan-network:
  cmd.run:
    - name: |
        echo "=== Listening Ports ===" > /var/log/ccdc-persistence/network.log
        ss -tulnp 2>/dev/null >> /var/log/ccdc-persistence/network.log || netstat -tulnp 2>/dev/null >> /var/log/ccdc-persistence/network.log
        echo "" >> /var/log/ccdc-persistence/network.log
        echo "=== Established Connections ===" >> /var/log/ccdc-persistence/network.log
        ss -tunp 2>/dev/null >> /var/log/ccdc-persistence/network.log || netstat -tunp 2>/dev/null >> /var/log/ccdc-persistence/network.log
    - shell: /bin/bash

# Scan for LD_PRELOAD and library hijacking
scan-ld-preload:
  cmd.run:
    - name: |
        echo "=== LD_PRELOAD Checks ===" > /var/log/ccdc-persistence/ld-preload.log
        echo "--- /etc/ld.so.preload ---" >> /var/log/ccdc-persistence/ld-preload.log
        cat /etc/ld.so.preload 2>/dev/null >> /var/log/ccdc-persistence/ld-preload.log || echo "(file not found)" >> /var/log/ccdc-persistence/ld-preload.log
        echo "" >> /var/log/ccdc-persistence/ld-preload.log
        echo "--- /etc/ld.so.conf.d/ ---" >> /var/log/ccdc-persistence/ld-preload.log
        cat /etc/ld.so.conf.d/* 2>/dev/null >> /var/log/ccdc-persistence/ld-preload.log
        echo "" >> /var/log/ccdc-persistence/ld-preload.log
        echo "--- Environment LD vars ---" >> /var/log/ccdc-persistence/ld-preload.log
        grep -r "LD_PRELOAD\|LD_LIBRARY_PATH" /etc/profile* /etc/bash* /etc/environment 2>/dev/null >> /var/log/ccdc-persistence/ld-preload.log
    - shell: /bin/bash

# Scan for kernel modules
scan-modules:
  cmd.run:
    - name: |
        echo "=== Loaded Kernel Modules ===" > /var/log/ccdc-persistence/modules.log
        lsmod >> /var/log/ccdc-persistence/modules.log
        echo "" >> /var/log/ccdc-persistence/modules.log
        echo "=== Module Autoload ===" >> /var/log/ccdc-persistence/modules.log
        cat /etc/modules 2>/dev/null >> /var/log/ccdc-persistence/modules.log
        ls -la /etc/modules-load.d/ 2>/dev/null >> /var/log/ccdc-persistence/modules.log
    - shell: /bin/bash

# Generate summary report
persistence-summary:
  cmd.run:
    - name: |
        echo "=== CCDC Persistence Hunt Summary ===" > /var/log/ccdc-persistence/SUMMARY.log
        echo "Generated: $(date)" >> /var/log/ccdc-persistence/SUMMARY.log
        echo "Host: $(hostname)" >> /var/log/ccdc-persistence/SUMMARY.log
        echo "" >> /var/log/ccdc-persistence/SUMMARY.log
        echo "Files generated in /var/log/ccdc-persistence/:" >> /var/log/ccdc-persistence/SUMMARY.log
        ls -la /var/log/ccdc-persistence/ >> /var/log/ccdc-persistence/SUMMARY.log
        echo "" >> /var/log/ccdc-persistence/SUMMARY.log
        echo "Review each file for suspicious entries!" >> /var/log/ccdc-persistence/SUMMARY.log
    - shell: /bin/bash
    - require:
      - cmd: scan-crontabs
      - cmd: scan-ssh-keys
      - cmd: scan-shell-configs
      - cmd: scan-suid
      - cmd: scan-network
