# Auditd comprehensive monitoring - CCDC Edition
# Full ruleset based on Florian Roth's best practices + CCDC expansions
# Apply: salt '*' state.apply linux.security.auditd
#
# Sources:
#   - github.com/gds-operations/puppet-auditd
#   - github.com/linux-audit/audit-userspace
#   - CCDC-Development/linux/postHardenTools/dependencies/audit.rules

{% set os_family = grains['os_family'] %}

auditd_package:
  pkg.installed:
    {% if os_family == 'Debian' %}
    - name: auditd
    {% elif os_family == 'RedHat' %}
    - name: audit
    {% endif %}

auditd_rules_dir:
  file.directory:
    - name: /etc/audit/rules.d
    - require:
      - pkg: auditd_package

auditd_comprehensive_rules:
  file.managed:
    - name: /etc/audit/rules.d/99-saltgui-comprehensive.rules
    - contents: |
        ## Salt-GUI Comprehensive Audit Rules
        ## Based on Florian Roth's best practices, modified for CCDC
        ## WARNING: Do NOT set -e 2 (immutable) - Salt needs runtime auditctl access

        # Remove any existing rules
        -D

        # Buffer Size
        -b 8192

        # Failure Mode (1 = printk)
        -f 1

        # Ignore errors from missing files/users
        -i

        # Web Server Activity (www-data uid=33)
        -a always,exit -F arch=b64 -S execve -F euid=33 -k detect_execve_www

        # ====================================================================
        # Self Auditing
        # ====================================================================
        -w /var/log/audit/ -p wra -k auditlog
        -w /var/audit/ -p wra -k auditlog
        -w /etc/audit/ -p wa -k auditconfig
        -w /etc/libaudit.conf -p wa -k auditconfig
        -w /etc/audisp/ -p wa -k audispconfig
        -w /sbin/auditctl -p x -k audittools
        -w /sbin/auditd -p x -k audittools
        -w /usr/sbin/auditd -p x -k audittools
        -w /usr/sbin/augenrules -p x -k audittools
        -a always,exit -F path=/usr/sbin/ausearch -F perm=x -k audittools
        -a always,exit -F path=/usr/sbin/aureport -F perm=x -k audittools
        -a always,exit -F path=/usr/sbin/aulast -F perm=x -k audittools
        -a always,exit -F path=/usr/sbin/aulastlogin -F perm=x -k audittools
        -a always,exit -F path=/usr/sbin/auvirt -F perm=x -k audittools

        # ====================================================================
        # Filters (first match wins - put these early)
        # ====================================================================
        -a always,exclude -F msgtype=CWD
        -a never,user -F subj_type=crond_t
        -a never,exit -F subj_type=crond_t
        -a never,exit -F arch=b64 -S adjtimex -F auid=-1 -F uid=chrony -F subj_type=chronyd_t
        -a always,exclude -F msgtype=CRYPTO_KEY_USER
        -a exit,never -F arch=b64 -S all -F exe=/usr/bin/vmtoolsd

        ## Exclude Salt minion noise (high volume during normal operation)
        -a never,exit -F arch=b64 -F exe=/usr/bin/salt-minion -k salt_noise
        -a never,exit -F arch=b64 -F exe=/usr/bin/salt-call -k salt_noise

        # ====================================================================
        # Kernel
        # ====================================================================
        -w /etc/sysctl.conf -p wa -k sysctl
        -w /etc/sysctl.d -p wa -k sysctl
        -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k modules
        -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k modules
        -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k modules
        -a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
        -w /etc/modprobe.conf -p wa -k modprobe
        -w /etc/modprobe.d -p wa -k modprobe
        -a always,exit -F arch=b64 -S kexec_load -k KEXEC
        -a always,exit -F arch=b64 -S mknod -S mknodat -k specialfiles
        -a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount
        -a always,exit -F arch=b64 -S swapon -S swapoff -F auid!=-1 -k swap

        # ====================================================================
        # Time
        # ====================================================================
        -a always,exit -F arch=b64 -F uid!=ntp -S adjtimex -S settimeofday -S clock_settime -k time
        -w /etc/localtime -p wa -k localtime

        # ====================================================================
        # Cron & Scheduled Tasks
        # ====================================================================
        -w /etc/cron.allow -p wa -k cron
        -w /etc/cron.deny -p wa -k cron
        -w /etc/cron.d/ -p wa -k cron
        -w /etc/cron.daily/ -p wa -k cron
        -w /etc/cron.hourly/ -p wa -k cron
        -w /etc/cron.monthly/ -p wa -k cron
        -w /etc/cron.weekly/ -p wa -k cron
        -w /etc/crontab -p wa -k cron
        -w /var/spool/cron/ -p wa -k cron
        ## systemd timers (persistence via timer units)
        -w /etc/systemd/system/ -p wa -k systemd_persistence
        -w /usr/lib/systemd/system/ -p wa -k systemd_persistence
        -w /lib/systemd/system/ -p wa -k systemd_persistence
        -w /etc/systemd/user/ -p wa -k systemd_persistence

        # ====================================================================
        # User/Group/Password databases
        # ====================================================================
        -w /etc/group -p wa -k etcgroup
        -w /etc/passwd -p wa -k etcpasswd
        -w /etc/gshadow -k etcgroup
        -w /etc/shadow -k etcpasswd
        -w /etc/security/opasswd -k opasswd
        -w /etc/sudoers -p wa -k actions
        -w /etc/sudoers.d/ -p wa -k actions
        -w /usr/bin/passwd -p x -k passwd_modification
        -w /usr/sbin/groupadd -p x -k group_modification
        -w /usr/sbin/groupmod -p x -k group_modification
        -w /usr/sbin/addgroup -p x -k group_modification
        -w /usr/sbin/useradd -p x -k user_modification
        -w /usr/sbin/userdel -p x -k user_modification
        -w /usr/sbin/usermod -p x -k user_modification
        -w /usr/sbin/adduser -p x -k user_modification

        # ====================================================================
        # Login
        # ====================================================================
        -w /etc/login.defs -p wa -k login
        -w /etc/securetty -p wa -k login
        -w /var/log/faillog -p wa -k login
        -w /var/log/lastlog -p wa -k login
        -w /var/log/tallylog -p wa -k login

        # ====================================================================
        # Network
        # ====================================================================
        -a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
        -a always,exit -F arch=b64 -F exe=/bin/bash -F success=1 -S connect -k remote_shell
        -a always,exit -F arch=b64 -F exe=/usr/bin/bash -F success=1 -S connect -k remote_shell
        -a always,exit -F arch=b64 -S connect -F a2=16 -F success=1 -F key=network_connect_4
        -a always,exit -F arch=b64 -S connect -F a2=28 -F success=1 -F key=network_connect_6
        -w /etc/hosts -p wa -k network_modifications
        -w /etc/sysconfig/network -p wa -k network_modifications
        -w /etc/sysconfig/network-scripts -p w -k network_modifications
        -w /etc/network/ -p wa -k network
        -a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k network_modifications
        -w /etc/issue -p wa -k etcissue
        -w /etc/issue.net -p wa -k etcissue

        ## Raw/packet socket creation (BPFDoor, sniffers, raw socket backdoors)
        ## AF_PACKET=17, SOCK_RAW=3
        -a always,exit -F arch=b64 -S socket -F a0=17 -k raw_socket
        -a always,exit -F arch=b32 -S socket -F a0=17 -k raw_socket
        -a always,exit -F arch=b64 -S socket -F a1=3 -k raw_socket
        -a always,exit -F arch=b32 -S socket -F a1=3 -k raw_socket

        ## BPF syscall (eBPF programs, BPFDoor-style filters)
        -a always,exit -F arch=b64 -S bpf -k bpf_syscall
        -a always,exit -F arch=b32 -S bpf -k bpf_syscall

        ## setsockopt for SO_ATTACH_FILTER / SO_ATTACH_BPF (packet filters)
        -a always,exit -F arch=b64 -S setsockopt -k sockopt_filter

        # ====================================================================
        # System startup & libraries
        # ====================================================================
        -w /etc/inittab -p wa -k init
        -w /etc/init.d/ -p wa -k init
        -w /etc/init/ -p wa -k init
        -w /etc/ld.so.conf -p wa -k libpath
        -w /etc/ld.so.conf.d -p wa -k libpath
        -w /etc/ld.so.preload -p wa -k systemwide_preloads

        # ====================================================================
        # PAM
        # ====================================================================
        -w /etc/pam.d/ -p wa -k pam
        -w /etc/security/limits.conf -p wa -k pam
        -w /etc/security/limits.d -p wa -k pam
        -w /etc/security/pam_env.conf -p wa -k pam
        -w /etc/security/namespace.conf -p wa -k pam
        -w /etc/security/namespace.d -p wa -k pam
        -w /etc/security/namespace.init -p wa -k pam

        # ====================================================================
        # SSH
        # ====================================================================
        -w /etc/ssh/sshd_config -k sshd
        -w /etc/ssh/sshd_config.d -k sshd
        -w /root/.ssh -p wa -k rootkey
        ## Watch all authorized_keys files
        -w /home/ -p wa -k home_changes

        # ====================================================================
        # Mail
        # ====================================================================
        -w /etc/aliases -p wa -k mail
        -w /etc/postfix/ -p wa -k mail
        -w /etc/exim4/ -p wa -k mail

        # ====================================================================
        # Systemd
        # ====================================================================
        -w /bin/systemctl -p x -k systemd
        -w /etc/systemd/ -p wa -k systemd
        -w /usr/lib/systemd -p wa -k systemd
        -w /etc/systemd/system-generators/ -p wa -k systemd_generator
        -w /usr/local/lib/systemd/system-generators/ -p wa -k systemd_generator
        -w /usr/lib/systemd/system-generators -p wa -k systemd_generator
        -w /etc/systemd/user-generators/ -p wa -k systemd_generator
        -w /usr/local/lib/systemd/user-generators/ -p wa -k systemd_generator
        -w /lib/systemd/system-generators/ -p wa -k systemd_generator

        # ====================================================================
        # SELinux / AppArmor
        # ====================================================================
        -w /etc/selinux/ -p wa -k mac_policy
        -w /etc/apparmor/ -p wa -k mac_policy
        -w /etc/apparmor.d/ -p wa -k mac_policy

        # ====================================================================
        # Critical file access failures
        # ====================================================================
        -a always,exit -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileaccess

        # ====================================================================
        # Privilege escalation
        # ====================================================================
        -w /bin/su -p x -k priv_esc
        -w /usr/bin/sudo -p x -k priv_esc
        -w /usr/bin/pkexec -p x -k pkexec

        # ====================================================================
        # Power state
        # ====================================================================
        -w /sbin/shutdown -p x -k power
        -w /sbin/poweroff -p x -k power
        -w /sbin/reboot -p x -k power
        -w /sbin/halt -p x -k power

        # ====================================================================
        # Sessions
        # ====================================================================
        -w /var/run/utmp -p wa -k session
        -w /var/log/btmp -p wa -k session
        -w /var/log/wtmp -p wa -k session

        # ====================================================================
        # DAC modifications
        # ====================================================================
        -a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=-1 -k perm_mod
        -a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=-1 -k perm_mod

        # ====================================================================
        # Reconnaissance
        # ====================================================================
        -w /usr/bin/whoami -p x -k recon
        -w /usr/bin/id -p x -k recon
        -w /bin/hostname -p x -k recon
        -w /bin/uname -p x -k recon
        -w /etc/issue -p r -k recon
        -w /etc/hostname -p r -k recon

        # ====================================================================
        # Suspicious activity
        # ====================================================================
        -w /usr/bin/wget -p x -k susp_activity
        -w /usr/bin/curl -p x -k susp_activity
        -w /usr/bin/base64 -p x -k susp_activity
        -w /bin/nc -p x -k susp_activity
        -w /bin/netcat -p x -k susp_activity
        -w /usr/bin/ncat -p x -k susp_activity
        -w /bin/nc.openbsd -p x -k susp_activity
        -w /bin/nc.traditional -p x -k susp_activity
        -w /usr/bin/ss -p x -k susp_activity
        -w /usr/bin/netstat -p x -k susp_activity
        -w /usr/bin/ssh -p x -k susp_activity
        -w /usr/bin/scp -p x -k susp_activity
        -w /usr/bin/sftp -p x -k susp_activity
        -w /usr/bin/ftp -p x -k susp_activity
        -w /usr/bin/socat -p x -k susp_activity
        -w /usr/bin/wireshark -p x -k susp_activity
        -w /usr/bin/tshark -p x -k susp_activity
        -w /usr/bin/rawshark -p x -k susp_activity
        -w /usr/bin/nmap -p x -k susp_activity
        -w /usr/bin/rdesktop -p x -k susp_activity
        -w /usr/local/bin/rdesktop -p x -k susp_activity
        -w /usr/bin/xfreerdp -p x -k susp_activity
        -w /usr/local/bin/xfreerdp -p x -k susp_activity
        -w /usr/bin/stunnel -p x -k stunnel
        -w /usr/sbin/stunnel -p x -k stunnel

        ## Sbin suspicious
        -w /sbin/iptables -p x -k sbin_susp
        -w /sbin/ip6tables -p x -k sbin_susp
        -w /sbin/ifconfig -p x -k sbin_susp
        -w /usr/sbin/arptables -p x -k sbin_susp
        -w /usr/sbin/ebtables -p x -k sbin_susp
        -w /sbin/xtables-nft-multi -p x -k sbin_susp
        -w /usr/sbin/nft -p x -k sbin_susp
        -w /usr/sbin/tcpdump -p x -k sbin_susp
        -w /usr/sbin/traceroute -p x -k sbin_susp
        -w /usr/sbin/ufw -p x -k sbin_susp

        # ====================================================================
        # Injection & memory exploitation
        # ====================================================================
        -a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
        -a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
        -a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection
        -a always,exit -F arch=b64 -S ptrace -k tracing
        -a always,exit -F arch=b64 -S memfd_create -F key=anon_file_create

        ## Privilege abuse (root browsing user homes)
        -a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=-1 -C auid!=obj_uid -k power_abuse

        # ====================================================================
        # Execution from temp/world-writable directories
        # ====================================================================
        -a always,exit -F dir=/tmp -F perm=x -k tmp_exec
        -a always,exit -F dir=/dev/shm -F perm=x -k shm_exec
        -a always,exit -F dir=/var/tmp -F perm=x -k tmp_exec
        -a always,exit -F dir=/run/shm -F perm=x -k shm_exec

        # ====================================================================
        # Socket creation (IPv4 + IPv6)
        # ====================================================================
        -a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket_created
        -a always,exit -F arch=b32 -S socket -F a0=2 -k network_socket_created
        -a always,exit -F arch=b64 -S socket -F a0=10 -k network_socket_created
        -a always,exit -F arch=b32 -S socket -F a0=10 -k network_socket_created

        # ====================================================================
        # Suspicious shells
        # ====================================================================
        -w /bin/ash -p x -k susp_shell
        -w /bin/csh -p x -k susp_shell
        -w /bin/fish -p x -k susp_shell
        -w /bin/tcsh -p x -k susp_shell
        -w /bin/tclsh -p x -k susp_shell
        -w /bin/xonsh -p x -k susp_shell
        -w /usr/local/bin/xonsh -p x -k susp_shell
        -w /bin/rbash -p x -k susp_shell
        -w /bin/wish -p x -k susp_shell
        -w /usr/bin/wish -p x -k susp_shell
        -w /bin/yash -p x -k susp_shell
        -w /usr/bin/yash -p x -k susp_shell
        -w /bin/tmux -p x -k susp_shell
        -w /usr/local/bin/tmux -p x -k susp_shell

        ## Shell/profile configurations
        -w /etc/profile.d/ -p wa -k shell_profiles
        -w /etc/profile -p wa -k shell_profiles
        -w /etc/shells -p wa -k shell_profiles
        -w /etc/bashrc -p wa -k shell_profiles
        -w /etc/csh.cshrc -p wa -k shell_profiles
        -w /etc/csh.login -p wa -k shell_profiles
        -w /etc/fish/ -p wa -k shell_profiles
        -w /etc/zsh/ -p wa -k shell_profiles

        # ====================================================================
        # CVE-specific
        # ====================================================================
        -w /usr/bin/dbus-send -p x -k dbus_send
        -w /usr/bin/gdbus -p x -k gdbus_call

        # ====================================================================
        # Data compression (exfiltration indicator)
        # ====================================================================
        -w /usr/bin/zip -p x -k Data_Compressed
        -w /usr/bin/gzip -p x -k Data_Compressed
        -w /usr/bin/tar -p x -k Data_Compressed
        -w /usr/bin/bzip2 -p x -k Data_Compressed
        -w /usr/bin/zstd -p x -k Data_Compressed
        -w /usr/bin/xz -p x -k Data_Compressed

        # ====================================================================
        # Software management
        # ====================================================================
        -w /usr/bin/rpm -p x -k software_mgmt
        -w /usr/bin/yum -p x -k software_mgmt
        -w /usr/bin/dnf -p x -k software_mgmt
        -w /usr/bin/dpkg -p x -k software_mgmt
        -w /usr/bin/apt -p x -k software_mgmt
        -w /usr/bin/apt-get -p x -k software_mgmt
        -w /usr/bin/pip -p x -k third_party_software_mgmt
        -w /usr/bin/pip3 -p x -k third_party_software_mgmt
        -w /usr/bin/npm -p x -k third_party_software_mgmt

        # ====================================================================
        # Docker
        # ====================================================================
        -w /usr/bin/dockerd -k docker
        -w /usr/bin/docker -k docker
        -w /usr/bin/docker-containerd -k docker
        -w /usr/bin/docker-runc -k docker
        -w /var/lib/docker -p wa -k docker
        -w /etc/docker -k docker

        # ====================================================================
        # Salt configuration tampering
        # ====================================================================
        -w /etc/salt -p wa -k soft_salt
        -w /usr/local/etc/salt -p wa -k soft_salt

        # ====================================================================
        # String search tools (credential hunting)
        # ====================================================================
        -w /usr/bin/grep -p x -k string_search
        -w /usr/bin/egrep -p x -k string_search
        -w /usr/bin/rg -p x -k string_search
        -w /usr/bin/ag -p x -k string_search
        -w /usr/bin/ack -p x -k string_search

        # ====================================================================
        # NFS mounts
        # ====================================================================
        -a always,exit -F path=/sbin/mount.nfs -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
        -a always,exit -F path=/usr/sbin/mount.nfs -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts

        # ====================================================================
        # High Volume Events (comment out if too noisy)
        # ====================================================================
        ## Common shells
        -w /bin/bash -p x -k susp_shell
        -w /bin/dash -p x -k susp_shell
        -w /bin/sh -p x -k susp_shell
        -w /bin/zsh -p x -k susp_shell
        -w /bin/ksh -p x -k susp_shell

        ## File deletion by user
        -a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete

        ## Unauthorized file access attempts
        -a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k file_access
        -a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k file_access

        ## Unsuccessful creation
        -a always,exit -F arch=b64 -S mkdir,creat,link,symlink,mknod,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
        -a always,exit -F arch=b64 -S mkdir,link,symlink,mkdirat -F exit=-EPERM -k file_creation

        ## Unsuccessful modification
        -a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
        -a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification

        ## 32-bit ABI exploitation detection
        -a always,exit -F arch=b32 -S all -k 32bit_abi

        # ====================================================================
        # EXPANDED: Additional file watches not in original CCDC rules
        # ====================================================================
        ## Resolver config (DNS hijacking)
        -w /etc/resolv.conf -p wa -k dns_config
        -w /etc/nsswitch.conf -p wa -k dns_config

        ## At jobs
        -w /etc/at.allow -p wa -k at_jobs
        -w /etc/at.deny -p wa -k at_jobs
        -w /var/spool/at/ -p wa -k at_jobs

        ## xinetd (legacy super-server backdoors)
        -w /etc/xinetd.conf -p wa -k xinetd
        -w /etc/xinetd.d/ -p wa -k xinetd

        ## inetd
        -w /etc/inetd.conf -p wa -k inetd

        ## rc.local persistence
        -w /etc/rc.local -p wa -k rc_local
        -w /etc/rc.d/rc.local -p wa -k rc_local

        ## Environment variables (LD_PRELOAD via /etc/environment)
        -w /etc/environment -p wa -k env_config

        ## Kernel parameters at runtime
        -a always,exit -F arch=b64 -S sysctl -k sysctl_runtime

        ## Capabilities (privilege escalation via file capabilities)
        -a always,exit -F arch=b64 -S capset -k capabilities

        ## Log tampering
        -w /var/log/syslog -p wa -k log_tamper
        -w /var/log/auth.log -p wa -k log_tamper
        -w /var/log/secure -p wa -k log_tamper
        -w /var/log/messages -p wa -k log_tamper

    - require:
      - file: auditd_rules_dir

# Remove old minimal SaltGUI rules if present
auditd_remove_old_rules:
  file.absent:
    - name: /etc/audit/rules.d/saltgui-forensics.rules

auditd_load_rules:
  cmd.run:
    - name: augenrules --load
    - onchanges:
      - file: auditd_comprehensive_rules
      - file: auditd_remove_old_rules

auditd_service:
  service.running:
    - name: auditd
    - enable: true
    - require:
      - pkg: auditd_package
    - watch:
      - file: auditd_comprehensive_rules
