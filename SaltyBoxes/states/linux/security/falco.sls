# Falco HIDS - CCDC Edition
# Deploys Falco with modern_ebpf, community rules, and extensive CCDC detection
# Apply: salt '*' state.apply linux.security.falco

{% set os_family = grains['os_family'] %}

# Install Falco repository and package
{% if os_family == 'Debian' %}
falco_gpg_key:
  cmd.run:
    - name: curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --batch --yes --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    - creates: /usr/share/keyrings/falco-archive-keyring.gpg

falco_repo:
  file.managed:
    - name: /etc/apt/sources.list.d/falcosecurity.list
    - contents: "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main"
    - require:
      - cmd: falco_gpg_key

falco_apt_update:
  cmd.run:
    - name: apt-get update -qq
    - onchanges:
      - file: falco_repo

falco_package:
  pkg.installed:
    - name: falco
    - require:
      - cmd: falco_apt_update

{% elif os_family == 'RedHat' %}
falco_repo:
  file.managed:
    - name: /etc/yum.repos.d/falcosecurity.repo
    - contents: |
        [falcosecurity]
        name=Falco Security
        baseurl=https://download.falco.org/packages/rpm
        gpgcheck=1
        gpgkey=https://falco.org/repo/falcosecurity-packages.asc
        enabled=1

falco_package:
  pkg.installed:
    - name: falco
    - require:
      - file: falco_repo
{% endif %}

# Create log directory
falco_log_dir:
  file.directory:
    - name: /var/log/falco
    - mode: '0755'

falco_log_file:
  file.managed:
    - name: /var/log/falco/falco_alerts.log
    - replace: false
    - mode: '0644'
    - require:
      - file: falco_log_dir

# Falco configuration - includes community rules AND CCDC rules
falco_config:
  file.managed:
    - name: /etc/falco/falco.yaml
    - contents: |
        engine:
          kind: modern_ebpf
          modern_ebpf:
            cpus_for_each_buffer: 2
        rules_files:
          - /etc/falco/falco_rules.yaml
          - /etc/falco/rules.d/ccdc_comprehensive.yaml
        json_output: true
        json_include_output_property: true
        json_include_tags_property: true
        file_output:
          enabled: true
          keep_alive: true
          filename: /var/log/falco/falco_alerts.log
        stdout_output:
          enabled: true
        syslog_output:
          enabled: false
        http_output:
          enabled: false
        buffered_outputs: false
        priority: debug
        watch_config_files: false
    - require:
      - pkg: falco_package

# Rules directory
falco_rules_dir:
  file.directory:
    - name: /etc/falco/rules.d
    - require:
      - pkg: falco_package

# Comprehensive CCDC detection rules
falco_ccdc_rules:
  file.managed:
    - name: /etc/falco/rules.d/ccdc_comprehensive.yaml
    - contents: |
        # =============================================================================
        # CCDC Comprehensive Detection Rules for Falco
        # Covers: Rootkits, eBPF abuse, persistence, credential theft, C2 frameworks,
        #         webshells, evasion, privilege escalation, lateral movement, exfiltration,
        #         and specific red team tools (Sliver, Cobalt Strike, Metasploit, etc.)
        # =============================================================================

        # ---------------------------------------------------------------------------
        # MACROS
        # ---------------------------------------------------------------------------
        - macro: spawned_process
          condition: evt.type in (execve, execveat)

        - macro: open_write
          condition: evt.type in (open, openat, openat2) and evt.is_open_write=true

        - macro: open_read
          condition: evt.type in (open, openat, openat2) and evt.is_open_read=true

        - macro: is_shell
          condition: proc.name in (bash, sh, dash, zsh, csh, ksh, fish, tcsh)

        - macro: safe_procs
          condition: proc.name in (sshd, sudo, su, passwd, login, systemd, salt-minion, salt-call)

        # ---------------------------------------------------------------------------
        # LISTS
        # ---------------------------------------------------------------------------
        - list: known_c2_tools
          items: [sliver-client, sliver-server, beacon, cobaltstrike, teamserver, msfconsole, msfvenom, meterpreter, merlin, mythic, havoc, brute_ratel, villain, poshc2, covenant, empire, starkiller]

        - list: known_tunnel_tools
          items: [chisel, ligolo, ligolo-ng, gost, frp, frpc, frps, rathole, bore, ngrok, cloudflared, socat, iodine, dnscat, dnscat2, dns2tcp, hans, ptunnel]

        - list: known_recon_tools
          items: [nmap, masscan, zmap, rustscan, fscan, nbtscan, enum4linux, smbclient, rpcclient, ldapsearch, bloodhound, sharphound, adidnsdump, kerbrute, crackmapexec, netexec, impacket]

        - list: known_exploit_tools
          items: [sqlmap, hydra, medusa, john, hashcat, mimikatz, rubeus, certify, whisker, coercer, petitpotam, printspoofer, godpotato, juicypotato, sweetpotato, roguepotato, dirtypipe, pwnkit, looney]

        - list: known_privesc_tools
          items: [linpeas, winpeas, linenum, linux-exploit-suggester, les, pspy, traitor, gtfobins, sudo_killer, beroot, suid3num]

        - list: rootkit_names
          items: [diamorphine, reptile, bpfdoor, ebpfkit, pamspy, libprocesshider, bdvl, jynx, azazel, vlany, brootus, enyelkm, adore-ng, knark, suckit, heroin, override, necurs, horsepill, drovorub]

        - list: web_servers
          items: [apache2, httpd, nginx, php-fpm, php, php-cgi, java, tomcat, node, python, python3, ruby, gunicorn, uwsgi, caddy, lighttpd, flask, django, spring]

        # ---------------------------------------------------------------------------
        # ROOTKITS
        # ---------------------------------------------------------------------------
        - rule: ROOTKIT - Kernel Module Loaded
          desc: Detect kernel module loading (LKM rootkit indicator)
          condition: evt.type in (init_module, finit_module) or (spawned_process and proc.name in (insmod, modprobe))
          output: "CRITICAL [ROOTKIT] Kernel module loaded (user=%user.name command=%proc.cmdline pid=%proc.pid)"
          priority: CRITICAL
          tags: [ccdc, rootkit, lkm]

        - rule: ROOTKIT - LD_PRELOAD Injection
          desc: Detect LD_PRELOAD abuse for userland rootkits (Jynx, Azazel, bdvl)
          condition: spawned_process and proc.env contains "LD_PRELOAD"
          output: "CRITICAL [ROOTKIT] LD_PRELOAD injection (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, rootkit, preload]

        - rule: ROOTKIT - ld.so.preload Modified
          desc: Detect writes to /etc/ld.so.preload (persistent preload rootkit)
          condition: open_write and fd.name = /etc/ld.so.preload
          output: "CRITICAL [ROOTKIT] /etc/ld.so.preload modified (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, rootkit, preload]

        - rule: ROOTKIT - Diamorphine Indicator
          desc: Detect Diamorphine LKM rootkit signals (kill -63, kill -64)
          condition: evt.type = kill and (evt.arg.sig = 63 or evt.arg.sig = 64 or evt.arg.sig = 31)
          output: "CRITICAL [ROOTKIT] Diamorphine signal detected sig=%evt.arg.sig (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, rootkit, diamorphine]

        - rule: ROOTKIT - Reptile Indicator
          desc: Detect Reptile rootkit artifacts
          condition: >
            (open_write and (fd.name contains "reptile" or fd.name contains "/rep/" or fd.name = /proc/reptile)) or
            (spawned_process and proc.cmdline contains "reptile")
          output: "CRITICAL [ROOTKIT] Reptile rootkit indicator (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, rootkit, reptile]

        - rule: ROOTKIT - Hidden Kernel Module
          desc: Detect access to /proc/modules or lsmod for rootkit hiding checks
          condition: spawned_process and proc.name = rmmod and proc.cmdline contains "--force"
          output: "CRITICAL [ROOTKIT] Forced kernel module removal (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, rootkit]

        - rule: ROOTKIT - Suspicious Proc Filesystem Access
          desc: Detect attempts to hide from /proc
          condition: open_write and (fd.name startswith /proc/sys/kernel and fd.name contains "hidden")
          output: "CRITICAL [ROOTKIT] Suspicious /proc write (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, rootkit]

        # ---------------------------------------------------------------------------
        # BPF / eBPF ABUSE
        # ---------------------------------------------------------------------------
        - rule: EBPF - BPF Program Loaded
          desc: Detect BPF program loading (BPFDoor, ebpfkit, pamspy indicator)
          condition: evt.type = bpf and not proc.name in (falco, sysdig, cilium, systemd, bpftool)
          output: "CRITICAL [EBPF] BPF program loaded (user=%user.name command=%proc.cmdline pid=%proc.pid)"
          priority: CRITICAL
          tags: [ccdc, ebpf, bpfdoor]

        - rule: EBPF - Raw Socket Created
          desc: Detect raw/packet socket creation (BPFDoor, sniffers)
          condition: evt.type = socket and evt.arg.domain = AF_PACKET and not proc.name in (tcpdump, dhclient, dhcpcd, NetworkManager, systemd-networkd)
          output: "CRITICAL [EBPF] Raw socket created (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, ebpf, bpfdoor]

        - rule: EBPF - BPFtool Usage
          desc: Detect bpftool usage for inspecting/loading BPF programs
          condition: spawned_process and proc.name = bpftool
          output: "WARNING [EBPF] bpftool executed (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, ebpf]

        - rule: EBPF - Tracee or BCC Tool Loaded
          desc: Detect eBPF tracing tools that could be abused
          condition: spawned_process and proc.name in (tracee, bcc, bpftrace) and not user.name = root
          output: "WARNING [EBPF] eBPF tracing tool by non-root (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, ebpf]

        # ---------------------------------------------------------------------------
        # PERSISTENCE
        # ---------------------------------------------------------------------------
        - rule: PERSIST - SSH Authorized Keys Modified
          desc: Detect authorized_keys changes
          condition: open_write and fd.name contains "authorized_keys"
          output: "CRITICAL [PERSIST] SSH keys modified (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, persistence, ssh]

        - rule: PERSIST - SSH Config Modified
          desc: Detect sshd_config or ssh_config changes
          condition: open_write and (fd.name = /etc/ssh/sshd_config or fd.name contains "sshd_config.d/")
          output: "CRITICAL [PERSIST] SSH config modified (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence, ssh]

        - rule: PERSIST - Cron Modified
          desc: Detect cron changes (crontab, cron.d, cron.daily, spool)
          condition: open_write and (fd.name startswith /etc/cron or fd.name startswith /var/spool/cron)
          output: "CRITICAL [PERSIST] Cron modified (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, persistence, cron]

        - rule: PERSIST - Systemd Service Created
          desc: Detect systemd unit file creation
          condition: >
            open_write and
            (fd.name startswith /etc/systemd/system or fd.name startswith /usr/lib/systemd/system or fd.name startswith /run/systemd/system) and
            (fd.name endswith ".service" or fd.name endswith ".timer" or fd.name endswith ".socket")
          output: "CRITICAL [PERSIST] Systemd unit created (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, persistence, systemd]

        - rule: PERSIST - Systemd Generator Created
          desc: Detect systemd generator creation for early-boot persistence
          condition: open_write and fd.name startswith /etc/systemd/system-generators
          output: "CRITICAL [PERSIST] Systemd generator created (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence, systemd]

        - rule: PERSIST - Init Script Modified
          desc: Detect init.d or rc.local changes
          condition: open_write and (fd.name startswith /etc/init.d or fd.name = /etc/rc.local)
          output: "CRITICAL [PERSIST] Init script modified (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence]

        - rule: PERSIST - Profile or Bashrc Modified
          desc: Detect shell profile modifications for login persistence
          condition: >
            open_write and
            (fd.name = /etc/profile or fd.name startswith /etc/profile.d/ or
             fd.name endswith ".bashrc" or fd.name endswith ".bash_profile" or
             fd.name endswith ".zshrc" or fd.name endswith ".profile")
          output: "CRITICAL [PERSIST] Shell profile modified (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, persistence, shell]

        - rule: PERSIST - PAM Configuration Modified
          desc: Detect PAM config changes (PAM backdoor indicator)
          condition: open_write and fd.name startswith /etc/pam.d/
          output: "CRITICAL [PERSIST] PAM config modified (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence, pam]

        - rule: PERSIST - PAM Module Added
          desc: Detect new PAM shared library (pam_backdoor, pamspy)
          condition: open_write and fd.name startswith /lib and fd.name contains "pam_" and fd.name endswith ".so"
          output: "CRITICAL [PERSIST] PAM module written (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence, pam]

        - rule: PERSIST - Shared Library Injected
          desc: Detect new shared libraries in system paths
          condition: >
            open_write and fd.name endswith ".so" and
            (fd.name startswith /lib or fd.name startswith /usr/lib) and
            not proc.name in (dpkg, rpm, yum, dnf, apt, apt-get, pip, pip3)
          output: "CRITICAL [PERSIST] Shared library written (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, persistence, library]

        - rule: PERSIST - MOTD Backdoor
          desc: Detect MOTD script modification for login-triggered execution
          condition: open_write and fd.name startswith /etc/update-motd.d/
          output: "CRITICAL [PERSIST] MOTD script modified (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence]

        - rule: PERSIST - Udev Rule Created
          desc: Detect udev rule creation for device-triggered persistence
          condition: open_write and fd.name startswith /etc/udev/rules.d/ and fd.name endswith ".rules"
          output: "CRITICAL [PERSIST] Udev rule created (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence, udev]

        - rule: PERSIST - At Job Created
          desc: Detect at job scheduling
          condition: spawned_process and proc.name in (at, atq, atrm, batch)
          output: "WARNING [PERSIST] At job scheduled (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, persistence]

        - rule: PERSIST - Git Hook Modified
          desc: Detect git hook modification for repo-triggered persistence
          condition: open_write and fd.name contains ".git/hooks/"
          output: "WARNING [PERSIST] Git hook modified (user=%user.name file=%fd.name)"
          priority: WARNING
          tags: [ccdc, persistence]

        # ---------------------------------------------------------------------------
        # CREDENTIAL THEFT
        # ---------------------------------------------------------------------------
        - rule: CREDS - Shadow File Read
          desc: Detect /etc/shadow access by non-standard processes
          condition: open_read and fd.name = /etc/shadow and not safe_procs
          output: "CRITICAL [CREDS] Shadow file read (user=%user.name command=%proc.cmdline pid=%proc.pid)"
          priority: CRITICAL
          tags: [ccdc, credentials]

        - rule: CREDS - Shadow File Modified
          desc: Detect /etc/shadow writes
          condition: open_write and fd.name = /etc/shadow and not proc.name in (passwd, chpasswd, useradd, usermod, shadow)
          output: "CRITICAL [CREDS] Shadow file modified (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials]

        - rule: CREDS - Passwd File Modified
          desc: Detect /etc/passwd modification (uid 0 backdoor)
          condition: open_write and fd.name = /etc/passwd and not proc.name in (useradd, usermod, userdel, passwd, chfn, chsh, vipw)
          output: "CRITICAL [CREDS] Passwd file modified (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials]

        - rule: CREDS - Group File Modified
          desc: Detect /etc/group or /etc/gshadow modification
          condition: open_write and (fd.name = /etc/group or fd.name = /etc/gshadow) and not proc.name in (groupadd, groupmod, groupdel, useradd, usermod)
          output: "CRITICAL [CREDS] Group file modified (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials]

        - rule: CREDS - Sudoers Modified
          desc: Detect sudoers or sudoers.d changes
          condition: open_write and (fd.name = /etc/sudoers or fd.name startswith /etc/sudoers.d/)
          output: "CRITICAL [CREDS] Sudoers modified (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials, privesc]

        - rule: CREDS - SSH Private Key Read
          desc: Detect reading of SSH private keys
          condition: open_read and (fd.name endswith "id_rsa" or fd.name endswith "id_ecdsa" or fd.name endswith "id_ed25519") and not proc.name in (sshd, ssh, ssh-agent, ssh-add)
          output: "CRITICAL [CREDS] SSH private key read (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials, ssh]

        - rule: CREDS - Credential File Access
          desc: Detect access to common credential stores
          condition: >
            open_read and
            (fd.name contains ".mysql_history" or fd.name contains ".pgpass" or
             fd.name contains ".my.cnf" or fd.name contains "credentials.xml" or
             fd.name contains ".aws/credentials" or fd.name contains ".docker/config.json" or
             fd.name contains ".kube/config" or fd.name contains ".git-credentials" or
             fd.name contains "wp-config.php" or fd.name contains ".env") and
            not safe_procs
          output: "WARNING [CREDS] Credential file accessed (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, credentials]

        - rule: CREDS - Password Brute Force Tool
          desc: Detect credential brute force tools
          condition: spawned_process and proc.name in (hydra, medusa, ncrack, patator, crowbar, crackmapexec, netexec, kerbrute, spray)
          output: "CRITICAL [CREDS] Brute force tool executed (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials, bruteforce]

        - rule: CREDS - Password Cracking Tool
          desc: Detect offline password cracking
          condition: spawned_process and proc.name in (john, hashcat, ophcrack, rainbowcrack)
          output: "CRITICAL [CREDS] Password cracking tool (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials, cracking]

        - rule: CREDS - Mimikatz or Credential Dumper
          desc: Detect credential dumping tools
          condition: spawned_process and (proc.name in (mimikatz, sekurlsa, procdump, pypykatz) or proc.cmdline contains "mimikatz" or proc.cmdline contains "sekurlsa" or proc.cmdline contains "hashdump")
          output: "CRITICAL [CREDS] Credential dumper detected (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials, dumping]

        # ---------------------------------------------------------------------------
        # C2 FRAMEWORKS
        # ---------------------------------------------------------------------------
        - rule: C2 - Reverse Shell via Bash
          desc: Detect bash reverse shells (/dev/tcp, /dev/udp)
          condition: spawned_process and proc.name = bash and (proc.cmdline contains "/dev/tcp" or proc.cmdline contains "/dev/udp")
          output: "CRITICAL [C2] Bash reverse shell (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, revshell]

        - rule: C2 - Reverse Shell via Netcat
          desc: Detect netcat reverse/bind shells
          condition: spawned_process and proc.name in (nc, ncat, netcat) and (proc.cmdline contains "-e" or proc.cmdline contains "-c" or proc.cmdline contains "-l")
          output: "CRITICAL [C2] Netcat shell (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, revshell]

        - rule: C2 - Reverse Shell via Python
          desc: Detect Python reverse shells
          condition: spawned_process and proc.name in (python, python3, python2) and (proc.cmdline contains "socket" and (proc.cmdline contains "connect" or proc.cmdline contains "subprocess"))
          output: "CRITICAL [C2] Python reverse shell (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, revshell]

        - rule: C2 - Reverse Shell via Perl
          desc: Detect Perl reverse shells
          condition: spawned_process and proc.name = perl and (proc.cmdline contains "socket" or proc.cmdline contains "IO::Socket")
          output: "CRITICAL [C2] Perl reverse shell (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, revshell]

        - rule: C2 - Reverse Shell via Ruby
          desc: Detect Ruby reverse shells
          condition: spawned_process and proc.name in (ruby, irb) and proc.cmdline contains "TCPSocket"
          output: "CRITICAL [C2] Ruby reverse shell (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, revshell]

        - rule: C2 - Reverse Shell via PHP
          desc: Detect PHP reverse shells
          condition: spawned_process and proc.name in (php, php-cgi) and (proc.cmdline contains "fsockopen" or proc.cmdline contains "exec" or proc.cmdline contains "shell_exec")
          output: "CRITICAL [C2] PHP reverse shell (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, revshell]

        - rule: C2 - Socat Tunnel
          desc: Detect socat used for tunneling or reverse shells
          condition: spawned_process and proc.name = socat
          output: "CRITICAL [C2] Socat tunnel detected (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, socat, tunnel]

        - rule: C2 - Sliver Implant Indicator
          desc: Detect Sliver C2 framework indicators
          condition: >
            spawned_process and
            (proc.name in (sliver-client, sliver-server) or
             proc.cmdline contains "sliver" or
             proc.cmdline contains "--mtls" or
             proc.cmdline contains "--wg" or
             proc.cmdline contains "--dns-listener")
          output: "CRITICAL [C2] Sliver C2 indicator (user=%user.name command=%proc.cmdline exe=%proc.exepath)"
          priority: CRITICAL
          tags: [ccdc, c2, sliver]

        - rule: C2 - Cobalt Strike Indicator
          desc: Detect Cobalt Strike beacon indicators
          condition: >
            spawned_process and
            (proc.name in (beacon, cobaltstrike, teamserver) or
             proc.cmdline contains "cobaltstrike" or
             proc.cmdline contains "beacon" or
             proc.cmdline contains "teamserver")
          output: "CRITICAL [C2] Cobalt Strike indicator (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, cobaltstrike]

        - rule: C2 - Metasploit Indicator
          desc: Detect Metasploit framework tools
          condition: >
            spawned_process and
            (proc.name in (msfconsole, msfvenom, msfdb, meterpreter) or
             proc.cmdline contains "msfconsole" or proc.cmdline contains "msfvenom" or
             proc.cmdline contains "meterpreter" or proc.cmdline contains "metasploit")
          output: "CRITICAL [C2] Metasploit indicator (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, metasploit]

        - rule: C2 - Known C2 Tool Execution
          desc: Detect known C2 framework binaries
          condition: spawned_process and proc.name in (known_c2_tools)
          output: "CRITICAL [C2] Known C2 tool executed (user=%user.name tool=%proc.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2]

        - rule: C2 - Tunneling Tool Detected
          desc: Detect known tunneling/proxy tools (chisel, ligolo, frp, etc.)
          condition: spawned_process and proc.name in (known_tunnel_tools)
          output: "CRITICAL [C2] Tunneling tool detected (user=%user.name tool=%proc.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, tunnel]

        - rule: C2 - Reverse SSH Tunnel
          desc: Detect SSH remote port forwarding (reverse tunnel)
          condition: spawned_process and proc.name = ssh and (proc.cmdline contains "-R " or proc.cmdline contains "-D " or proc.cmdline contains "RemoteForward")
          output: "CRITICAL [C2] Reverse SSH tunnel (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, tunnel, ssh]

        - rule: C2 - Pwncat Detected
          desc: Detect pwncat reverse shell handler
          condition: spawned_process and (proc.name = pwncat or proc.cmdline contains "pwncat")
          output: "CRITICAL [C2] Pwncat detected (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, pwncat]

        - rule: C2 - Empire or Starkiller
          desc: Detect PowerShell Empire or Starkiller
          condition: spawned_process and (proc.cmdline contains "empire" or proc.cmdline contains "starkiller" or proc.cmdline contains "powershell-empire")
          output: "CRITICAL [C2] Empire/Starkiller detected (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, empire]

        - rule: C2 - DNS Tunnel Tool
          desc: Detect DNS tunneling tools
          condition: spawned_process and proc.name in (iodine, iodined, dnscat, dnscat2, dns2tcp, dns2tcpc, dns2tcpd, hans)
          output: "CRITICAL [C2] DNS tunnel tool (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, dns, tunnel]

        - rule: C2 - ICMP Tunnel Tool
          desc: Detect ICMP tunneling
          condition: spawned_process and proc.name in (ptunnel, hans, icmpsh, icmptunnel)
          output: "CRITICAL [C2] ICMP tunnel tool (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2, icmp, tunnel]

        # ---------------------------------------------------------------------------
        # WEBSHELLS
        # ---------------------------------------------------------------------------
        - rule: WEBSHELL - Shell from Web Server
          desc: Detect shell spawned from web server process
          condition: spawned_process and proc.pname in (web_servers) and is_shell
          output: "CRITICAL [WEBSHELL] Shell from web server (user=%user.name command=%proc.cmdline parent=%proc.pname ppid=%proc.ppid)"
          priority: CRITICAL
          tags: [ccdc, webshell]

        - rule: WEBSHELL - Command Execution from Web Server
          desc: Detect command tools spawned from web server
          condition: >
            spawned_process and proc.pname in (web_servers) and
            proc.name in (whoami, id, uname, hostname, ifconfig, ip, cat, wget, curl, nc, ncat, python, python3, perl, gcc, cc)
          output: "CRITICAL [WEBSHELL] Command from web server (user=%user.name command=%proc.cmdline parent=%proc.pname)"
          priority: CRITICAL
          tags: [ccdc, webshell]

        - rule: WEBSHELL - File Upload to Web Directory
          desc: Detect files written to common web directories
          condition: >
            open_write and
            (fd.name startswith /var/www or fd.name startswith /srv/www or
             fd.name startswith /usr/share/nginx or fd.name startswith /opt/lampp) and
            (fd.name endswith ".php" or fd.name endswith ".jsp" or fd.name endswith ".aspx" or
             fd.name endswith ".py" or fd.name endswith ".pl" or fd.name endswith ".cgi" or
             fd.name endswith ".sh" or fd.name endswith ".war")
          output: "CRITICAL [WEBSHELL] Executable uploaded to web dir (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, webshell, upload]

        - rule: WEBSHELL - Outbound Connection from Web Server
          desc: Detect web server making outbound connections
          condition: >
            evt.type = connect and evt.dir = > and
            proc.name in (web_servers) and
            fd.sip != "127.0.0.1" and fd.sport != 80 and fd.sport != 443 and fd.sport != 8080
          output: "WARNING [WEBSHELL] Web server outbound connection (process=%proc.name dest=%fd.sip:%fd.sport)"
          priority: WARNING
          tags: [ccdc, webshell]

        # ---------------------------------------------------------------------------
        # PRIVILEGE ESCALATION
        # ---------------------------------------------------------------------------
        - rule: PRIVESC - SUID Binary Created
          desc: Detect SUID bit being set on a file
          condition: evt.type in (chmod, fchmod, fchmodat) and evt.arg.mode contains "S_ISUID"
          output: "CRITICAL [PRIVESC] SUID binary created (user=%user.name file=%evt.arg.path command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, privesc, suid]

        - rule: PRIVESC - Capabilities Changed
          desc: Detect file capability changes
          condition: spawned_process and proc.name in (setcap, getcap) and proc.cmdline contains "cap_"
          output: "CRITICAL [PRIVESC] File capabilities changed (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, privesc, capabilities]

        - rule: PRIVESC - Known Privesc Tool
          desc: Detect known privilege escalation tools
          condition: spawned_process and (proc.name in (known_privesc_tools) or proc.exepath contains "linpeas" or proc.exepath contains "pspy")
          output: "CRITICAL [PRIVESC] Privesc tool executed (user=%user.name command=%proc.cmdline exe=%proc.exepath)"
          priority: CRITICAL
          tags: [ccdc, privesc]

        - rule: PRIVESC - Sudo Misconfiguration Exploit
          desc: Detect common sudo exploits (sudo -l enumeration by non-interactive process)
          condition: spawned_process and proc.name = sudo and proc.cmdline contains "-l" and not proc.pname in (bash, sh, zsh, sshd, login)
          output: "WARNING [PRIVESC] Sudo enumeration from non-interactive source (user=%user.name command=%proc.cmdline parent=%proc.pname)"
          priority: WARNING
          tags: [ccdc, privesc, sudo]

        - rule: PRIVESC - User Added to Sudo/Wheel Group
          desc: Detect user being added to privileged groups
          condition: spawned_process and (proc.name = usermod or proc.name = gpasswd) and (proc.cmdline contains "sudo" or proc.cmdline contains "wheel" or proc.cmdline contains "admin")
          output: "CRITICAL [PRIVESC] User added to privileged group (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, privesc]

        - rule: PRIVESC - New Root User Created
          desc: Detect user creation with UID 0
          condition: spawned_process and proc.name = useradd and (proc.cmdline contains "uid 0" or proc.cmdline contains "-u 0" or proc.cmdline contains "-o")
          output: "CRITICAL [PRIVESC] Root-level user created (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, privesc]

        - rule: PRIVESC - Ptrace Injection
          desc: Detect ptrace-based process injection
          condition: evt.type = ptrace and evt.arg.request in (PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_ATTACH) and not proc.name in (strace, ltrace, gdb, lldb)
          output: "CRITICAL [PRIVESC] Ptrace injection detected (user=%user.name command=%proc.cmdline target_pid=%evt.arg.pid)"
          priority: CRITICAL
          tags: [ccdc, privesc, injection]

        - rule: PRIVESC - Docker Socket Access
          desc: Detect access to Docker socket (container escape)
          condition: (open_read or open_write) and fd.name = /var/run/docker.sock and not proc.name in (dockerd, containerd, docker)
          output: "CRITICAL [PRIVESC] Docker socket access (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, privesc, docker, escape]

        - rule: PRIVESC - Container Escape Attempt
          desc: Detect known container escape techniques
          condition: >
            spawned_process and
            (proc.cmdline contains "nsenter" or
             proc.cmdline contains "unshare" or
             (proc.name = mount and proc.cmdline contains "cgroup"))
          output: "CRITICAL [PRIVESC] Container escape attempt (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, privesc, container, escape]

        # ---------------------------------------------------------------------------
        # RECONNAISSANCE
        # ---------------------------------------------------------------------------
        - rule: RECON - Network Scanning Tool
          desc: Detect network scanning and enumeration tools
          condition: spawned_process and proc.name in (known_recon_tools)
          output: "WARNING [RECON] Network scan tool (user=%user.name tool=%proc.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, recon, scan]

        - rule: RECON - Known Exploit Tool
          desc: Detect known exploitation tools
          condition: spawned_process and proc.name in (known_exploit_tools)
          output: "CRITICAL [RECON] Exploit tool executed (user=%user.name tool=%proc.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, recon, exploit]

        - rule: RECON - Internal Network Enumeration
          desc: Detect rapid network discovery commands
          condition: >
            spawned_process and
            (proc.cmdline contains "ping -c 1" or
             (proc.name = arp and proc.cmdline contains "-a") or
             proc.cmdline contains "for i in" or
             proc.cmdline contains "255.255.255.0") and
            not safe_procs
          output: "WARNING [RECON] Network enumeration (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, recon]

        # ---------------------------------------------------------------------------
        # LATERAL MOVEMENT
        # ---------------------------------------------------------------------------
        - rule: LATERAL - Impacket Tool Detected
          desc: Detect Impacket suite tools
          condition: >
            spawned_process and
            (proc.cmdline contains "impacket" or proc.cmdline contains "psexec.py" or
             proc.cmdline contains "smbexec.py" or proc.cmdline contains "wmiexec.py" or
             proc.cmdline contains "atexec.py" or proc.cmdline contains "dcomexec.py" or
             proc.cmdline contains "secretsdump.py" or proc.cmdline contains "getTGT.py" or
             proc.cmdline contains "getST.py" or proc.cmdline contains "smbclient.py" or
             proc.cmdline contains "ntlmrelayx" or proc.cmdline contains "responder")
          output: "CRITICAL [LATERAL] Impacket tool detected (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, lateral, impacket]

        - rule: LATERAL - Responder or Relay Attack
          desc: Detect LLMNR/NTLM relay tools
          condition: spawned_process and (proc.name = responder or proc.cmdline contains "ntlmrelayx" or proc.cmdline contains "multirelay")
          output: "CRITICAL [LATERAL] Responder/relay attack (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, lateral, relay]

        # ---------------------------------------------------------------------------
        # EVASION
        # ---------------------------------------------------------------------------
        - rule: EVASION - Log Deletion
          desc: Detect log file deletion or truncation
          condition: >
            (evt.type in (unlink, unlinkat) and evt.arg.name startswith /var/log and not proc.name = logrotate) or
            (evt.type in (open, openat) and evt.is_open_write=true and fd.name startswith /var/log and evt.arg.flags contains O_TRUNC)
          output: "CRITICAL [EVASION] Log tampering (user=%user.name file=%fd.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, evasion, logs]

        - rule: EVASION - History Cleared
          desc: Detect shell history clearing or disabling
          condition: >
            spawned_process and
            (proc.cmdline contains "history -c" or proc.cmdline contains "history -w /dev/null" or
             proc.cmdline contains "HISTFILE=/dev/null" or proc.cmdline contains "HISTSIZE=0" or
             proc.cmdline contains "unset HISTFILE" or proc.cmdline contains "set +o history" or
             proc.cmdline contains "shred.*history" or proc.cmdline contains "rm.*history")
          output: "CRITICAL [EVASION] History cleared (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, evasion]

        - rule: EVASION - Timestomping
          desc: Detect file timestamp manipulation
          condition: spawned_process and proc.name = touch and (proc.cmdline contains " -t " or proc.cmdline contains " -r " or proc.cmdline contains "--reference")
          output: "WARNING [EVASION] Timestomping detected (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, evasion, timestomp]

        - rule: EVASION - Binary Renamed or Copied
          desc: Detect suspicious binary operations in /tmp or /dev/shm
          condition: >
            spawned_process and
            (proc.name = cp or proc.name = mv) and
            (proc.cmdline contains "/tmp/" or proc.cmdline contains "/dev/shm/") and
            (proc.cmdline contains "/bin/" or proc.cmdline contains "/sbin/" or proc.cmdline contains "/usr/bin/")
          output: "WARNING [EVASION] Binary moved to temp dir (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, evasion]

        - rule: EVASION - Auditd Tampered
          desc: Detect auditd being stopped or rules cleared
          condition: >
            spawned_process and
            ((proc.name in (systemctl, service) and proc.cmdline contains "auditd" and (proc.cmdline contains "stop" or proc.cmdline contains "disable")) or
             (proc.name = auditctl and proc.cmdline contains "-D"))
          output: "CRITICAL [EVASION] Auditd tampered (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, evasion, audit]

        - rule: EVASION - Falco Tampered
          desc: Detect Falco being stopped or disabled
          condition: >
            spawned_process and
            (proc.name in (systemctl, service) and proc.cmdline contains "falco" and
            (proc.cmdline contains "stop" or proc.cmdline contains "disable" or proc.cmdline contains "kill"))
          output: "CRITICAL [EVASION] Falco tampered (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, evasion, falco]

        - rule: EVASION - Firewall Disabled
          desc: Detect firewall being flushed or disabled
          condition: >
            spawned_process and
            ((proc.name = iptables and (proc.cmdline contains "-F" or proc.cmdline contains "--flush" or proc.cmdline contains "-P INPUT ACCEPT")) or
             (proc.name = ufw and proc.cmdline contains "disable") or
             (proc.name = firewall-cmd and proc.cmdline contains "--panic-off"))
          output: "CRITICAL [EVASION] Firewall disabled (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, evasion, firewall]

        - rule: EVASION - Process Name Masquerading
          desc: Detect processes running from unusual locations with common names
          condition: >
            spawned_process and
            proc.name in (sshd, cron, systemd, dbus, rsyslog, kworker) and
            not (proc.exepath startswith /usr or proc.exepath startswith /sbin or proc.exepath startswith /bin or proc.exepath startswith /lib)
          output: "CRITICAL [EVASION] Process masquerading (name=%proc.name actual_path=%proc.exepath user=%user.name)"
          priority: CRITICAL
          tags: [ccdc, evasion, masquerade]

        # ---------------------------------------------------------------------------
        # DATA EXFILTRATION
        # ---------------------------------------------------------------------------
        - rule: EXFIL - Curl or Wget Uploading Data
          desc: Detect data upload via curl or wget
          condition: >
            spawned_process and
            ((proc.name = curl and (proc.cmdline contains "-d " or proc.cmdline contains "--data" or proc.cmdline contains "-F " or proc.cmdline contains "--upload-file" or proc.cmdline contains "-T ")) or
             (proc.name = wget and proc.cmdline contains "--post"))
          output: "WARNING [EXFIL] Data upload detected (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, exfil]

        - rule: EXFIL - Archive Before Transfer
          desc: Detect archive creation followed by suspicious context
          condition: >
            spawned_process and
            proc.name in (tar, zip, 7z, gzip, bzip2, xz, rar) and
            (proc.cmdline contains "/etc" or proc.cmdline contains "/home" or proc.cmdline contains "/root" or
             proc.cmdline contains "/var" or proc.cmdline contains "shadow" or proc.cmdline contains "passwd")
          output: "WARNING [EXFIL] Sensitive data archiving (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, exfil, archive]

        - rule: EXFIL - Base64 Encoding
          desc: Detect base64 encoding of sensitive files
          condition: spawned_process and proc.name = base64 and not proc.cmdline contains "--decode"
          output: "WARNING [EXFIL] Base64 encoding (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, exfil]

        # ---------------------------------------------------------------------------
        # CRYPTO / MINING
        # ---------------------------------------------------------------------------
        - rule: MINING - Cryptominer Indicator
          desc: Detect cryptocurrency mining tools or indicators
          condition: >
            spawned_process and
            (proc.name in (xmrig, minerd, cpuminer, cgminer, bfgminer, ethminer, ccminer, t-rex, nbminer, phoenixminer) or
             proc.cmdline contains "stratum+tcp" or proc.cmdline contains "stratum+ssl" or
             proc.cmdline contains "pool.minexmr" or proc.cmdline contains "nicehash" or
             proc.cmdline contains "moneroocean" or proc.cmdline contains "nanopool" or
             proc.cmdline contains "randomx" or proc.cmdline contains "--coin=")
          output: "CRITICAL [MINING] Cryptominer detected (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, mining, crypto]

        # ---------------------------------------------------------------------------
        # BASELINE / SUSPICIOUS ACTIVITY
        # ---------------------------------------------------------------------------
        - rule: BASELINE - Execution from /tmp or /dev/shm
          desc: Detect binary execution from temp directories
          condition: spawned_process and (proc.exepath startswith /tmp or proc.exepath startswith /dev/shm or proc.exepath startswith /var/tmp)
          output: "WARNING [BASELINE] Execution from temp dir (user=%user.name exe=%proc.exepath command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, baseline]

        - rule: BASELINE - Script Download and Execute
          desc: Detect pipe-to-shell patterns
          condition: >
            spawned_process and
            proc.name in (curl, wget) and
            (proc.cmdline contains "| sh" or proc.cmdline contains "| bash" or
             proc.cmdline contains "|sh" or proc.cmdline contains "|bash" or
             proc.cmdline contains "| python" or proc.cmdline contains "|python")
          output: "CRITICAL [BASELINE] Download and execute (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, baseline]

        - rule: BASELINE - Compiler on Production System
          desc: Detect compilation (dropping compiled malware)
          condition: spawned_process and proc.name in (gcc, g++, cc, make, as, ld, clang, rustc, go)
          output: "WARNING [BASELINE] Compiler usage (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, baseline, compiler]

        - rule: BASELINE - Suspicious ELF Downloaded
          desc: Detect wget/curl downloading to executable paths
          condition: >
            spawned_process and
            proc.name in (wget, curl) and
            (proc.cmdline contains "-o /tmp" or proc.cmdline contains "-O /tmp" or
             proc.cmdline contains "-o /dev/shm" or proc.cmdline contains "-O /dev/shm" or
             proc.cmdline contains "-o /var/tmp" or proc.cmdline contains "-O /var/tmp")
          output: "WARNING [BASELINE] Download to temp dir (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, baseline]

        - rule: BASELINE - Suspicious Chmod
          desc: Detect chmod +x on files in temp directories
          condition: >
            spawned_process and proc.name = chmod and
            (proc.cmdline contains "+x" or proc.cmdline contains "777" or proc.cmdline contains "755") and
            (proc.cmdline contains "/tmp" or proc.cmdline contains "/dev/shm" or proc.cmdline contains "/var/tmp")
          output: "WARNING [BASELINE] Chmod in temp dir (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, baseline]

        - rule: BASELINE - Interactive Shell from Non-Terminal
          desc: Detect interactive shell spawned from non-standard parent
          condition: >
            spawned_process and is_shell and
            proc.cmdline contains "-i" and
            not proc.pname in (sshd, login, su, sudo, bash, sh, screen, tmux, script)
          output: "CRITICAL [BASELINE] Interactive shell from unusual parent (user=%user.name command=%proc.cmdline parent=%proc.pname)"
          priority: CRITICAL
          tags: [ccdc, baseline]

        - rule: BASELINE - Nohup or Disown for Persistence
          desc: Detect nohup or background detachment
          condition: spawned_process and (proc.name = nohup or proc.cmdline contains "disown")
          output: "WARNING [BASELINE] Background persistence (user=%user.name command=%proc.cmdline)"
          priority: WARNING
          tags: [ccdc, baseline]
    - require:
      - file: falco_rules_dir

# Enable BPF if restricted
falco_bpf_access:
  cmd.run:
    - name: echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled
    - onlyif: test "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)" != "0"

# Stop conflicting Falco services
{% for svc in ['falco', 'falco-bpf', 'falco-kmod'] %}
falco_stop_{{ svc }}:
  service.dead:
    - name: {{ svc }}
    - enable: false
    - require:
      - pkg: falco_package
{% endfor %}

# Start modern-bpf service
falco_modern_bpf:
  service.running:
    - name: falco-modern-bpf
    - enable: true
    - require:
      - file: falco_config
      - file: falco_ccdc_rules
      - cmd: falco_bpf_access
    - watch:
      - file: falco_config
      - file: falco_ccdc_rules
