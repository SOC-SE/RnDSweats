# ============================================================================
# FALCO SECURITY MONITORING - SELF-CONTAINED STATE
# ============================================================================
# Description: Deploys Falco runtime security with CCDC-optimized detection rules
# OS Support: Ubuntu, Debian, Fedora, CentOS, RHEL, Oracle Linux, Rocky, Alma
# Services: falco, falco-modern-bpf
# 
# This state is FULLY SELF-CONTAINED - no salt:// dependencies required
# Works with: state.template_str, salt-call --local, or state.apply
# ============================================================================

{% set os_family = grains['os_family'] %}
{% set os = grains['os'] %}
{% set os_major = grains['osmajorrelease']|int %}

# ----------------------------------------------------------------------------
# CREATE DIRECTORIES
# ----------------------------------------------------------------------------

falco_log_dir:
  file.directory:
    - name: /var/log/falco
    - user: root
    - group: root
    - mode: 755

falco_rules_dir:
  file.directory:
    - name: /etc/falco/rules.d
    - user: root
    - group: root
    - mode: 755
    - makedirs: True

# ----------------------------------------------------------------------------
# INSTALL FALCO REPOSITORY
# ----------------------------------------------------------------------------

{% if os_family == 'Debian' %}
falco_repo:
  pkgrepo.managed:
    - name: falcosecurity
    - humanname: Falco Security Repository
    - file: /etc/apt/sources.list.d/falcosecurity.list
    - key_url: https://falcosecurity.github.io/falco/repo/falcosecurity-packages.asc
    - baseurl: https://download.falco.org/packages/deb
    - aptkey: False
    - refresh: True

{% elif os_family == 'RedHat' %}
falco_repo:
  pkgrepo.managed:
    - name: falcosecurity
    - humanname: Falco Security Repository
    - baseurl: https://download.falco.org/packages/rpm/
    - gpgcheck: 1
    - gpgkey: https://falcosecurity.github.io/falco/repo/falcosecurity-packages.asc
    - enabled: 1

{% else %}
falco_repo:
  cmd.run:
    - name: echo "Unsupported OS family for Falco repo - manual installation may be required"
{% endif %}

# ----------------------------------------------------------------------------
# INSTALL FALCO
# ----------------------------------------------------------------------------

falco_install:
  pkg.installed:
    - name: falco
    - require:
      - falco_repo

# ----------------------------------------------------------------------------
# DEPLOY CCDC EXTENDED RULES (EMBEDDED)
# ----------------------------------------------------------------------------

falco_ccdc_rules:
  file.managed:
    - name: /etc/falco/rules.d/ccdc_extended_rules.yaml
    - user: root
    - group: root
    - mode: 644
    - require:
      - falco_rules_dir
      - falco_install
    - contents: |
        # ============================================================================
        # CCDC EXTENDED FALCO RULES
        # Focus: Rootkit Detection, Persistence Hunting, General Security Baseline
        # ============================================================================
        # Deploy to: /etc/falco/rules.d/ccdc_extended_rules.yaml
        # 
        # Categories:
        #   - ROOTKIT: Kernel and userspace rootkit indicators
        #   - PERSIST: Persistence mechanism modifications  
        #   - PRIVESC: Privilege escalation attempts
        #   - CREDS: Credential access and theft
        #   - EVASION: Defense evasion techniques
        #   - C2: Command and control indicators
        #   - RECON: Reconnaissance and discovery
        #   - LATERAL: Lateral movement
        #   - EXFIL: Data exfiltration indicators
        # ============================================================================
        
        # ============================================================================
        # MACRO DEFINITIONS
        # ============================================================================
        
        - macro: spawned_process
          condition: evt.type in (execve, execveat) and evt.dir=<
        
        - macro: open_write
          condition: evt.type in (open, openat, openat2) and evt.is_open_write=true and fd.typechar='f'
        
        - macro: open_read
          condition: evt.type in (open, openat, openat2) and evt.is_open_read=true and fd.typechar='f'
        
        - macro: open_read_write
          condition: evt.type in (open, openat, openat2) and evt.is_open_read=true and evt.is_open_write=true and fd.typechar='f'
        
        - macro: container
          condition: container.id != host
        
        - macro: shell_procs
          condition: proc.name in (bash, sh, dash, zsh, csh, tcsh, ksh, fish)
        
        - macro: shell_binaries
          condition: proc.name in (bash, sh, dash, zsh, csh, tcsh, ksh, fish)
        
        - macro: known_root_procs
          condition: proc.name in (systemd, init, cron, crond, anacron, sshd, login, su, sudo, polkitd, dbus-daemon)
        
        - macro: package_managers
          condition: proc.name in (apt, apt-get, dpkg, yum, dnf, rpm, pacman, zypper, emerge, apk)
        
        - macro: salt_or_ansible
          condition: proc.name in (salt-minion, salt-call, ansible, ansible-playbook) or proc.pname in (salt-minion, salt-call, ansible, ansible-playbook)
        
        # ============================================================================
        # LISTS
        # ============================================================================
        
        - list: rootkit_binaries
          items: [
            # Classic Linux Rootkits
            azazel, bdvl, beurk, brootkit, diamorphine, enyelkm, flea, horsepill,
            jynx, jynx2, khook, kitsune, kovid, ldpreloadhook, libprocesshider,
            lilith, linux_rkit, lkm, mafix, necurs, nuker, phalanx, rkh, rkorova,
            rootfoo, shv4, shv5, suckit, superkit, torn, turtle, umbreon, vlany,
            weaponx, xor-ddos,
            # Additional Kernel Rootkits
            adore, adore-ng, knark, rial, kbd, rkdet, mood-nt, phantasmagoria,
            sebek, synapsys, override, rkit, all-root, ambient, ark, balrog,
            beastkit, bobkit, cinik, cub, dica, fbrk, fu, fukitol, greenkit,
            heroin, hijacker, illusion, joy, kbdv3, kis, lechat, lockit, lrk,
            moodnt, n3rds, omega, optik, oz, ramen, replicator, rial, sadmind,
            satan, shitc, sintherix, slapper, sneakin, solaris, t0rn, teamtnt,
            telekit, togroot, trojanit, vampire, volc, wormkit, x, zarathustra,
            zeroaccess, zk,
            # Modern/Advanced Rootkits
            reptile, drovorub, bpfdoor, symbiote, orbit, skidmap, doki, kinsing,
            hildegard, siloscape, cr4sh, blackcat, hive, industrial_spy,
            # eBPF-based
            ebpfkit, boopkit, pamspy, bad-bpf, tricephalic,
            # Container-focused
            ezuri, doki, kinsing, xmrig_rootkit, coinminer_rootkit
          ]
        
        - list: rootkit_files
          items: [
            "/etc/ld.so.preload",
            "/lib/libselinux.so",
            "/lib64/libselinux.so",
            ".bashrc.swp",
            "/usr/lib/libcurl.so.2",
            "/dev/ptyr",
            "/dev/ptyp",
            "/dev/ptyq",
            "/dev/ptys",
            "/dev/hda06",
            "/dev/hdx1",
            "/dev/hdx2",
            "/dev/xdf1",
            "/dev/xdf2",
            "/usr/include/file.h",
            "/usr/include/hosts.h",
            "/usr/include/log.h",
            "/usr/include/proc.h",
            "/usr/include/lidps1.so",
            "/usr/include/lpstree.so"
          ]
        
        - list: rootkit_kernel_modules
          items: [
            diamorphine, reptile, reptile_module, kovid, bdvl, beurk, khook,
            suterusu, nurupo, rkduck, enyelkm, adore, adore-ng, knark, modhide,
            cleaner, hide_lkm, rt, rootme, hacked_kill, tasklist, kernel_hacker,
            hp, kis, rpldev, synapsys, mod_rootme, moodnt
          ]
        
        - list: miner_binaries
          items: [xmrig, xmr-stak, minerd, cpuminer, cgminer, bfgminer, ethminer, ccminer]
        
        - list: network_recon_tools
          items: [nmap, masscan, zmap, netcat, nc, ncat, socat, tcpdump, wireshark, tshark, ettercap, arpspoof, responder, bettercap]
        
        - list: hacking_tools
          items: [
            # Password Cracking
            hydra, medusa, john, hashcat, ophcrack, rainbowcrack, l0phtcrack,
            cewl, crunch, cupp, maskprocessor, statsprocessor, princeprocessor,
            # Network Attack Tools
            aircrack-ng, airmon-ng, airodump-ng, aireplay-ng, wifite, reaver,
            bully, pixiewps, fern-wifi-cracker, cowpatty,
            # Exploitation Frameworks
            metasploit, msfconsole, msfvenom, msfdb, armitage, cobalt, cobaltstrike,
            empire, starkiller, pupy, koadic, silenttrinity, villain, havoc,
            sliver, mythic, merlin, covenant, faction, apfell, poseidon, apollo,
            nimplant, brute_ratel, nighthawk,
            # Web Exploitation
            sqlmap, sqlninja, sqlsus, bbqsql, nosqlmap, jsql, havij,
            nikto, gobuster, dirb, dirbuster, wfuzz, ffuf, feroxbuster,
            wpscan, joomscan, droopescan, cmseek, nuclei,
            burp, burpsuite, zap, mitmproxy, bettercap,
            xsser, xsstrike, dalfox, kxss,
            commix, tplmap,
            # Post-Exploitation
            mimikatz, pypykatz, lsassy, secretsdump, impacket, crackmapexec,
            bloodhound, sharphound, rubeus, kekeo, ticketer, getTGT,
            evil-winrm, psexec, smbexec, wmiexec, dcomexec, atexec,
            pth-toolkit, passing-the-hash,
            spray, kerbrute, adidnsdump, ldapdomaindump,
            responder, inveigh, ntlmrelayx, mitm6,
            powersploit, nishang, powerup, powercat, psgetsys,
            # Privilege Escalation
            linpeas, winpeas, linenum, linux-exploit-suggester, les,
            unix-privesc-check, pspy, sudo_killer, gtfobins,
            beroot, seatbelt, watson, sherlock, jaws,
            # Tunneling & Pivoting
            chisel, ligolo, ligolo-ng, gost, ssf, sshuttle, rpivot,
            revsocks, 3proxy, proxychains, nps, frp, ngrok, bore,
            # Evasion
            veil, shellter, msfencode, shikata_ga_nai,
            scarecrow, donut, pe2shc, sharpshooter,
            # Recon
            amass, subfinder, assetfinder, findomain, knockpy,
            masscan, rustscan, naabu, zmap,
            eyewitness, aquatone, gowitness, webscreenshot,
            theHarvester, recon-ng, maltego, spiderfoot,
            # Active Directory
            pingcastle, adalanche, aced, certipy, petitpotam,
            zerologon, printnightmare, samaccountname,
            # Cloud
            pacu, prowler, scoutsuite, cloudsploit, pmapper
          ]
        
        - list: c2_frameworks
          items: [
            # Commercial/Professional C2
            cobaltstrike, cobalt, beacon, teamserver,
            brute_ratel, badger, bruteratel,
            nighthawk,
            # Open Source C2
            sliver, metasploit, msfconsole,
            empire, starkiller, powershell-empire,
            covenant, grunt, elite,
            mythic, apfell, poseidon, apollo, athena,
            havoc, demon, teamserver,
            villain, hoaxshell,
            pupy, pupysh,
            koadic, zombie,
            silenttrinity, st,
            poshc2,
            merlin, merlinserver,
            faction,
            deimos,
            ares,
            # Lightweight/Minimal C2
            tinyshell, icmpsh, dnscat, dnscat2,
            powercat, nishang,
            hoaxshell, villain,
            # DNS-based C2
            iodine, iodined, dns2tcp, dnscat, dnscat2, dnschef,
            # ICMP-based C2
            icmpsh, icmptunnel, ptunnel, hans,
            # HTTP-based C2
            pwncat, netcat, ncat, socat
          ]
        
        - list: webshell_names
          items: [
            # PHP Webshells
            c99, c100, r57, r58, b374k, wso, wso2, alfa, alfav3, alfav4,
            indoxploit, flavioxploit, b374k, mini, madspot, cyb3r, blackhat,
            k8gege, antak, p0wny, weevely, phpspy, phpkit, cgitelnet,
            simple_backdoor, php_backdoor, single_shell, safe0ver,
            ghoster, antichat, milw0rm, 1337, w4ck1ng, tryag, locus7s,
            nst, fx29, dq99, uploader, upbeta, small, telnet, tool,
            passion, myshell, lostdc, h4ntu, haxor, dx, cyberlord,
            casing, caidao, chopper, behinder, godzilla, aihttps,
            # JSP Webshells  
            jspspy, cmdjsp, jshell, jsp_cmd, cmdline, shell_jsp,
            browser, browser_jsp, upload_jsp, hack_jsp,
            # ASP/ASPX Webshells
            cmdasp, aspxspy, devilzshell, nightmare, zehir, indexer,
            # General names (any extension)
            shell, cmd, command, backdoor, hack, pwn, own, execute,
            upload, uploader, file, files, manager, admin, test123,
            config, configuration, setup, install, tmp, temp, cache,
            eval, assert, system, passthru, exec, base64, reverse,
            connect, socket, tunnel, proxy, gate, door
          ]
        
        - list: webshell_indicators
          items: [
            "eval(", "base64_decode(", "gzinflate(", "gzuncompress(",
            "str_rot13(", "assert(", "create_function(", "call_user_func(",
            "preg_replace", "passthru(", "shell_exec(", "system(",
            "exec(", "popen(", "proc_open(", "pcntl_exec(",
            "$_GET[", "$_POST[", "$_REQUEST[", "$_FILES[",
            "fsockopen(", "stream_socket_client(", "curl_exec(",
            "file_get_contents(", "file_put_contents(",
            "Runtime.getRuntime().exec", "ProcessBuilder",
            "ScriptEngine", "javax.script"
          ]
        
        - list: suspicious_directories
          items: [/tmp, /var/tmp, /dev/shm, /run/shm, /var/run, /run]
        
        - list: ebpf_tools
          items: [
            bpftool, bpftrace, bpfcc-tools, bcc-tools,
            tcptracer, execsnoop, opensnoop, biosnoop,
            capable, tcpconnect, tcpaccept, tcpretrans,
            bpf_load, libbpf, cilium
          ]
        
        # ============================================================================
        # ROOTKIT DETECTION RULES
        # ============================================================================
        
        - rule: ROOTKIT - Kernel Module Loaded
          desc: Detect kernel module loading (potential rootkit)
          condition: >
            evt.type in (init_module, finit_module) and
            not salt_or_ansible
          output: >
            CRITICAL [ROOTKIT] Kernel module loaded
            (user=%user.name user_uid=%user.uid module=%proc.cmdline
            parent=%proc.pname gparent=%proc.aname[2])
          priority: CRITICAL
          tags: [ccdc, rootkit, kernel, mitre_persistence, mitre_defense_evasion]
        
        - rule: ROOTKIT - Kernel Module Unloaded
          desc: Detect kernel module removal (hiding tracks)
          condition: evt.type = delete_module
          output: >
            CRITICAL [ROOTKIT] Kernel module unloaded
            (user=%user.name user_uid=%user.uid module=%evt.arg.name
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, kernel, mitre_defense_evasion]
        
        - rule: ROOTKIT - LD_PRELOAD Injection
          desc: Detect LD_PRELOAD environment variable manipulation
          condition: >
            spawned_process and
            (proc.env contains "LD_PRELOAD" or
             proc.cmdline contains "LD_PRELOAD" or
             proc.cmdline contains "ld.so.preload")
          output: >
            CRITICAL [ROOTKIT] LD_PRELOAD injection detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname env=%proc.env)
          priority: CRITICAL
          tags: [ccdc, rootkit, ld_preload, mitre_persistence, mitre_defense_evasion]
        
        - rule: ROOTKIT - ld.so.preload Modified
          desc: Detect modification of /etc/ld.so.preload
          condition: >
            (open_write or open_read_write) and
            fd.name = /etc/ld.so.preload
          output: >
            CRITICAL [ROOTKIT] /etc/ld.so.preload modified
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, ld_preload, mitre_persistence]
        
        - rule: ROOTKIT - Shared Library Directory Modified
          desc: Detect suspicious writes to shared library directories
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /lib/ or
             fd.name startswith /lib64/ or
             fd.name startswith /usr/lib/ or
             fd.name startswith /usr/lib64/) and
            fd.name endswith ".so" and
            not package_managers and
            not salt_or_ansible
          output: >
            CRITICAL [ROOTKIT] Shared library modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, library_injection, mitre_persistence]
        
        - rule: ROOTKIT - ld.so.cache Modified
          desc: Detect modification of dynamic linker cache
          condition: >
            (open_write or open_read_write) and
            fd.name = /etc/ld.so.cache and
            not proc.name = ldconfig
          output: >
            CRITICAL [ROOTKIT] ld.so.cache modified outside ldconfig
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, mitre_defense_evasion]
        
        - rule: ROOTKIT - Proc Filesystem Manipulation
          desc: Detect writes to /proc (hiding processes)
          condition: >
            (open_write or open_read_write) and
            fd.name startswith /proc/ and
            not fd.name startswith /proc/sys and
            not proc.name in (sysctl, systemd)
          output: >
            CRITICAL [ROOTKIT] /proc filesystem manipulation
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, proc_hiding, mitre_defense_evasion]
        
        - rule: ROOTKIT - Sys Filesystem Manipulation
          desc: Detect suspicious writes to /sys
          condition: >
            (open_write or open_read_write) and
            fd.name startswith /sys/ and
            not proc.name in (systemd, udevd, udevadm, modprobe)
          output: >
            WARNING [ROOTKIT] /sys filesystem manipulation
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, rootkit, mitre_defense_evasion]
        
        - rule: ROOTKIT - Dev Mem Access
          desc: Detect access to /dev/mem or /dev/kmem
          condition: >
            (open_read or open_write or open_read_write) and
            fd.name in (/dev/mem, /dev/kmem, /dev/port)
          output: >
            CRITICAL [ROOTKIT] Raw memory device accessed
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, memory_access, mitre_credential_access]
        
        - rule: ROOTKIT - Hidden File Created
          desc: Detect creation of hidden files in suspicious locations
          condition: >
            (open_write or open_read_write) and
            fd.name contains "/." and
            (fd.directory in (suspicious_directories) or
             fd.directory = /root or
             fd.directory startswith /home) and
            not fd.name contains ".bash" and
            not fd.name contains ".profile" and
            not fd.name contains ".ssh" and
            not proc.name in (vim, vi, nano, emacs)
          output: >
            WARNING [ROOTKIT] Hidden file created
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, rootkit, hidden_files, mitre_defense_evasion]
        
        - rule: ROOTKIT - Known Rootkit Binary
          desc: Detect execution of known rootkit binaries
          condition: >
            spawned_process and
            proc.name in (rootkit_binaries)
          output: >
            CRITICAL [ROOTKIT] Known rootkit binary executed
            (user=%user.name user_uid=%user.uid binary=%proc.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, mitre_persistence]
        
        - rule: ROOTKIT - Diamorphine Indicators
          desc: Detect Diamorphine rootkit specific indicators
          condition: >
            spawned_process and
            (proc.cmdline contains "diamorphine" or
             proc.cmdline contains "kill -31" or
             proc.cmdline contains "kill -63" or
             proc.cmdline contains "kill -64")
          output: >
            CRITICAL [ROOTKIT] Diamorphine rootkit indicator
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, diamorphine, mitre_persistence]
        
        - rule: ROOTKIT - Reptile Indicators
          desc: Detect Reptile rootkit indicators
          condition: >
            (spawned_process and proc.cmdline contains "reptile") or
            ((open_write or open_read_write) and fd.name contains "reptile")
          output: >
            CRITICAL [ROOTKIT] Reptile rootkit indicator
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            file=%fd.name parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, reptile, mitre_persistence]
        
        # ============================================================================
        # PERSISTENCE DETECTION RULES
        # ============================================================================
        
        - rule: PERSIST - SSH Authorized Keys Modified
          desc: Detect SSH authorized_keys file modifications
          condition: >
            (open_write or open_read_write) and
            fd.name contains "authorized_keys" and
            not salt_or_ansible
          output: >
            CRITICAL [PERSIST] SSH authorized_keys modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, ssh, mitre_persistence, T1098]
        
        - rule: PERSIST - SSH Config Modified
          desc: Detect SSH configuration changes
          condition: >
            (open_write or open_read_write) and
            (fd.name = /etc/ssh/sshd_config or
             fd.name startswith /etc/ssh/sshd_config.d/) and
            not salt_or_ansible
          output: >
            CRITICAL [PERSIST] SSH config modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, ssh, mitre_persistence]
        
        - rule: PERSIST - Cron Job Created
          desc: Detect cron job creation or modification
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/cron or
             fd.name startswith /var/spool/cron or
             fd.name = /etc/crontab or
             fd.name startswith /etc/anacrontab) and
            not salt_or_ansible
          output: >
            CRITICAL [PERSIST] Cron job modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, cron, mitre_persistence, T1053]
        
        - rule: PERSIST - Systemd Service Created
          desc: Detect systemd service file creation
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/systemd/system or
             fd.name startswith /usr/lib/systemd/system or
             fd.name startswith /lib/systemd/system or
             fd.name startswith /run/systemd/system) and
            (fd.name endswith ".service" or fd.name endswith ".timer") and
            not salt_or_ansible and
            not package_managers
          output: >
            CRITICAL [PERSIST] Systemd service/timer created
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, systemd, mitre_persistence, T1543]
        
        - rule: PERSIST - Init Script Created
          desc: Detect init script creation (sysvinit/rc.d)
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/init.d or
             fd.name startswith /etc/rc.d or
             fd.name startswith /etc/rc.local or
             fd.name = /etc/rc.local) and
            not salt_or_ansible and
            not package_managers
          output: >
            CRITICAL [PERSIST] Init script created/modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, init, mitre_persistence, T1037]
        
        - rule: PERSIST - Shell Profile Modified
          desc: Detect shell profile modifications for persistence
          condition: >
            (open_write or open_read_write) and
            (fd.name endswith ".bashrc" or
             fd.name endswith ".bash_profile" or
             fd.name endswith ".profile" or
             fd.name endswith ".zshrc" or
             fd.name endswith ".cshrc" or
             fd.name = /etc/profile or
             fd.name startswith /etc/profile.d or
             fd.name = /etc/bash.bashrc or
             fd.name = /etc/bashrc) and
            not salt_or_ansible and
            not proc.name in (vim, vi, nano, emacs)
          output: >
            CRITICAL [PERSIST] Shell profile modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, shell_profile, mitre_persistence, T1546]
        
        - rule: PERSIST - PAM Configuration Modified
          desc: Detect PAM configuration changes
          condition: >
            (open_write or open_read_write) and
            fd.name startswith /etc/pam.d and
            not salt_or_ansible and
            not package_managers
          output: >
            CRITICAL [PERSIST] PAM configuration modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, pam, mitre_persistence, mitre_credential_access]
        
        - rule: PERSIST - User Account Created
          desc: Detect new user account creation
          condition: >
            spawned_process and
            proc.name in (useradd, adduser, usermod) and
            not salt_or_ansible
          output: >
            CRITICAL [PERSIST] User account activity
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, user_account, mitre_persistence, T1136]
        
        - rule: PERSIST - Sudoers Modified
          desc: Detect sudoers file modifications
          condition: >
            (open_write or open_read_write) and
            (fd.name = /etc/sudoers or fd.name startswith /etc/sudoers.d) and
            not proc.name = visudo and
            not salt_or_ansible
          output: >
            CRITICAL [PERSIST] Sudoers modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, sudoers, mitre_persistence, mitre_privilege_escalation]
        
        - rule: PERSIST - Binary Replaced
          desc: Detect replacement of system binaries
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /bin/ or
             fd.name startswith /sbin/ or
             fd.name startswith /usr/bin/ or
             fd.name startswith /usr/sbin/) and
            not package_managers and
            not salt_or_ansible
          output: >
            CRITICAL [PERSIST] System binary replaced
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, binary_replacement, mitre_persistence, T1554]
        
        - rule: PERSIST - At Job Created
          desc: Detect at job scheduling
          condition: >
            spawned_process and
            proc.name in (at, atq, atrm, batch)
          output: >
            WARNING [PERSIST] At job scheduled
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, persistence, at, mitre_persistence, T1053]
        
        - rule: PERSIST - MOTD Modified
          desc: Detect MOTD script modifications for persistence
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/update-motd.d or
             fd.name = /etc/motd) and
            not salt_or_ansible
          output: >
            WARNING [PERSIST] MOTD modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, persistence, motd, mitre_persistence]
        
        - rule: PERSIST - Xinetd Modified
          desc: Detect xinetd configuration changes
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/xinetd or fd.name = /etc/inetd.conf)
          output: >
            CRITICAL [PERSIST] Xinetd/inetd configuration modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, xinetd, mitre_persistence]
        
        - rule: PERSIST - Udev Rules Modified
          desc: Detect udev rules modifications
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/udev/rules.d or
             fd.name startswith /lib/udev/rules.d) and
            not salt_or_ansible and
            not package_managers
          output: >
            WARNING [PERSIST] Udev rules modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, persistence, udev, mitre_persistence]
        
        # ============================================================================
        # CREDENTIAL ACCESS RULES
        # ============================================================================
        
        - rule: CREDS - Shadow File Access
          desc: Detect access to /etc/shadow
          condition: >
            open_read and
            fd.name = /etc/shadow and
            not proc.name in (sshd, sudo, su, passwd, useradd, usermod, login, chage, unix_chkpwd, pam)
          output: >
            CRITICAL [CREDS] Shadow file accessed
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, credentials, shadow, mitre_credential_access, T1003]
        
        - rule: CREDS - Password Hash Dump
          desc: Detect password hash extraction attempts
          condition: >
            spawned_process and
            (proc.cmdline contains "/etc/shadow" or
             proc.cmdline contains "unshadow" or
             proc.cmdline contains "pwdump" or
             proc.cmdline contains "hashdump")
          output: >
            CRITICAL [CREDS] Password hash dump attempt
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, credentials, hash_dump, mitre_credential_access, T1003]
        
        - rule: CREDS - SSH Private Key Access
          desc: Detect access to SSH private keys
          condition: >
            open_read and
            (fd.name contains "id_rsa" or
             fd.name contains "id_dsa" or
             fd.name contains "id_ecdsa" or
             fd.name contains "id_ed25519") and
            not fd.name contains ".pub" and
            not proc.name in (sshd, ssh, ssh-agent, ssh-add)
          output: >
            CRITICAL [CREDS] SSH private key accessed
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, credentials, ssh_keys, mitre_credential_access, T1552]
        
        - rule: CREDS - Keyring Access
          desc: Detect access to keyring/wallet files
          condition: >
            open_read and
            (fd.name contains ".gnupg" or
             fd.name contains "keyrings" or
             fd.name contains ".pki" or
             fd.name contains "wallet")
          output: >
            WARNING [CREDS] Keyring/wallet accessed
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, credentials, keyring, mitre_credential_access]
        
        - rule: CREDS - History File Access
          desc: Detect access to shell history files
          condition: >
            open_read and
            (fd.name contains ".bash_history" or
             fd.name contains ".zsh_history" or
             fd.name contains ".history" or
             fd.name contains ".mysql_history" or
             fd.name contains ".psql_history") and
            not proc.name in (bash, zsh, sh)
          output: >
            WARNING [CREDS] Shell history accessed
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, credentials, history, mitre_credential_access, T1552]
        
        - rule: CREDS - Web Application Config Access
          desc: Detect access to web application config files
          condition: >
            open_read and
            (fd.name contains "wp-config.php" or
             fd.name contains "config.php" or
             fd.name contains "settings.py" or
             fd.name contains "database.yml" or
             fd.name contains ".env" or
             fd.name contains "secrets.yml")
          output: >
            WARNING [CREDS] Web app config accessed
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, credentials, web_config, mitre_credential_access]
        
        # ============================================================================
        # PRIVILEGE ESCALATION RULES
        # ============================================================================
        
        - rule: PRIVESC - SUID Binary Created
          desc: Detect creation of SUID binaries
          condition: >
            evt.type = chmod and
            evt.arg.mode contains "S_ISUID"
          output: >
            CRITICAL [PRIVESC] SUID binary created
            (user=%user.name user_uid=%user.uid file=%evt.arg.path
            mode=%evt.arg.mode command=%proc.cmdline)
          priority: CRITICAL
          tags: [ccdc, privesc, suid, mitre_privilege_escalation, T1548]
        
        - rule: PRIVESC - Capabilities Set
          desc: Detect setting of file capabilities
          condition: >
            spawned_process and
            proc.name = setcap
          output: >
            CRITICAL [PRIVESC] File capabilities modified
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, privesc, capabilities, mitre_privilege_escalation]
        
        - rule: PRIVESC - Sudo Abuse
          desc: Detect suspicious sudo usage
          condition: >
            spawned_process and
            proc.name = sudo and
            (proc.cmdline contains "ALL" or
             proc.cmdline contains "NOPASSWD" or
             proc.cmdline contains "/bin/bash" or
             proc.cmdline contains "/bin/sh")
          output: >
            WARNING [PRIVESC] Suspicious sudo usage
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, privesc, sudo, mitre_privilege_escalation, T1548]
        
        - rule: PRIVESC - Polkit Exploitation
          desc: Detect potential polkit exploitation
          condition: >
            spawned_process and
            (proc.cmdline contains "pkexec" or
             proc.cmdline contains "polkit")
          output: >
            WARNING [PRIVESC] Polkit activity
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, privesc, polkit, mitre_privilege_escalation]
        
        # ============================================================================
        # COMMAND AND CONTROL RULES
        # ============================================================================
        
        - rule: C2 - Reverse Shell
          desc: Detect reverse shell establishment
          condition: >
            spawned_process and
            ((proc.name in (nc, ncat, netcat) and
              (proc.cmdline contains "-e" or proc.cmdline contains "-c")) or
             (proc.name = bash and proc.cmdline contains "/dev/tcp") or
             (proc.name in (python, python2, python3) and proc.cmdline contains "socket") or
             (proc.name = perl and proc.cmdline contains "socket") or
             (proc.name = php and proc.cmdline contains "fsockopen") or
             (proc.name = ruby and proc.cmdline contains "TCPSocket") or
             (proc.cmdline contains "bash -i" and proc.cmdline contains "&"))
          output: >
            CRITICAL [C2] Reverse shell detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, reverse_shell, mitre_command_and_control, T1059]
        
        - rule: C2 - Suspicious Download
          desc: Detect downloading and executing scripts
          condition: >
            spawned_process and
            proc.name in (curl, wget) and
            (proc.cmdline contains "|" or
             proc.cmdline contains ".sh" or
             proc.cmdline contains ".py" or
             proc.cmdline contains ".pl" or
             proc.cmdline contains "raw.githubusercontent" or
             proc.cmdline contains "pastebin" or
             proc.cmdline contains "transfer.sh" or
             proc.cmdline contains "ngrok")
          output: >
            WARNING [C2] Suspicious download
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, c2, download, mitre_command_and_control, T1105]
        
        - rule: C2 - DNS Tunneling Indicators
          desc: Detect potential DNS tunneling
          condition: >
            spawned_process and
            (proc.name in (dnscat, dnscat2, iodine, dns2tcp) or
             proc.cmdline contains "dns2tcp" or
             proc.cmdline contains "dnscat")
          output: >
            CRITICAL [C2] DNS tunneling tool detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, dns_tunnel, mitre_command_and_control, T1071]
        
        - rule: C2 - Cryptocurrency Miner
          desc: Detect cryptocurrency miner execution
          condition: >
            spawned_process and
            (proc.name in (miner_binaries) or
             proc.cmdline contains "stratum" or
             proc.cmdline contains "nicehash" or
             proc.cmdline contains "monero" or
             proc.cmdline contains "bitcoin")
          output: >
            CRITICAL [C2] Cryptocurrency miner detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, miner, mitre_impact]
        
        # ============================================================================
        # DEFENSE EVASION RULES
        # ============================================================================
        
        - rule: EVASION - Log Tampering
          desc: Detect log file deletion or truncation
          condition: >
            ((evt.type in (unlink, unlinkat) and evt.arg.name startswith /var/log) or
             (open_write and fd.name startswith /var/log and proc.name in (cat, echo, truncate))) and
            not proc.name in (logrotate, journald, rsyslogd, syslog-ng)
          output: >
            CRITICAL [EVASION] Log tampering detected
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, evasion, logs, mitre_defense_evasion, T1070]
        
        - rule: EVASION - History Cleared
          desc: Detect shell history clearing
          condition: >
            spawned_process and
            (proc.cmdline contains "history -c" or
             proc.cmdline contains "history -w" or
             proc.cmdline contains "unset HISTFILE" or
             proc.cmdline contains "export HISTFILE=/dev/null" or
             proc.cmdline contains "HISTSIZE=0" or
             proc.cmdline contains "rm.*history")
          output: >
            CRITICAL [EVASION] Shell history cleared
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, evasion, history, mitre_defense_evasion, T1070]
        
        - rule: EVASION - Timestomp
          desc: Detect file timestamp manipulation
          condition: >
            spawned_process and
            proc.name = touch and
            (proc.cmdline contains "-t" or
             proc.cmdline contains "-d" or
             proc.cmdline contains "--date" or
             proc.cmdline contains "-r")
          output: >
            WARNING [EVASION] Timestamp manipulation
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, evasion, timestomp, mitre_defense_evasion, T1070]
        
        - rule: EVASION - Process Hiding
          desc: Detect process hiding attempts
          condition: >
            spawned_process and
            (proc.cmdline contains "exec -a" or
             proc.cmdline contains "prctl" or
             proc.cmdline contains "argv0")
          output: >
            WARNING [EVASION] Process hiding attempt
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, evasion, process_hiding, mitre_defense_evasion]
        
        - rule: EVASION - Disable Security Tools
          desc: Detect attempts to disable security tools
          condition: >
            spawned_process and
            ((proc.name = systemctl and proc.cmdline contains "stop") or
             (proc.name = service and proc.cmdline contains "stop") or
             proc.name = pkill or proc.name = killall) and
            (proc.cmdline contains "falco" or
             proc.cmdline contains "auditd" or
             proc.cmdline contains "ossec" or
             proc.cmdline contains "wazuh" or
             proc.cmdline contains "fail2ban" or
             proc.cmdline contains "iptables" or
             proc.cmdline contains "firewalld" or
             proc.cmdline contains "apparmor" or
             proc.cmdline contains "selinux")
          output: >
            CRITICAL [EVASION] Security tool disabled
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, evasion, disable_security, mitre_defense_evasion, T1562]
        
        # ============================================================================
        # WEBSHELL DETECTION RULES
        # ============================================================================
        
        - rule: WEBSHELL - Shell from Web Server
          desc: Detect shell spawned from web server process
          condition: >
            spawned_process and
            proc.pname in (apache2, httpd, nginx, php-fpm, php, php-cgi, tomcat, java, node, www-data) and
            proc.name in (bash, sh, dash, zsh, csh, python, python3, perl, ruby, nc, ncat)
          output: >
            CRITICAL [WEBSHELL] Shell from web server
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname gparent=%proc.aname[2])
          priority: CRITICAL
          tags: [ccdc, webshell, mitre_persistence, T1505]
        
        - rule: WEBSHELL - Suspicious Web Directory Write
          desc: Detect suspicious files written to web directories
          condition: >
            (open_write or open_read_write) and
            (fd.directory startswith /var/www or
             fd.directory startswith /srv/www or
             fd.directory startswith /usr/share/nginx or
             fd.directory startswith /var/lib/tomcat) and
            (fd.name endswith ".php" or
             fd.name endswith ".jsp" or
             fd.name endswith ".jspx" or
             fd.name endswith ".asp" or
             fd.name endswith ".aspx" or
             fd.name endswith ".sh" or
             fd.name endswith ".py" or
             fd.name contains "shell" or
             fd.name contains "cmd" or
             fd.name contains "backdoor" or
             fd.name contains "c99" or
             fd.name contains "r57" or
             fd.name contains "b374k")
          output: >
            CRITICAL [WEBSHELL] Suspicious file in webroot
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, mitre_persistence, T1505]
        
        # ============================================================================
        # RECONNAISSANCE RULES
        # ============================================================================
        
        - rule: RECON - Network Scanning
          desc: Detect network scanning tools
          condition: >
            spawned_process and
            proc.name in (network_recon_tools)
          output: >
            WARNING [RECON] Network scanning tool
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, recon, scanning, mitre_discovery, T1046]
        
        - rule: RECON - Internal Discovery
          desc: Detect internal network/host discovery
          condition: >
            spawned_process and
            (proc.cmdline contains "ifconfig" or
             proc.cmdline contains "ip addr" or
             proc.cmdline contains "ip route" or
             proc.cmdline contains "netstat" or
             proc.cmdline contains "ss -" or
             proc.cmdline contains "arp -a" or
             proc.cmdline contains "cat /etc/hosts" or
             proc.cmdline contains "cat /etc/resolv.conf")
          output: >
            WARNING [RECON] Internal discovery
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, recon, discovery, mitre_discovery]
        
        - rule: RECON - Hacking Tools
          desc: Detect known hacking/pentest tools
          condition: >
            spawned_process and
            proc.name in (hacking_tools)
          output: >
            CRITICAL [RECON] Hacking tool detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, recon, hacking_tools, mitre_execution]
        
        # ============================================================================
        # DATA EXFILTRATION RULES
        # ============================================================================
        
        - rule: EXFIL - Bulk File Archive
          desc: Detect bulk archiving of files
          condition: >
            spawned_process and
            proc.name in (tar, zip, gzip, bzip2, xz, 7z, rar) and
            (proc.cmdline contains "/home" or
             proc.cmdline contains "/etc" or
             proc.cmdline contains "/var/www" or
             proc.cmdline contains "/root")
          output: >
            WARNING [EXFIL] Bulk file archiving
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, exfil, archive, mitre_collection, T1560]
        
        - rule: EXFIL - Data Transfer Tools
          desc: Detect data transfer to external locations
          condition: >
            spawned_process and
            (proc.name in (scp, rsync, ftp, sftp) or
             (proc.name in (curl, wget) and proc.cmdline contains "POST") or
             proc.cmdline contains "nc -w" or
             proc.cmdline contains "ncat -w")
          output: >
            WARNING [EXFIL] Data transfer activity
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, exfil, transfer, mitre_exfiltration, T1048]
        
        # ============================================================================
        # GENERAL SECURITY BASELINE
        # ============================================================================
        
        - rule: BASELINE - Suspicious Process in Temp
          desc: Detect execution from temporary directories
          condition: >
            spawned_process and
            (proc.exepath startswith /tmp or
             proc.exepath startswith /var/tmp or
             proc.exepath startswith /dev/shm or
             proc.exepath startswith /run/shm)
          output: >
            WARNING [BASELINE] Execution from temp directory
            (user=%user.name user_uid=%user.uid exe=%proc.exepath
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, baseline, temp_exec, mitre_execution]
        
        - rule: BASELINE - Suspicious Parent-Child
          desc: Detect unusual process parent-child relationships
          condition: >
            spawned_process and
            shell_procs and
            proc.pname in (mysql, mysqld, postgres, mongod, redis-server, memcached)
          output: >
            CRITICAL [BASELINE] Shell from database process
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, baseline, suspicious_parent, mitre_execution]
        
        - rule: BASELINE - Hosts File Modified
          desc: Detect /etc/hosts modifications
          condition: >
            (open_write or open_read_write) and
            fd.name = /etc/hosts and
            not salt_or_ansible
          output: >
            WARNING [BASELINE] Hosts file modified
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, baseline, hosts, mitre_defense_evasion]
        
        - rule: BASELINE - Resolv.conf Modified
          desc: Detect DNS resolver modifications
          condition: >
            (open_write or open_read_write) and
            fd.name = /etc/resolv.conf and
            not salt_or_ansible and
            not proc.name in (dhclient, NetworkManager, systemd-resolved)
          output: >
            WARNING [BASELINE] DNS resolver modified
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, baseline, dns, mitre_defense_evasion]
        
        - rule: BASELINE - Firewall Modified
          desc: Detect firewall rule changes
          condition: >
            spawned_process and
            proc.name in (iptables, ip6tables, nft, nftables, firewall-cmd, ufw) and
            not salt_or_ansible
          output: >
            WARNING [BASELINE] Firewall modified
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, baseline, firewall, mitre_defense_evasion]
        
        - rule: BASELINE - Netcat Listener
          desc: Detect netcat listening on a port
          condition: >
            spawned_process and
            proc.name in (nc, ncat, netcat) and
            (proc.cmdline contains "-l" or proc.cmdline contains "-p")
          output: >
            CRITICAL [BASELINE] Netcat listener detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, baseline, netcat, mitre_command_and_control]
        
        # ============================================================================
        # ADDITIONAL ROOTKIT DETECTION RULES
        # ============================================================================
        
        - rule: ROOTKIT - Known Rootkit Kernel Module
          desc: Detect loading of known rootkit kernel modules
          condition: >
            (evt.type in (init_module, finit_module) or
             (spawned_process and proc.name in (insmod, modprobe))) and
            (evt.arg.name in (rootkit_kernel_modules) or
             proc.cmdline intersects (rootkit_kernel_modules))
          output: >
            CRITICAL [ROOTKIT] Known rootkit kernel module loaded
            (user=%user.name user_uid=%user.uid module=%evt.arg.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, kernel_module, mitre_persistence]
        
        - rule: ROOTKIT - Suspicious Kernel Module Path
          desc: Detect kernel modules loaded from non-standard paths
          condition: >
            spawned_process and
            proc.name in (insmod, modprobe) and
            (proc.cmdline contains "/tmp" or
             proc.cmdline contains "/var/tmp" or
             proc.cmdline contains "/dev/shm" or
             proc.cmdline contains "/home" or
             proc.cmdline contains "/root")
          output: >
            CRITICAL [ROOTKIT] Kernel module loaded from suspicious path
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, kernel_module, mitre_persistence]
        
        - rule: ROOTKIT - Hide Process via Kill Signal
          desc: Detect rootkit hide/unhide process signals (diamorphine style)
          condition: >
            evt.type = kill and
            (evt.arg.sig = 31 or evt.arg.sig = 63 or evt.arg.sig = 64)
          output: >
            CRITICAL [ROOTKIT] Suspicious kill signal detected (rootkit hide command)
            (user=%user.name user_uid=%user.uid signal=%evt.arg.sig
            target_pid=%evt.arg.pid command=%proc.cmdline)
          priority: CRITICAL
          tags: [ccdc, rootkit, diamorphine, process_hiding, mitre_defense_evasion]
        
        - rule: ROOTKIT - Syscall Table Modification
          desc: Detect attempts to access syscall table
          condition: >
            (open_read or open_write) and
            (fd.name contains "sys_call_table" or
             fd.name contains "ia32_sys_call_table" or
             fd.name = "/boot/System.map" or
             fd.name startswith "/boot/System.map-")
          output: >
            CRITICAL [ROOTKIT] Syscall table access attempt
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, syscall_table, mitre_defense_evasion]
        
        - rule: ROOTKIT - Kallsyms Access
          desc: Detect reading kernel symbols (common rootkit behavior)
          condition: >
            open_read and
            fd.name = "/proc/kallsyms" and
            not proc.name in (perf, systemd, journald, dmesg)
          output: >
            WARNING [ROOTKIT] Kernel symbols accessed
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, rootkit, kernel_symbols, mitre_discovery]
        
        - rule: ROOTKIT - Kcore Access
          desc: Detect access to kernel memory image
          condition: >
            (open_read or open_write) and
            fd.name = "/proc/kcore"
          output: >
            CRITICAL [ROOTKIT] Kernel memory accessed via /proc/kcore
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, kernel_memory, mitre_credential_access]
        
        - rule: ROOTKIT - Suspicious Library in LD Path
          desc: Detect suspicious additions to library search path
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/ld.so.conf.d or
             fd.name = /etc/ld.so.conf)
          output: >
            CRITICAL [ROOTKIT] Library search path modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, ld_preload, mitre_persistence]
        
        - rule: ROOTKIT - Module Hiding Attempt
          desc: Detect attempts to hide kernel modules
          condition: >
            spawned_process and
            (proc.cmdline contains "list_del" or
             proc.cmdline contains "kobject_del" or
             proc.cmdline contains "module_hide")
          output: >
            CRITICAL [ROOTKIT] Module hiding attempt detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, rootkit, module_hiding, mitre_defense_evasion]
        
        # ============================================================================
        # eBPF ABUSE DETECTION RULES
        # ============================================================================
        
        - rule: EBPF - BPF Program Loaded
          desc: Detect BPF program loading (potential BPFdoor/rootkit)
          condition: >
            evt.type = bpf and
            not proc.name in (cilium, calico, falco, sysdig, bpftrace, systemd) and
            not salt_or_ansible
          output: >
            CRITICAL [EBPF] BPF program loaded
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname evt_type=%evt.type)
          priority: CRITICAL
          tags: [ccdc, ebpf, bpfdoor, mitre_persistence, mitre_defense_evasion]
        
        - rule: EBPF - BPFdoor Indicators
          desc: Detect BPFdoor specific patterns
          condition: >
            (spawned_process and
             (proc.cmdline contains "BPF_PROG_TYPE_SOCKET_FILTER" or
              proc.cmdline contains "SO_ATTACH_FILTER" or
              proc.cmdline contains "raw socket" or
              proc.name contains "bpfdoor")) or
            ((open_read or open_write) and
             (fd.name contains "bpfdoor" or fd.name contains "/dev/shm/kdmtmpflush"))
          output: >
            CRITICAL [EBPF] BPFdoor rootkit indicators detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            file=%fd.name parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, ebpf, bpfdoor, rootkit, mitre_persistence]
        
        - rule: EBPF - Suspicious BPF Tool Usage
          desc: Detect use of BPF tools that could be abused
          condition: >
            spawned_process and
            proc.name in (ebpf_tools) and
            not proc.pname in (systemd, init, sshd, bash, sh) and
            not salt_or_ansible
          output: >
            WARNING [EBPF] BPF tool executed
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, ebpf, mitre_discovery]
        
        - rule: EBPF - Raw Socket with BPF
          desc: Detect raw socket creation with BPF filter (packet sniffing/BPFdoor)
          condition: >
            evt.type in (socket, socketpair) and
            evt.arg.domain = AF_PACKET and
            not proc.name in (tcpdump, wireshark, tshark, dhclient, NetworkManager, dhcpcd)
          output: >
            CRITICAL [EBPF] Raw socket created (potential BPFdoor)
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, ebpf, raw_socket, bpfdoor, mitre_command_and_control]
        
        - rule: EBPF - BPF Map Creation
          desc: Detect BPF map creation
          condition: >
            evt.type = bpf and
            evt.arg.cmd = BPF_MAP_CREATE and
            not proc.name in (cilium, calico, falco, sysdig, systemd)
          output: >
            WARNING [EBPF] BPF map created
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, ebpf, mitre_persistence]
        
        - rule: EBPF - Tracepoint Attachment
          desc: Detect attachment to kernel tracepoints via eBPF
          condition: >
            spawned_process and
            proc.cmdline contains "tracepoint" and
            proc.name in (bpftrace, bpftool) and
            not salt_or_ansible
          output: >
            WARNING [EBPF] Tracepoint attachment detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, ebpf, tracepoint, mitre_collection]
        
        - rule: EBPF - Kprobe Attachment
          desc: Detect kprobe/kretprobe attachment (kernel function hooking)
          condition: >
            (spawned_process and
             (proc.cmdline contains "kprobe" or proc.cmdline contains "kretprobe")) or
            ((open_write or open_read_write) and
             (fd.name startswith /sys/kernel/debug/tracing/kprobe or
              fd.name startswith /sys/kernel/tracing/kprobe))
          output: >
            CRITICAL [EBPF] Kernel probe attachment detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            file=%fd.name parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, ebpf, kprobe, mitre_persistence]
        
        - rule: EBPF - BTF Access
          desc: Detect access to BTF (BPF Type Format) data
          condition: >
            open_read and
            (fd.name startswith /sys/kernel/btf or
             fd.name contains ".btf") and
            not proc.name in (bpftool, bpftrace, cilium, falco, sysdig)
          output: >
            WARNING [EBPF] BTF data accessed
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, ebpf, btf, mitre_discovery]
        
        - rule: EBPF - Symbiote Rootkit Indicators
          desc: Detect Symbiote rootkit behavior (LD_PRELOAD + BPF)
          condition: >
            (spawned_process and proc.env contains "LD_PRELOAD") and
            (evt.type = bpf or proc.cmdline contains "BPF")
          output: >
            CRITICAL [EBPF] Symbiote rootkit indicators (LD_PRELOAD + BPF)
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            env=%proc.env parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, ebpf, symbiote, rootkit, mitre_persistence]
        
        # ============================================================================
        # ADDITIONAL C2 DETECTION RULES
        # ============================================================================
        
        - rule: C2 - Known C2 Framework
          desc: Detect execution of known C2 frameworks
          condition: >
            spawned_process and
            proc.name in (c2_frameworks)
          output: >
            CRITICAL [C2] Known C2 framework detected
            (user=%user.name user_uid=%user.uid binary=%proc.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, framework, mitre_command_and_control]
        
        - rule: C2 - Cobalt Strike Indicators
          desc: Detect Cobalt Strike beacon patterns
          condition: >
            spawned_process and
            (proc.cmdline contains "beacon" or
             proc.cmdline contains "cobaltstrike" or
             proc.cmdline contains "aggressor" or
             proc.cmdline contains "teamserver" or
             proc.cmdline contains "artifact.exe" or
             proc.cmdline contains "pipename" or
             proc.cmdline contains "spawnto")
          output: >
            CRITICAL [C2] Cobalt Strike indicators detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, cobaltstrike, mitre_command_and_control]
        
        - rule: C2 - Sliver C2 Indicators
          desc: Detect Sliver C2 patterns
          condition: >
            spawned_process and
            (proc.cmdline contains "sliver" or
             proc.cmdline contains "implant" or
             proc.cmdline contains "mtls" or
             proc.cmdline contains "wg-" or
             proc.name contains "sliver")
          output: >
            CRITICAL [C2] Sliver C2 indicators detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, sliver, mitre_command_and_control]
        
        - rule: C2 - Empire/Starkiller Indicators
          desc: Detect PowerShell Empire indicators
          condition: >
            spawned_process and
            (proc.cmdline contains "empire" or
             proc.cmdline contains "starkiller" or
             proc.cmdline contains "Invoke-Empire" or
             proc.cmdline contains "powershell -enc" or
             proc.cmdline contains "powershell -e " or
             proc.cmdline contains "FromBase64String")
          output: >
            CRITICAL [C2] Empire/PowerShell indicators detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, empire, mitre_command_and_control]
        
        - rule: C2 - Havoc Framework
          desc: Detect Havoc C2 framework
          condition: >
            spawned_process and
            (proc.cmdline contains "havoc" or
             proc.cmdline contains "demon" or
             proc.name contains "havoc")
          output: >
            CRITICAL [C2] Havoc framework indicators detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, havoc, mitre_command_and_control]
        
        - rule: C2 - Mythic Framework
          desc: Detect Mythic C2 framework
          condition: >
            spawned_process and
            (proc.cmdline contains "mythic" or
             proc.cmdline contains "apfell" or
             proc.cmdline contains "poseidon" or
             proc.cmdline contains "apollo" or
             proc.cmdline contains "athena")
          output: >
            CRITICAL [C2] Mythic framework indicators detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, mythic, mitre_command_and_control]
        
        - rule: C2 - HTTP Beacon Pattern
          desc: Detect HTTP beacon-like behavior
          condition: >
            spawned_process and
            proc.name in (curl, wget) and
            (proc.cmdline contains "-X POST" or proc.cmdline contains "--data") and
            proc.pname in (bash, sh, dash, python, python3, perl, ruby)
          output: >
            WARNING [C2] HTTP beacon pattern detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, c2, beacon, mitre_command_and_control]
        
        - rule: C2 - ICMP Tunnel
          desc: Detect ICMP tunneling tools
          condition: >
            spawned_process and
            proc.name in (icmpsh, icmptunnel, ptunnel, hans, icmp_tunnel)
          output: >
            CRITICAL [C2] ICMP tunnel detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, icmp_tunnel, mitre_command_and_control]
        
        - rule: C2 - Chisel Tunnel
          desc: Detect Chisel tunneling tool
          condition: >
            spawned_process and
            (proc.name = chisel or
             proc.cmdline contains "chisel" or
             proc.cmdline contains "r:socks" or
             proc.cmdline contains "R:socks")
          output: >
            CRITICAL [C2] Chisel tunnel detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, chisel, tunnel, mitre_command_and_control]
        
        - rule: C2 - Ligolo Tunnel
          desc: Detect Ligolo tunneling tool
          condition: >
            spawned_process and
            (proc.name contains "ligolo" or
             proc.cmdline contains "ligolo" or
             proc.cmdline contains "agent -connect")
          output: >
            CRITICAL [C2] Ligolo tunnel detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, ligolo, tunnel, mitre_command_and_control]
        
        - rule: C2 - Ngrok Tunnel
          desc: Detect Ngrok tunnel usage
          condition: >
            spawned_process and
            (proc.name = ngrok or proc.cmdline contains "ngrok")
          output: >
            CRITICAL [C2] Ngrok tunnel detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, ngrok, tunnel, mitre_command_and_control]
        
        - rule: C2 - FRP Tunnel
          desc: Detect FRP (Fast Reverse Proxy) tunnel
          condition: >
            spawned_process and
            (proc.name in (frpc, frps) or
             proc.cmdline contains "frpc" or
             proc.cmdline contains "frps")
          output: >
            CRITICAL [C2] FRP tunnel detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, frp, tunnel, mitre_command_and_control]
        
        - rule: C2 - Pwncat
          desc: Detect pwncat reverse shell framework
          condition: >
            spawned_process and
            (proc.name = pwncat or
             proc.cmdline contains "pwncat" or
             proc.cmdline contains "pwncat-cs")
          output: >
            CRITICAL [C2] Pwncat detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, pwncat, mitre_command_and_control]
        
        - rule: C2 - Encoded PowerShell Command
          desc: Detect encoded PowerShell execution
          condition: >
            spawned_process and
            proc.name in (powershell, pwsh, powershell.exe) and
            (proc.cmdline contains "-enc" or
             proc.cmdline contains "-e " or
             proc.cmdline contains "-EncodedCommand" or
             proc.cmdline contains "FromBase64String" or
             proc.cmdline contains "[Convert]::")
          output: >
            CRITICAL [C2] Encoded PowerShell command
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, powershell, encoded, mitre_execution]
        
        - rule: C2 - Python Reverse Shell
          desc: Detect Python-based reverse shells
          condition: >
            spawned_process and
            proc.name in (python, python2, python3) and
            (proc.cmdline contains "socket" and
             (proc.cmdline contains "connect" or
              proc.cmdline contains "subprocess" or
              proc.cmdline contains "pty.spawn" or
              proc.cmdline contains "os.dup2"))
          output: >
            CRITICAL [C2] Python reverse shell detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, python, reverse_shell, mitre_command_and_control]
        
        - rule: C2 - Perl Reverse Shell
          desc: Detect Perl-based reverse shells
          condition: >
            spawned_process and
            proc.name = perl and
            (proc.cmdline contains "socket" or
             proc.cmdline contains "IO::Socket" or
             proc.cmdline contains "fdopen")
          output: >
            CRITICAL [C2] Perl reverse shell detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, perl, reverse_shell, mitre_command_and_control]
        
        - rule: C2 - Ruby Reverse Shell
          desc: Detect Ruby-based reverse shells
          condition: >
            spawned_process and
            proc.name in (ruby, irb) and
            (proc.cmdline contains "TCPSocket" or
             proc.cmdline contains "socket")
          output: >
            CRITICAL [C2] Ruby reverse shell detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, ruby, reverse_shell, mitre_command_and_control]
        
        - rule: C2 - PHP Reverse Shell
          desc: Detect PHP-based reverse shells
          condition: >
            spawned_process and
            proc.name = php and
            (proc.cmdline contains "fsockopen" or
             proc.cmdline contains "pfsockopen" or
             proc.cmdline contains "stream_socket_client")
          output: >
            CRITICAL [C2] PHP reverse shell detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, php, reverse_shell, mitre_command_and_control]
        
        - rule: C2 - Socat Tunnel
          desc: Detect Socat tunnel usage
          condition: >
            spawned_process and
            proc.name = socat and
            (proc.cmdline contains "TCP:" or
             proc.cmdline contains "EXEC:" or
             proc.cmdline contains "PTY")
          output: >
            CRITICAL [C2] Socat tunnel detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, c2, socat, tunnel, mitre_command_and_control]
        
        # ============================================================================
        # ADDITIONAL PERSISTENCE RULES
        # ============================================================================
        
        - rule: PERSIST - Kernel Module Autoload
          desc: Detect modifications to kernel module autoload configuration
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/modules-load.d or
             fd.name = /etc/modules or
             fd.name startswith /etc/modprobe.d or
             fd.name = /etc/modprobe.conf)
          output: >
            CRITICAL [PERSIST] Kernel module autoload configuration modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, kernel, mitre_persistence]
        
        - rule: PERSIST - Dracut Module
          desc: Detect modifications to dracut (initramfs) modules
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/dracut.conf.d or
             fd.name startswith /usr/lib/dracut)
          output: >
            CRITICAL [PERSIST] Dracut/initramfs module modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, initramfs, mitre_persistence]
        
        - rule: PERSIST - GRUB Configuration
          desc: Detect modifications to GRUB bootloader
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/grub.d or
             fd.name startswith /boot/grub or
             fd.name startswith /boot/grub2 or
             fd.name = /etc/default/grub)
          output: >
            CRITICAL [PERSIST] GRUB bootloader configuration modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, grub, bootloader, mitre_persistence]
        
        - rule: PERSIST - Polkit Rules
          desc: Detect modifications to Polkit authorization rules
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/polkit-1 or
             fd.name startswith /usr/share/polkit-1)
          output: >
            CRITICAL [PERSIST] Polkit rules modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, polkit, mitre_persistence]
        
        - rule: PERSIST - DBus Service
          desc: Detect DBus service configuration changes
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/dbus-1 or
             fd.name startswith /usr/share/dbus-1) and
            fd.name endswith ".conf"
          output: >
            WARNING [PERSIST] DBus service configuration modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, persistence, dbus, mitre_persistence]
        
        - rule: PERSIST - User Systemd Service
          desc: Detect user-level systemd service creation
          condition: >
            (open_write or open_read_write) and
            fd.name contains ".config/systemd/user" and
            fd.name endswith ".service"
          output: >
            CRITICAL [PERSIST] User systemd service created
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, systemd, user_service, mitre_persistence]
        
        - rule: PERSIST - Systemd Timer
          desc: Detect systemd timer creation
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/systemd or
             fd.name startswith /usr/lib/systemd) and
            fd.name endswith ".timer"
          output: >
            CRITICAL [PERSIST] Systemd timer created
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, systemd, timer, mitre_persistence]
        
        - rule: PERSIST - Systemd Generator
          desc: Detect systemd generator modifications
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/systemd/system-generators or
             fd.name startswith /usr/lib/systemd/system-generators or
             fd.name startswith /lib/systemd/system-generators)
          output: >
            CRITICAL [PERSIST] Systemd generator modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, systemd, generator, mitre_persistence]
        
        - rule: PERSIST - Message of the Day Scripts
          desc: Detect MOTD update scripts modification
          condition: >
            (open_write or open_read_write) and
            fd.name startswith /etc/update-motd.d and
            not salt_or_ansible
          output: >
            CRITICAL [PERSIST] MOTD script modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, motd, mitre_persistence]
        
        - rule: PERSIST - Network Scripts
          desc: Detect network script modifications for persistence
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/network/if- or
             fd.name startswith /etc/NetworkManager/dispatcher.d or
             fd.name startswith /etc/dhcp/dhclient-exit-hooks or
             fd.name startswith /etc/ppp)
          output: >
            CRITICAL [PERSIST] Network script modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, network, mitre_persistence]
        
        - rule: PERSIST - APT/Yum Hooks
          desc: Detect package manager hook modifications
          condition: >
            (open_write or open_read_write) and
            (fd.name startswith /etc/apt/apt.conf.d or
             fd.name startswith /etc/yum/pluginconf.d or
             fd.name startswith /etc/dnf/plugins or
             fd.name = /etc/apt/apt.conf)
          output: >
            CRITICAL [PERSIST] Package manager hook modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, package_manager, mitre_persistence]
        
        - rule: PERSIST - Git Hooks
          desc: Detect Git hook modifications (persistence via dev tools)
          condition: >
            (open_write or open_read_write) and
            fd.name contains ".git/hooks" and
            (fd.name endswith "pre-commit" or
             fd.name endswith "post-commit" or
             fd.name endswith "pre-push" or
             fd.name endswith "post-merge")
          output: >
            WARNING [PERSIST] Git hook modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, persistence, git, mitre_persistence]
        
        - rule: PERSIST - Vim Plugin Persistence
          desc: Detect Vim plugin directory modifications for persistence
          condition: >
            (open_write or open_read_write) and
            (fd.name contains ".vim/plugin" or
             fd.name contains ".vim/autoload" or
             fd.name contains ".config/nvim")
          output: >
            WARNING [PERSIST] Vim plugin modified
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, persistence, vim, mitre_persistence]
        
        - rule: PERSIST - XDG Autostart
          desc: Detect XDG autostart entry creation
          condition: >
            (open_write or open_read_write) and
            (fd.name contains ".config/autostart" or
             fd.name startswith /etc/xdg/autostart) and
            fd.name endswith ".desktop"
          output: >
            CRITICAL [PERSIST] XDG autostart entry created
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, persistence, xdg, autostart, mitre_persistence]
        
        # ============================================================================
        # ADDITIONAL WEBSHELL DETECTION RULES
        # ============================================================================
        
        - rule: WEBSHELL - Known Webshell Name
          desc: Detect files with known webshell names
          condition: >
            (open_write or open_read_write) and
            (fd.name contains (webshell_names)) and
            (fd.directory startswith /var/www or
             fd.directory startswith /srv/www or
             fd.directory startswith /usr/share/nginx or
             fd.directory startswith /var/lib/tomcat or
             fd.directory startswith /opt/lampp/htdocs or
             fd.directory startswith /home)
          output: >
            CRITICAL [WEBSHELL] Known webshell name detected
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, mitre_persistence]
        
        - rule: WEBSHELL - China Chopper Indicators
          desc: Detect China Chopper webshell patterns
          condition: >
            (spawned_process and
             proc.pname in (apache2, httpd, nginx, php-fpm, php) and
             (proc.cmdline contains "base64_decode" or
              proc.cmdline contains "eval(" or
              proc.cmdline contains "assert(")) or
            ((open_write or open_read_write) and
             fd.directory startswith /var/www and
             fd.name contains "chopper")
          output: >
            CRITICAL [WEBSHELL] China Chopper indicators detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            file=%fd.name parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, china_chopper, mitre_persistence]
        
        - rule: WEBSHELL - Behinder/Godzilla Indicators
          desc: Detect Behinder/Godzilla webshell patterns
          condition: >
            (spawned_process and
             proc.pname in (apache2, httpd, nginx, php-fpm, php, java, tomcat) and
             (proc.cmdline contains "AES" or
              proc.cmdline contains "Cipher" or
              proc.cmdline contains "javax.crypto")) or
            ((open_write or open_read_write) and
             fd.directory startswith /var/www and
             (fd.name contains "behinder" or fd.name contains "godzilla"))
          output: >
            CRITICAL [WEBSHELL] Behinder/Godzilla webshell indicators
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            file=%fd.name parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, behinder, godzilla, mitre_persistence]
        
        - rule: WEBSHELL - JSP Webshell Activity
          desc: Detect JSP webshell execution
          condition: >
            spawned_process and
            proc.pname in (java, tomcat, catalina, jboss, wildfly, glassfish) and
            proc.name in (bash, sh, dash, cmd, powershell, python, perl)
          output: >
            CRITICAL [WEBSHELL] JSP webshell activity detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname gparent=%proc.aname[2])
          priority: CRITICAL
          tags: [ccdc, webshell, jsp, mitre_persistence]
        
        - rule: WEBSHELL - Weevely Shell
          desc: Detect Weevely webshell patterns
          condition: >
            spawned_process and
            (proc.cmdline contains "weevely" or
             (proc.pname in (php, php-fpm) and
              proc.cmdline contains "str_replace" and
              proc.cmdline contains "base64"))
          output: >
            CRITICAL [WEBSHELL] Weevely webshell detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, weevely, mitre_persistence]
        
        - rule: WEBSHELL - B374k Shell
          desc: Detect B374k webshell
          condition: >
            (open_write or open_read_write) and
            fd.directory startswith /var/www and
            (fd.name contains "b374k" or fd.name contains "b374")
          output: >
            CRITICAL [WEBSHELL] B374k webshell detected
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, b374k, mitre_persistence]
        
        - rule: WEBSHELL - WSO Shell
          desc: Detect WSO webshell
          condition: >
            (open_write or open_read_write) and
            fd.directory startswith /var/www and
            (fd.name contains "wso" or fd.name contains "wso2")
          output: >
            CRITICAL [WEBSHELL] WSO webshell detected
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, wso, mitre_persistence]
        
        - rule: WEBSHELL - PHP Input Wrapper
          desc: Detect PHP input wrapper abuse
          condition: >
            spawned_process and
            proc.pname in (php, php-fpm, apache2, httpd) and
            proc.cmdline contains "php://input"
          output: >
            CRITICAL [WEBSHELL] PHP input wrapper abuse
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, php, mitre_execution]
        
        - rule: WEBSHELL - Eval POST/GET
          desc: Detect direct eval of user input
          condition: >
            spawned_process and
            proc.pname in (php, php-fpm, apache2, httpd) and
            (proc.cmdline contains "eval($_" or
             proc.cmdline contains "assert($_" or
             proc.cmdline contains "create_function($_")
          output: >
            CRITICAL [WEBSHELL] Direct eval of user input
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, php, eval, mitre_execution]
        
        - rule: WEBSHELL - Web Database Tool
          desc: Detect database admin tools used as webshells
          condition: >
            spawned_process and
            proc.pname in (php, php-fpm, apache2, httpd) and
            (proc.cmdline contains "adminer" or
             proc.cmdline contains "phpmyadmin" or
             proc.cmdline contains "phpminiadmin")
          output: >
            WARNING [WEBSHELL] Web database tool execution
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, webshell, database, mitre_persistence]
        
        - rule: WEBSHELL - File Upload to Web Directory
          desc: Detect suspicious file uploads to web directories
          condition: >
            (open_write or open_read_write) and
            proc.pname in (apache2, httpd, nginx, php-fpm, php, java, tomcat) and
            (fd.directory startswith /var/www or
             fd.directory startswith /srv/www) and
            (fd.name endswith ".php" or
             fd.name endswith ".phtml" or
             fd.name endswith ".phar" or
             fd.name endswith ".php5" or
             fd.name endswith ".php7" or
             fd.name endswith ".jsp" or
             fd.name endswith ".jspx" or
             fd.name endswith ".asp" or
             fd.name endswith ".aspx" or
             fd.name endswith ".cfm" or
             fd.name endswith ".sh" or
             fd.name endswith ".py" or
             fd.name endswith ".pl" or
             fd.name endswith ".cgi")
          output: >
            CRITICAL [WEBSHELL] Suspicious file upload to web directory
            (user=%user.name user_uid=%user.uid file=%fd.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, webshell, upload, mitre_persistence]
        
        # ============================================================================
        # RED TEAM TOOL DETECTION RULES
        # ============================================================================
        
        - rule: REDTEAM - Known Hacking Tool
          desc: Detect execution of known hacking/pentest tools
          condition: >
            spawned_process and
            proc.name in (hacking_tools)
          output: >
            CRITICAL [REDTEAM] Known hacking tool executed
            (user=%user.name user_uid=%user.uid tool=%proc.name
            command=%proc.cmdline parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, hacking_tool, mitre_execution]
        
        - rule: REDTEAM - Impacket Tools
          desc: Detect Impacket tool execution
          condition: >
            spawned_process and
            (proc.cmdline contains "impacket" or
             proc.name in (secretsdump, getTGT, getST, getADUsers, 
                           psexec, smbexec, wmiexec, dcomexec, atexec,
                           ntlmrelayx, smbrelayx, karmaSMB, sniff))
          output: >
            CRITICAL [REDTEAM] Impacket tool detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, impacket, mitre_lateral_movement]
        
        - rule: REDTEAM - Mimikatz/Credential Dumper
          desc: Detect credential dumping tools
          condition: >
            spawned_process and
            (proc.name in (mimikatz, pypykatz, lsassy, procdump) or
             proc.cmdline contains "mimikatz" or
             proc.cmdline contains "sekurlsa" or
             proc.cmdline contains "lsadump" or
             proc.cmdline contains "kerberos::list")
          output: >
            CRITICAL [REDTEAM] Credential dumping tool detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, mimikatz, credential_dump, mitre_credential_access]
        
        - rule: REDTEAM - BloodHound/SharpHound
          desc: Detect Active Directory reconnaissance tools
          condition: >
            spawned_process and
            (proc.name in (bloodhound, sharphound) or
             proc.cmdline contains "bloodhound" or
             proc.cmdline contains "sharphound" or
             proc.cmdline contains "Invoke-BloodHound")
          output: >
            CRITICAL [REDTEAM] AD reconnaissance tool detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, bloodhound, ad_recon, mitre_discovery]
        
        - rule: REDTEAM - Responder
          desc: Detect Responder LLMNR/NBNS poisoning tool
          condition: >
            spawned_process and
            (proc.name = responder or
             proc.cmdline contains "responder" or
             proc.cmdline contains "Responder.py")
          output: >
            CRITICAL [REDTEAM] Responder detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, responder, mitre_credential_access]
        
        - rule: REDTEAM - CrackMapExec
          desc: Detect CrackMapExec tool
          condition: >
            spawned_process and
            (proc.name in (crackmapexec, cme, cmedb) or
             proc.cmdline contains "crackmapexec" or
             proc.cmdline contains "cme ")
          output: >
            CRITICAL [REDTEAM] CrackMapExec detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, crackmapexec, mitre_lateral_movement]
        
        - rule: REDTEAM - Linpeas/Winpeas
          desc: Detect privilege escalation enumeration scripts
          condition: >
            spawned_process and
            (proc.cmdline contains "linpeas" or
             proc.cmdline contains "winpeas" or
             proc.cmdline contains "linenum" or
             proc.cmdline contains "linux-exploit-suggester" or
             proc.cmdline contains "LinEnum")
          output: >
            CRITICAL [REDTEAM] Privilege escalation enumeration detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, privesc_enum, mitre_discovery]
        
        - rule: REDTEAM - Rubeus Kerberos Tool
          desc: Detect Rubeus Kerberos attack tool
          condition: >
            spawned_process and
            (proc.name = rubeus or
             proc.cmdline contains "rubeus" or
             proc.cmdline contains "asktgt" or
             proc.cmdline contains "asktgs" or
             proc.cmdline contains "kerberoast" or
             proc.cmdline contains "s4u")
          output: >
            CRITICAL [REDTEAM] Rubeus Kerberos tool detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, rubeus, kerberos, mitre_credential_access]
        
        - rule: REDTEAM - Evil-WinRM
          desc: Detect Evil-WinRM remote access tool
          condition: >
            spawned_process and
            (proc.cmdline contains "evil-winrm" or
             proc.cmdline contains "evilwinrm")
          output: >
            CRITICAL [REDTEAM] Evil-WinRM detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, evil_winrm, mitre_lateral_movement]
        
        - rule: REDTEAM - Kerbrute
          desc: Detect Kerbrute Kerberos brute force tool
          condition: >
            spawned_process and
            (proc.name = kerbrute or
             proc.cmdline contains "kerbrute" or
             proc.cmdline contains "userenum" or
             proc.cmdline contains "passwordspray")
          output: >
            CRITICAL [REDTEAM] Kerbrute detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, kerbrute, mitre_credential_access]
        
        - rule: REDTEAM - Enum4Linux
          desc: Detect enum4linux SMB enumeration
          condition: >
            spawned_process and
            (proc.cmdline contains "enum4linux" or
             proc.cmdline contains "enum4linux-ng")
          output: >
            CRITICAL [REDTEAM] Enum4linux detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, enum4linux, mitre_discovery]
        
        - rule: REDTEAM - SMBMap
          desc: Detect SMBMap tool
          condition: >
            spawned_process and
            proc.cmdline contains "smbmap"
          output: >
            CRITICAL [REDTEAM] SMBMap detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, smbmap, mitre_discovery]
        
        - rule: REDTEAM - SQLMap
          desc: Detect SQLMap SQL injection tool
          condition: >
            spawned_process and
            (proc.name = sqlmap or
             proc.cmdline contains "sqlmap")
          output: >
            CRITICAL [REDTEAM] SQLMap detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, sqlmap, mitre_initial_access]
        
        - rule: REDTEAM - Gobuster/FFuf/Dirbuster
          desc: Detect web directory brute forcing tools
          condition: >
            spawned_process and
            proc.name in (gobuster, ffuf, dirbuster, dirb, feroxbuster, wfuzz)
          output: >
            WARNING [REDTEAM] Web directory brute forcer detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, redteam, web_bruteforce, mitre_discovery]
        
        - rule: REDTEAM - Nuclei Scanner
          desc: Detect Nuclei vulnerability scanner
          condition: >
            spawned_process and
            (proc.name = nuclei or
             proc.cmdline contains "nuclei")
          output: >
            WARNING [REDTEAM] Nuclei scanner detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, redteam, nuclei, mitre_discovery]
        
        - rule: REDTEAM - Nmap Aggressive Scan
          desc: Detect aggressive Nmap scanning
          condition: >
            spawned_process and
            proc.name = nmap and
            (proc.cmdline contains "-A" or
             proc.cmdline contains "-sS" or
             proc.cmdline contains "-sV" or
             proc.cmdline contains "--script" or
             proc.cmdline contains "vuln")
          output: >
            WARNING [REDTEAM] Aggressive Nmap scan detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, redteam, nmap, mitre_discovery]
        
        - rule: REDTEAM - Masscan
          desc: Detect Masscan port scanner
          condition: >
            spawned_process and
            proc.name = masscan
          output: >
            WARNING [REDTEAM] Masscan detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, redteam, masscan, mitre_discovery]
        
        - rule: REDTEAM - Password Spray
          desc: Detect password spraying attempts
          condition: >
            spawned_process and
            (proc.cmdline contains "spray" or
             proc.cmdline contains "passwordspray" or
             proc.cmdline contains "password-spray")
          output: >
            CRITICAL [REDTEAM] Password spray detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, password_spray, mitre_credential_access]
        
        - rule: REDTEAM - PSPY Process Spy
          desc: Detect PSPY process monitoring tool
          condition: >
            spawned_process and
            (proc.name = pspy or
             proc.name contains "pspy" or
             proc.cmdline contains "pspy")
          output: >
            WARNING [REDTEAM] PSPY process spy detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: WARNING
          tags: [ccdc, redteam, pspy, mitre_discovery]
        
        - rule: REDTEAM - PrintSpoofer/Potato
          desc: Detect Windows privilege escalation exploits
          condition: >
            spawned_process and
            (proc.cmdline contains "printspoofer" or
             proc.cmdline contains "godpotato" or
             proc.cmdline contains "juicypotato" or
             proc.cmdline contains "sweetpotato" or
             proc.cmdline contains "rottenpotato" or
             proc.cmdline contains "hotpotato")
          output: >
            CRITICAL [REDTEAM] Potato/PrintSpoofer exploit detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, potato, mitre_privilege_escalation]
        
        - rule: REDTEAM - Certify/Certipy
          desc: Detect AD certificate abuse tools
          condition: >
            spawned_process and
            (proc.name in (certify, certipy) or
             proc.cmdline contains "certify" or
             proc.cmdline contains "certipy")
          output: >
            CRITICAL [REDTEAM] AD certificate abuse tool detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, adcs, mitre_credential_access]
        
        - rule: REDTEAM - LaZagne
          desc: Detect LaZagne credential recovery tool
          condition: >
            spawned_process and
            (proc.name = lazagne or
             proc.cmdline contains "lazagne")
          output: >
            CRITICAL [REDTEAM] LaZagne credential recovery detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, lazagne, mitre_credential_access]
        
        - rule: REDTEAM - Hashcat/John
          desc: Detect password cracking tools
          condition: >
            spawned_process and
            proc.name in (hashcat, john, johnny, hydra, medusa)
          output: >
            CRITICAL [REDTEAM] Password cracker detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, password_cracker, mitre_credential_access]
        
        - rule: REDTEAM - SharpCollection Tools
          desc: Detect SharpCollection .NET tools
          condition: >
            spawned_process and
            (proc.cmdline contains "Sharp" and
             (proc.cmdline contains "Hound" or
              proc.cmdline contains "Dump" or
              proc.cmdline contains "Roast" or
              proc.cmdline contains "Up" or
              proc.cmdline contains "View"))
          output: >
            CRITICAL [REDTEAM] Sharp* tool detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, sharp_tools, mitre_execution]
        
        - rule: REDTEAM - GTFOBins Abuse
          desc: Detect GTFOBins privilege escalation patterns
          condition: >
            spawned_process and
            ((proc.name = find and proc.cmdline contains "-exec") or
             (proc.name = vim and proc.cmdline contains "-c") or
             (proc.name = awk and proc.cmdline contains "system") or
             (proc.name = tar and proc.cmdline contains "--checkpoint") or
             (proc.name = zip and proc.cmdline contains "-T") or
             (proc.name = perl and proc.cmdline contains "-e") or
             (proc.name = python and proc.cmdline contains "os.system") or
             (proc.name = less and proc.cmdline contains "!"))
          output: >
            CRITICAL [REDTEAM] GTFOBins abuse pattern detected
            (user=%user.name user_uid=%user.uid command=%proc.cmdline
            parent=%proc.pname)
          priority: CRITICAL
          tags: [ccdc, redteam, gtfobins, mitre_privilege_escalation]

# ----------------------------------------------------------------------------
# CONFIGURE FALCO
# ----------------------------------------------------------------------------

falco_config:
  file.managed:
    - name: /etc/falco/falco.yaml
    - user: root
    - group: root
    - mode: 644
    - require:
      - falco_install
    - contents: |
        # Falco Configuration - CCDC Optimized
        # Generated by SaltGUI
        
        rules_file:
          - /etc/falco/falco_rules.yaml
          - /etc/falco/rules.d
        
        # Output settings
        json_output: true
        json_include_output_property: true
        json_include_tags_property: true
        
        # Log output for Splunk integration
        file_output:
          enabled: true
          keep_alive: true
          filename: /var/log/falco/falco_alerts.log
        
        # Stdout for debugging
        stdout_output:
          enabled: true
        
        # Syslog integration
        syslog_output:
          enabled: true
        
        # HTTP output (for webhook integration)
        http_output:
          enabled: false
          url: ""
        
        # Performance tuning
        buffered_outputs: false
        outputs_queue:
          capacity: 1024
        
        # Syscall event source
        syscall_event_drops:
          threshold: 0.1
          actions:
            - log
            - alert
          rate: 0.03333
          max_burst: 1
        
        # Rule matching
        priority: debug
        
        # Watch config files for changes
        watch_config_files: true
        
        # Metadata
        metadata_download:
          enabled: true
          max_mb: 100
          chunk_wait_us: 1000
          watch_freq_sec: 1

# ----------------------------------------------------------------------------
# LOGROTATE CONFIGURATION
# ----------------------------------------------------------------------------

falco_logrotate:
  file.managed:
    - name: /etc/logrotate.d/falco
    - user: root
    - group: root
    - mode: 644
    - contents: |
        /var/log/falco/*.log {
            daily
            rotate 7
            compress
            delaycompress
            missingok
            notifempty
            create 644 root root
            postrotate
                /bin/kill -HUP $(cat /var/run/falco.pid 2>/dev/null) 2>/dev/null || true
            endscript
        }

# ----------------------------------------------------------------------------
# START FALCO SERVICE
# ----------------------------------------------------------------------------

# Try legacy service first (more compatible)
falco_service_fallback:
  service.running:
    - name: falco
    - enable: True
    - require:
      - falco_install
      - falco_config
      - falco_ccdc_rules
    - watch:
      - file: falco_config
      - file: falco_ccdc_rules

# Modern BPF service (if available, preferred)
falco_service_modern:
  service.running:
    - name: falco-modern-bpf
    - enable: True
    - require:
      - falco_ccdc_rules
    - watch:
      - file: falco_config
      - file: falco_ccdc_rules
    - onlyif:
      - systemctl list-unit-files | grep -q falco-modern-bpf

# ----------------------------------------------------------------------------
# VERIFICATION
# ----------------------------------------------------------------------------

falco_verify:
  cmd.run:
    - name: |
        echo ""
        echo "=========================================="
        echo "  FALCO DEPLOYMENT COMPLETE"
        echo "=========================================="
        echo ""
        if pgrep -x falco > /dev/null 2>&1; then
          echo "[OK] Falco is running (PID: $(pgrep -x falco))"
        else
          echo "[!!] Falco process not detected"
        fi
        echo ""
        echo "Log file: /var/log/falco/falco_alerts.log"
        echo "Rules:    /etc/falco/rules.d/ccdc_extended_rules.yaml"
        echo ""
        echo "Verify with: tail -f /var/log/falco/falco_alerts.log"
        echo "=========================================="
    - require:
      - falco_service_fallback
