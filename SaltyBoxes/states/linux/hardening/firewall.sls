# Basic firewall lockdown - CCDC Edition
# Blocks all incoming except Salt (4505/4506) and established connections
# Apply: salt '*' state.apply linux.hardening.firewall

iptables_flush:
  cmd.run:
    - name: iptables -F INPUT

iptables_established:
  cmd.run:
    - name: iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    - require:
      - cmd: iptables_flush

iptables_loopback:
  cmd.run:
    - name: iptables -A INPUT -i lo -j ACCEPT
    - require:
      - cmd: iptables_flush

iptables_salt_4505:
  cmd.run:
    - name: iptables -A INPUT -p tcp --dport 4505 -j ACCEPT
    - require:
      - cmd: iptables_flush

iptables_salt_4506:
  cmd.run:
    - name: iptables -A INPUT -p tcp --dport 4506 -j ACCEPT
    - require:
      - cmd: iptables_flush

iptables_drop_policy:
  cmd.run:
    - name: iptables -P INPUT DROP
    - require:
      - cmd: iptables_established
      - cmd: iptables_loopback
      - cmd: iptables_salt_4505
      - cmd: iptables_salt_4506
