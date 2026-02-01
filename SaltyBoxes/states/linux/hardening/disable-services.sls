# Disable unnecessary services - CCDC Edition
# Stops and disables common services red team may exploit
# Apply: salt '*' state.apply linux.hardening.disable-services

{% set services_to_disable = [
    'cups', 'avahi-daemon', 'bluetooth', 'rpcbind',
    'smbd', 'nmbd', 'vsftpd', 'telnet.socket',
    'rsh.socket', 'rlogin.socket', 'rexec.socket',
    'tftp.socket', 'xinetd'
] %}

{% for svc in services_to_disable %}
disable_{{ svc }}:
  service.dead:
    - name: {{ svc }}
    - enable: false
    - init_delay: 1
{% endfor %}
