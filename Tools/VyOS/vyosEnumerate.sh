#!/bin/vbash
source /opt/vyatta/etc/functions/script-template
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

echo -e '\n+------+INTERFACES+------+\n' > vyosConfig.txt
run show interfaces >> vyosConfig.txt
echo -e '\n+------+FIREWALL+------+\n' >> vyosConfig.txt
run show firewall >> vyosConfig.txt
echo -e '\n+------+RUNNING CONTAINERS+------+\n' >> vyosConfig.txt
run show container >> vyosConfig.txt
echo -e '\n+------+DOMAIN/OS INFO+------+\n' >> vyosConfig.txt
run show host os >> vyosConfig.txt
run show host domain >> vyosConfig.txt
echo -e '\n+------+IP ROUTES+------+\n' >> vyosConfig.txt
run show ip route >> vyosConfig.txt
echo -e '\n+------+OPEN PORTS+------+\n' >> vyosConfig.txt
run show ip ports >> vyosConfig.txt
echo -e '\n+------+SRC/DEST NAT RULES+------+\n' >> vyosConfig.txt
run show nat source rules >> vyosConfig.txt
run show nat destination rules >> vyosConfig.txt
echo -e '\n+------+USERS/SESSIONS+------+\n' >> vyosConfig.txt
run show users >> vyosConfig.txt
echo -e '\n+------+------+------+\n' >> vyosConfig.txt

exit
echo -e 'Configuration details found in ./vyosConfig.txt'
