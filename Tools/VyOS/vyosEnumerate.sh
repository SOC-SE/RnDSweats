#!/bin/vbash
source /opt/vyatta/etc/functions/script-template
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

run show interfaces > vyosConfig.txt
cat '--------------------' >> vyosConfig.txt
run show firewall >> vyosConfig.txt
cat '--------------------' >> vyosConfig.txt
run show container >> vyosConfig.txt
cat '--------------------' >> vyosConfig.txt
run show host os >> vyosConfig.txt
run show host domain >> vyosConfig.txt
cat '--------------------' >> vyosConfig.txt
run show ip route >> vyosConfig.txt
cat '--------------------' >> vyosConfig.txt
run show ip ports >> vyosConfig.txt
cat '--------------------' >> vyosConfig.txt
run show nat source rules >> vyosConfig.txt
run show nat destination rules >> vyosConfig.txt
cat '--------------------' >> vyosConfig.txt
run show users >> vyosConfig.txt

exit
