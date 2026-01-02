# Palo Scripting Notes

#### example of commands.txt:

```
set cli pager off
set cli scripting-mode on
configure
# --- Bulk Commands Start ---
set address "Test-IP" ip-netmask 192.168.50.50
# --- Bulk Commands End  ---
commit
exit
exit
```

#### run config using ssh:

`ssh -oHostKeyAlgorithms=+ssh-rsa [user]@[ip] < commands.txt`

*you can also just ssh by omitting the caret*


