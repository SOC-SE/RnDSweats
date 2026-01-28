#!/bin/sh

# Add main/community/edge repos
cat > /etc/apk/repositories << EOF; $(echo)

https://dl-cdn.alpinelinux.org/alpine/v$(cut -d'.' -f1,2 /etc/alpine-release)/main/
https://dl-cdn.alpinelinux.org/alpine/v$(cut -d'.' -f1,2 /etc/alpine-release)/community/
https://dl-cdn.alpinelinux.org/alpine/edge/testing/

EOF

apk update

# Add docker packages/required libs
apk add docker
apk add docker-cli-compose
apk add git
apk add --update --no-cache curl py-pip

rc-update add docker default
service docker start
addgroup ${USER} docker


