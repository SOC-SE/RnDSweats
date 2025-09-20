## Proxy streams
- Streams will not work unless port is exposed in docker-compose.yml
### Current technique:
- cd /opt/nginx-proxy-manager # or wherever docker-compose.yml is stored
- nano docker-compose.yml
- (add whatever ports you want to forward, 1-to-1 (open 777 w/ 777:777)
- docker compose up -d --force-recreate
