#!/bin/bash
# 文件名：sync_sources.sh

# 同步 source1
rsync -avz -e ssh root@192.168.1.101:/root/src/dart_ping_client /root/src/dart/dart-dhcp_dns_server/dart_ping
# 同步 source2
rsync -avz -e ssh root@192.168.1.102:/root/src/dart_ping_server /root/src/dart/dart-dhcp_dns_server/dart_ping
