#########################################################################
# File Name: start.sh
# Author: hanker
# mail: hanpeiyi1@gmail.com
# Created Time: 2014年03月24日 星期一 11时30分56秒
#########################################################################
#!/bin/sh
sudo /sbin/iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 0
sudo ./test
sudo /sbin/iptables -F OUTPUT
