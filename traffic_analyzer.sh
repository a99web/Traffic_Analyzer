#/usr/bin/bash

# this shell script it used to print the traffic stat's, using the syslog
# on adding traffic_analyzer as a service, the logs will be stored in /var/log/syslog

# get the total http session's
total_http_sessions=`cat /var/log/syslog | grep traffic_analyzer | grep "port no: 80" | wc -l`

# get the total ssl session's
total_https_sessions=`cat /var/log/syslog | grep traffic_analyzer | grep "port no: 443" | wc -l`

# get total DNS connections
total_dns_sessions=`cat /var/log/syslog | grep traffic_analyzer | grep "port no: 53" | wc -l`

echo "Total HTTP sessions: ${total_http_sessions}\nTotal HTTPS sessions: ${total_https_sessions}\nTotal DNS requests: ${total_dns_sessions}\n"

total_sessions=`expr ${total_http_sessions} + ${total_https_sessions} + ${total_dns_sessions}`

echo "Total Traffic: ${total_sessions}"

scale=3
http_percentage=`echo "scale=3;(${total_http_sessions}/${total_sessions})*100" | bc`
https_percentage=`echo "scale=3;(${total_https_sessions}/${total_sessions})*100" | bc`
dns_percentage=`echo "scale=3;(${total_dns_sessions}/${total_sessions})*100" | bc`

echo "HTTP %: ${http_percentage}\nHTTPS %: ${https_percentage}\nDNS %: ${dns_percentage}\n"
