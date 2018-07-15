 Project --- Traffic analyzer

This C program uses libpcap to capture packet's.

It captures all the outgoing packets and count's the total HTTP, HTTPS, DNS request's. It calculates the percentage of each type of traffic

Steps to compile the code
gcc traffic_analyzer.c -o sniffer -lpcap

How to use ----
Add the program as a service to start capturing packets when the OS boots up.
Logs generated by the service will be stored in /var/log/syslog -- SyslogIndentifier is used to identify the log entry
traffic_analyzer.sh is the shell script that should be used to display the stats (sh traffic_analyzer.sh)

Note
traffic_analyzer.c uses "src host 192.168.0.4" as the tcpdump packet filter expression, i'm using 192.168.0.4 as the host address, replace it with ur ip.

Future Enhancement's
Read the host ip ---> no need to enter it manually
Add more type of port / protocol detection (right now its only HTTP, HTTPS, DNS requests)
Find the most visited url / ip