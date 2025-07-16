# Login Info
Login Info:
Stack#: 10
Username: DAHA-019-M
Password: oybOV5rOD7Jo
Jump: 10.50.15.68
# Operations and Scanning
Open source intel:
  social medial, linkdin, whois


## Active Enumerations
### nmap scripts
stored scripts:
  ls /usr/share/nmap/scripts

# Control Sockets
Authenticate to JUmp box, -S create socket file to store socket s, -M uses multiplexing, Kepp this open or the connection will die. up to 17 hops deep only unising a single connection
Create master socket:
  ssh -MS /tmp/jump student@10.50.15.68 (own ip)
  ssh -MS /tmp/demo demo1@10.50.14.70 (demo ip)

After moving to a new box do a ping sweep:
use duckduck go to convert cider notation
for i in {97..126}; do (ping -c 1 192.168.28.$i | grep "bytes from"&); done
                ^                          ^
        (availible ips in cider)      (target ip to scan)

Scan for ports on lsited hosts
set up dynamic tunnel:
ssh -S /tmp/demo demo -O forward -D 9050
                  ^    ^
              (name of master socket)
Proxychains nmap (taget ip) 
verify port
proxychains nc (targetip) (taget port)
  
* optional *
to close the dynamic tunnel
ssh -S /tmp/demo demo -O cancel -D 9050

## Add listenting port forward
    ssh -S /tmp/demo demo -O forward -L1111:192.168.28.100:80 -L 1112:192.168.28.100:2222
## Remove port forward
  ssh -S /tmp/demo demo -O cancel -L1111:192.168.28.100:80 -L 1112:192.168.28.100:2222

  ### verify port is op 
  ss -ntlp | grep (port number)
