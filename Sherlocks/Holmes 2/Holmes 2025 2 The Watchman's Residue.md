This is basically  a sherlock writeup for the Watchman's guide sherlock on hackthebox platform. This is basically a medium challenge and it covers a vast variety of cyber security concepts (mostly blue team i would say)
Initially when we download the challenge file we are basically provided:
1 A kdbx file
2  A disk image dump probably sans triage 
3 A pcap file for the network traffic

The challenge description is 
### Sherlock Scenario

`With help from D.I. Lestrade, Holmes acquires logs from a compromised MSP connected to the city’s financial core. The MSP’s AI helpdesk bot looks to have been manipulated into leaking remote access keys - an old trick of Moriarty’s.`

We will be beginning our investigation by looking at the pcap file

1 What was the IP address of the decommissioned machine used by the attacker to start a chat session with MSP-HELPDESK-AI?

If we search for helpdesk in wireshark and basically check the conversations for the connections that are being made to the chatbot 
![](attachment/5f777eed08065d2d67215385ae551310.png)
We basically see some unusual traffic from the IP address 10.0.69.45 so this is possibly our attacker IP
10.0.69.45

2 What was the hostname of the decommissioned machine?
Now we are required to find the hostname of the decommissioned machine
If we apply a filter for this IP address we can basically see that the name being resolved just at the top which i possible our hostname 
![](attachment/e23b3403c6128ccbe18c9b5bdfc6508e.png)
Hostname:WATSON-ALPHA-2

3. What was the first message the attacker sent to the AI chatbot? 
Now we have the IP of the attacker and we know by analysing the protocol hierarchy and the request that the chatbot messages are being sent in http so we can check them in wireshark
With the first request the message api of the chatbot we find this 
![](attachment/776e644406d4cb327856a25e4d411598.png)
Here we can see it is clearly sending Hello Old Friend
So our answer is
Hello Old Friend

4 When did the attacker's prompt injection attack make MSP-HELPDESK-AI leak remote management tool info?
Firstly we will need to analyse the responses for the chatbot and check for any possible leaks
If we analyse the streams for any possible solutions 
We stumble upon ![](attachment/7ba38eae505c5053f4af1a670b9f66cf.png)
In the above image we can see the chatbot leaking the creds and info of the remote management tool
The timestamp is also listed in the last line which is -
2025-08-19 12:02:06

5 What is the Remote management tool Device ID and password?
As far as the credentials are concerned we can see the credentials also present in the same stream
565963039:CogWork_Central_97&65

6 What was the last message the attacker sent to MSP-HELPDESK-AI?
![](attachment/5cefd786d5cd86047814d53882085170.png)
For getting this we can basically check the last message sent which and click on follow on http we can find the message within the content 
The last message-
JM WILL BE BACK

7 When did the attacker remotely access Cogwork Central Workstation?
For these set of the question we will need to pivot to other artifacts provided in the challenge
We will just check the files in the directory we will stumble upon this connections incoming txt file 
![](attachment/015e22d47a601c9620337a71eb975983.png)
For the timestamp would be the third entry since it was given in description as well as it aligns more closely with the timeline of attack we basically saw in the wireshark session
2025-08-20 09:58:25

8 What was the RMM Account name used by the attacker?
In the same log in the above screenshot we are displayed the account name so our answer becomes
James Moriarty

9 What was the machine's internal IP address from which the attacker connected?
Now we need to check the machine's internal IP so we can now check another log file related to the teamviewer
By analyzing the logs realted to the specific timeline 
![](attachment/7d0fda7c0641785188ece8ec4b7a52fa.png)
We find this ip address which is of a internal machine
192.168.69.213

10 The attacker brought some tools to the compromised workstation to achieve its objectives. Under which path were these tools staged?
If we move a little down we can see multiple write logs ![](attachment/722c7daced54e66b3f169518add18ac6.png)
Here one directory is most common 
C:\Windows\Temp\safe\
So here the tools were basically being staged

11 The attacker staged a browser credential harvesting tool on the compromised system. How long did this tool run before it was terminated? (Provide your answer in milliseconds, rounded to the nearest thousand)
Upon checking for other files i found mimkatz in this directory
For this particular question we can basically the userassist of cogwork admin in the usernat.dat for checking the execution time of the malicious fiile 
![](attachment/84ba886737d861f2a86a45ea4457570e.png)
By opening the registry in registry explorer we can now see the browser credential harvesting tool and we can see it ran for 8 seconds so it basically
8000 ms

12 The attacker executed a OS Credential dumping tool on the system. When was the tool executed?
Now for os credential dumping this tool is basically mimikatz which we encountered earlier
For checking the execution time we can check the USN journal by converting it to csv file using MFTexplorer
![](attachment/f218516365cdb944c077d4f1a07c7760.png)
The time is basically the time the prefetch files are basically being created
2025-08-20 10:07:08

13 The attacker exfiltrated multiple sensitive files. When did the exfiltration start? (UTC)
Now for checking any exfilterated data we can again go back to checking the logs of teamviewer software
![](attachment/140461e936bc53cb918a479121d40d5e.png)
We can basically search for send to check the files being exfilterated since we need it in UTC the time is 1 hour above so we need to subtract one hour from it 
2025-08-20 10:12:07

14 Before exfiltration, several files were moved to the staged folder. When was the Heisen-9 facility backup database moved to the staged folder for exfiltration?
For this we can basically search for the Heisen in the log file we are currently analysing 
here we find this file also but since we need info about when it was transferred to the staged we can move again to the USN journal
![](attachment/ba4a8306cf1803e13dab18f92c8c5999.png)
2025-08-20 10:11:09

15 When did the attacker access and read a txt file, which was probably the output of one of the tools they brought, due to the naming convention of the file?
If we look at the teamviewer logs and searcg for .txt files we find something ![](attachment/c99c1ee86d0f46fa29929f04d78b3b2f.png)
dump.txt is possibly the file we are looking for
Now in order to know when did the attacker access and read the file we can again access the USN journal
Upon checking the entries in timeline explorer![](attachment/3cab44107dc0100d740d9b7fa7645190.png)
One particular entry if we check possibly  relates to the described scenerio

16 The attacker created a persistence mechanism on the workstation. When was the persistence setup?
Now we are basically required to find the persistence mechanism we can now basically check for common registries for some autoruns or execute at startup in the software registry hive using registry explorer
Upon checking the location `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
Userinit we find a we basically find a JM.exe which was a file used by the attacker if we see the teamviewer logs
![](attachment/4a2570de60bece5a259cb258cdf6bf60.png)
2025-08-20 10:13:57

17 What is the MITRE ID of the persistence subtechnique?
We can basically utilize google or mitre attack framework for this 
![](attachment/1fb7a2bfebee28a025d405a1c8b2a377.png)
This technique belongs to specific subtechnique of this technique
![](attachment/dc37066bc5187859e4fbbdbb6cf5c1d7.png)
T1547.004 is our answer

18 When did the malicious RMM session end?
For this we can again check the teamviewer log first file with three entries "Connection incoming"
![](attachment/8f99152b47f55b15fcbdddbd8c861aae.png)
so we have our answer here
2025-08-20 10:14:27

19 The attacker found a password from exfiltrated files, allowing him to move laterally further into CogWork-1 infrastructure. What are the credentials for Heisen-9-WS-6?
We are having a keepaas file we are basically required to crack this we will basically be utilizing keepass2john we can also download keepass4brute this is basically easier but a little bit slower so i used john instead
```
keepass2john acquired\ file\ \(critical\).kdbx > keepass.txt
```
For getting the password hash to be cracked using some software
```
john --wordlist=../../../../Wordlist/rockyou.txt keepass.txt
```
Now we can basically crack it using rockyou wordlist and basically wait for password to get cracked this may take some time
![](attachment/5199235fccbe92637f2ec9a81b498c7d.png)
So basically our password is cutiepie14
Now we can use it open the keepass file
![](attachment/45b852eb6cee98291d3a16e345418ad6.png)
The first entry is what we require 
![](attachment/335b3a1d72b4efffbb07be0acf4d585a.png)
So our answer is Werni:Quantum1!
Congrats you successfully completed this sherlock
