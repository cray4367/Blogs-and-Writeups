<div>

# HTB Whisper Walkthrough {#htb-whisper-walkthrough .p-name}

This is whisper sherlock walkthrough on hackthebox
:::

------------------------------------------------------------------------


Scenerio:The SOC team received an alert on 21st January 2025 about
suspicious activity originating from an employee's system (Alpha). Alpha
was not authorized to engage in any offensive hacking activities within
the network. The Incident Response (IR) team quickly acted, isolating
the system so you can perform a thorough triage and investigation to
determine the scope of the breach and potentiLl impact on the network.

In the challenge description two things are very important one is 21st
January date being provided and other being a user name Alpha which was
the source of origin of the cyber attack

We are basically provided with a forensic disk image of the system
:::
:

------------------------------------------------------------------------
:::

Let's start with the walkthrough

1 What is the hostname of the company computer involved in the
unauthorized activity?

Since we are required to find the hostname of the computer so we can
basically use registry explorer for opening system registry present
C:\\Windows\\System32\\config directory

Now for specifically finding the computer hostname we will be checking
the
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`{.markup--code
.markup--p-code}

Here we can find the computername

<figure id="b296" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*DPHn-KrQhRkMqwgjfpORhw.png"
class="graf-image" data-image-id="1*DPHn-KrQhRkMqwgjfpORhw.png"
data-width="1086" data-height="375" data-is-featured="true" />
</figure>

2 What is the IP address associated with the machine?

For this question check
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` 

Here we can find the Dhcpid address which is our required address

<figure id="b626" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*_9hOpU4NMB8SkNtHgDEm5g.png"
class="graf-image" data-image-id="1*_9hOpU4NMB8SkNtHgDEm5g.png"
data-width="1065" data-height="474" />
</figure>

3 What is the Security Identifier (SID) of the computer involved in the
incident?

For this we are basically required to check to check the software so we
will be checking the software hive in registry explorer from the
location

C:\\Windows\\System32\\config

Now we will basically navigate to
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\ProfileList`
<figure id="72ff" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*-orvc73E10XJaW8Mdcy9YA.png"
class="graf-image" data-image-id="1*-orvc73E10XJaW8Mdcy9YA.png"
data-width="1375" data-height="407" />
</figure>

Since we are asked only about SID of the computer we will basically not
be including the user identifier here

Key Name\
S-1--5--21--953115734--2025219997--3674921352--1001

So our answer would be S-1--5--21--953115734--2025219997--3674921352

4 What was the timezone setting of the machine?

For this question we will again be moving back to our System hive

Now we have to navigate to
CurrentControlSet\\Control\\TimeZoneInformation

<figure id="33d6" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*CP91e6lzDO_yGmiLtBuWxA.png"
class="graf-image" data-image-id="1*CP91e6lzDO_yGmiLtBuWxA.png"
data-width="1357" data-height="457" />
</figure>

5 Which tool did the attacker use to escalate privileges and extract
sensitive credentials from the system?

For this question we can check for any files related to privesc in the
forensic disk image of the target computer

While looking for any malicious file we stumble upon this

HTB-Sherlocks/Whisper/C/Users/A7md-NaS3eR/AppData/Roaming/Microsoft/Windows/Recent/

here we can found something interesting

<figure id="9571" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*RFXMH6P65rAk54E_8ub0Jw.png"
class="graf-image" data-image-id="1*RFXMH6P65rAk54E_8ub0Jw.png"
data-width="1620" data-height="607" />
</figure>

Mimikatz_trunk.lnk is created so possibly it was used to escalate
privileges

Answer :mimikatz.exe

6 What is the timestamp of the last execution of the credential
extraction tool on the system used by the attacker?

For the timestamp of the last execution of credential extraction we can
basically look at what time the mimkatz service was last executed so we
can use prefetch logs for mimikatz by using Eric Zimmerman tools(PEcmd)

We can move to C:\\Windows\\Prefetch to check for prefetch files and try
looking for mimikatz

For both prefetch files the results are as follows

<figure id="2ab1" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*QyJpYYm3qdWx5qE4pvoB0A.png"
class="graf-image" data-image-id="1*QyJpYYm3qdWx5qE4pvoB0A.png"
data-width="1204" data-height="535" />
</figure>

<figure id="472d" class="graf graf--figure graf-after--figure">
<img
src="https://cdn-images-1.medium.com/max/800/1*TtjYOcxXLlrkJQvLXCSBPA.png"
class="graf-image" data-image-id="1*TtjYOcxXLlrkJQvLXCSBPA.png"
data-width="1468" data-height="716" />
</figure>

So the last running time was

Answer: 2025--01--21 00:21:41

7 What is the timestamp when the attacker first downloaded the
credential extraction tool onto the system?

For this question we will be utilizing MFT file since we cannot find
anything in the disk image we are provided

Now just navigate to C:\\Users\\Alpha\\Downloads

<figure id="da1b" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*0ZOQMMz03qiqhuMT7_R7Kw.png"
class="graf-image" data-image-id="1*0ZOQMMz03qiqhuMT7_R7Kw.png"
data-width="1593" data-height="707" />
</figure>

We have Created On: 2025--01--21 00:20:15

So Answer: 2025--01--21 00:20:15

We will be checking the Downloads folder of the Alpha user

8 After using the previously mentioned tool, the attacker downloaded a
script to scan the domain controller. What is the URL from which the
attacker downloaded this script?

Since a tool is downloaded so we can check the browser history to check
where it was download. Now since we have the disk image so we will now
proceed to find the history database of the browser that was being used.

Upon searching i found edge was being used and since the alpha user
account was being used so
HTB-Sherlocks/Whisper/C/Users/Alpha/AppData/Local/Microsoft/Edge/User
Data/Default/ is the path to go

Since we want to know the url used to download so we will be moving on
to using DB browser for sqlite and checking urls table

<figure id="4614" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*3eArpO0atj7fO-lMzGXhSg.png"
class="graf-image" data-image-id="1*3eArpO0atj7fO-lMzGXhSg.png"
data-width="1920" data-height="468" />
</figure>

Url:
[https://mega.nz/file/I31zBZTb#H5aUJamEj2xMroi9baoTKCMjQF1jiV8TK9gbjoNGgkw](https://mega.nz/file/I31zBZTb#H5aUJamEj2xMroi9baoTKCMjQF1jiV8TK9gbjoNGgkw){.markup--anchor
.markup--p-anchor
data-href="https://mega.nz/file/I31zBZTb#H5aUJamEj2xMroi9baoTKCMjQF1jiV8TK9gbjoNGgkw"
rel="nofollow noopener" target="_blank"}

9 What is the filename of the script? (Format --- Full path of file,
starting with drive letter)

For this we will first try to visit the url to check the filename then
we will move forward on to check the path of the file we are required to
find.\
On visiting the url

<figure id="4d32" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*lXO5KsMoKV7qE3SkplBssQ.png"
class="graf-image" data-image-id="1*lXO5KsMoKV7qE3SkplBssQ.png"
data-width="1872" data-height="988" />
</figure>

now we have to find location of this file, since we know this file would
probably by the attacker after his engagement so we will move on to
search for the downloads table using DB browser

<figure id="da53" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*ycfbN0A6m8a8V1IiWyVCBg.png"
class="graf-image" data-image-id="1*ycfbN0A6m8a8V1IiWyVCBg.png"
data-width="1763" data-height="375" />
</figure>

Answer: C:\\Users\\Alpha\\Downloads\\DC-Scan.ps1

10 What is the timestamp indicating when the attacker deleted the script
after it was downloaded?

Now we know that attacker deleted the script we can find one very
important thing that \$J journal stores information about any
modifications to a file so we can use that to check when was the script
deleted

We can use MFETCmd.exe to convert it to a csv file so we can analyse it
using timeline explorer and check the events happening

For converting we can use this command

<figure id="0a4a" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*n-xrvjw0-a_3YZ6HfKiTjA.png"
class="graf-image" data-image-id="1*n-xrvjw0-a_3YZ6HfKiTjA.png"
data-width="945" data-height="221" />
</figure>

.\\MFTECmd.exe -f 'Registry_HTB\\\$J' --- csv "J.csv"

Now we open use this J.csv file using timeline explorer and check the
filename of the downloaded file

Here we will search for DC-Scan

<figure id="cc84" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*41vetW2-NhXEw7phMm7H8A.png"
class="graf-image" data-image-id="1*41vetW2-NhXEw7phMm7H8A.png"
data-width="1920" data-height="337" />
</figure>

<figure id="f298" class="graf graf--figure graf-after--figure">
<img
src="https://cdn-images-1.medium.com/max/800/1*Q1dk0-tGLFQwxP3ksEDixQ.png"
class="graf-image" data-image-id="1*Q1dk0-tGLFQwxP3ksEDixQ.png"
data-width="1872" data-height="280" />
</figure>

So our timeline would be

Answer: 2025--01--21 01:27:47

11 What is the name of the shared file that the attacker accessed?

Since we know attacker accessed this file so we can basically check for
recent files that we accessed

Firstly check the the shared directories using Shellbag explorer then we
will move to check the filename in that directory

<figure id="b570" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*f4u2fT9eOs0Zmo-3ooWLjg.png"
class="graf-image" data-image-id="1*f4u2fT9eOs0Zmo-3ooWLjg.png"
data-width="1807" data-height="758" />
</figure>

Now checking registries of Alpha user in Ntuser.dat file

Now checking for recently accessed files

For this we need to move to
\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs

We will find our required filename

<figure id="6cad" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*vI5agaMFXp9rqH_DJzXqxQ.png"
class="graf-image" data-image-id="1*vI5agaMFXp9rqH_DJzXqxQ.png"
data-width="1402" data-height="564" />
</figure>

So our path becomes

Answer:
\\\\CYBERUP\\Users\\Administrator\\Desktop\\Top-Secret\\Secret.xlsx

12 To persist, the attacker created a new user account. What is the SID
of the newly created account?

We can extract windows logs from the disk image

Whisper/C/Windows/System32/winevt/Logs now since we are required to
check the SID of the newly created user we need to use Security.evtx log
we can use event viewer to check it

We know the event id for creation of a new user is 4720

So we can filter those logs

<figure id="404e" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*oucqam5p-NaK1xE-8UOpeA.png"
class="graf-image" data-image-id="1*oucqam5p-NaK1xE-8UOpeA.png"
data-width="1327" data-height="521" />
</figure>

We only get one log here so which depicts a new user Admin being created

Target-Sid: S-1--5--21--953115734--2025219997--3674921352--1002

13 How many times has the newly created user logged in?

Now since we know Admin user was the newly created user

For logging in the event ID is 4624

Since we know the Username is "Admin"

So we basically construct a filter query for Admin username

``` {#7632 .graf .graf--pre .graf-after--p .graf--preV2 code-block-mode="1" spellcheck="false" code-block-lang="xml"}
<QueryList>
  <Query Id="0" Path="file://C:\Users\bob\Downloads\Forenics\Registry_HTB\Security.evtx">
    <Select Path="file://C:\Users\bob\Downloads\Forenics\Registry_HTB\Security.evtx">*[EventData[Data[@Name='TargetUserName']='Admin']]</Select>
  </Query>
</QueryList>
```

Now we will only be displayed events related to Admin on checking for
events with event ID 4624

<figure id="a2a0" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*xDucIjNcdaDHBZwXlNsBQg.png"
class="graf-image" data-image-id="1*xDucIjNcdaDHBZwXlNsBQg.png"
data-width="1222" data-height="342" />
</figure>

Since there are no events so

Answer:0

14 What is the password of the newly created user?

For this question we will be utilizing a script impacket-secretdump

This basically utlilizes registry hives mainly SAM and SYSTEM hives

For running this script directly i was having some problems so i
basically created a virtual environment and used pip to install impacket

Now just virtual environment

<figure id="1f57" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*5868-Zc_Llyj6almxvFh9A.png"
class="graf-image" data-image-id="1*5868-Zc_Llyj6almxvFh9A.png"
data-width="1295" data-height="140" />
</figure>

Checking if impacket is properly installed

Now we just use secretsdump from venv

``` {#7706 .graf .graf--pre .graf-after--p .graf--preV2 code-block-mode="1" spellcheck="false" code-block-lang="lua"}
find venv -name secretsdump.py
```

<figure id="b811" class="graf graf--figure graf-after--pre">
<img
src="https://cdn-images-1.medium.com/max/800/1*ZOHaVcucunKKBLqK8g76XQ.png"
class="graf-image" data-image-id="1*ZOHaVcucunKKBLqK8g76XQ.png"
data-width="1185" data-height="73" />
</figure>

Now use secretsdump for dumping creds

<figure id="95ef" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*9mltxICVIRPkQud6p_bp2A.png"
class="graf-image" data-image-id="1*9mltxICVIRPkQud6p_bp2A.png"
data-width="1070" data-height="330" />
</figure>

Now we have to crack the Admin NTLM hash using hashcat against rockyou

58a478135a93ac3bf058a5ea0e8fdb71

This is basically the hash we need to crack

<figure id="9bcd" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*Eo2IquhrVzE1We_lNLKSlw.png"
class="graf-image" data-image-id="1*Eo2IquhrVzE1We_lNLKSlw.png"
data-width="1447" data-height="464" />
</figure>

Since i have already cracked the hash i used --- show it again

For cracking just save 58a478135a93ac3bf058a5ea0e8fdb71 in a txt file
or .hash and run hashcat as follows:

``` 
 hashcat -m 1000 whisper_admin.txt ../../../Wordlist/rockyou.txt                                                                                                                    255 ↵
```

here whisper_admin.txt is the filename

On cracking the hash the password hash obtained is

Answer:Password123

Congrats the whisper sherlock has been successfully solved :)
:::

Exported from [Medium](https://medium.com) on February 24, 2026.
