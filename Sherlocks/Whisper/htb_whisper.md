# HTB Whisper Walkthrough

This is whisper sherlock walkthrough on hackthebox

---

**Scenario:** The SOC team received an alert on 21st January 2025 about suspicious activity originating from an employee's system (Alpha). Alpha was not authorized to engage in any offensive hacking activities within the network. The Incident Response (IR) team quickly acted, isolating the system so you can perform a thorough triage and investigation to determine the scope of the breach and potential impact on the network.

In the challenge description two things are very important: the **21st January** date being provided, and the username **Alpha** which was the source of origin of the cyber attack.

We are basically provided with a forensic disk image of the system.

---

## 1. What is the hostname of the company computer involved in the unauthorized activity?

Since we are required to find the hostname of the computer, we can use **Registry Explorer** to open the System registry at:

`C:\Windows\System32\config`

For finding the computer hostname, navigate to:

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`

Here we can find the ComputerName.

![Registry showing ComputerName](https://cdn-images-1.medium.com/max/800/1*DPHn-KrQhRkMqwgjfpORhw.png)

---

## 2. What is the IP address associated with the machine?

Navigate to:

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

Here we can find the **DhcpIPAddress** which is our required address.

![Registry showing DHCP IP address](https://cdn-images-1.medium.com/max/800/1*_9hOpU4NMB8SkNtHgDEm5g.png)

---

## 3. What is the Security Identifier (SID) of the computer involved in the incident?

Open the **Software** hive in Registry Explorer from:

`C:\Windows\System32\config`

Navigate to:

`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\ProfileList`

![Registry showing ProfileList](https://cdn-images-1.medium.com/max/800/1*-orvc73E10XJaW8Mdcy9YA.png)

Since we are asked only about the SID of the computer, we exclude the user-specific portion.

**Key Name:** `S-1-5-21-953115734-2025219997-3674921352-1001`

**Answer:** `S-1-5-21-953115734-2025219997-3674921352`

---

## 4. What was the timezone setting of the machine?

Go back to the **System** hive and navigate to:

`CurrentControlSet\Control\TimeZoneInformation`

![Registry showing TimeZoneInformation](https://cdn-images-1.medium.com/max/800/1*CP91e6lzDO_yGmiLtBuWxA.png)

---

## 5. Which tool did the attacker use to escalate privileges and extract sensitive credentials from the system?

Check for any files related to privilege escalation in the forensic disk image.

While looking for malicious files, navigate to:

`HTB-Sherlocks/Whisper/C/Users/A7md-NaS3eR/AppData/Roaming/Microsoft/Windows/Recent/`

Here we find something interesting:

![Recent files showing mimikatz_trunk.lnk](https://cdn-images-1.medium.com/max/800/1*RFXMH6P65rAk54E_8ub0Jw.png)

`Mimikatz_trunk.lnk` was created, so it was likely used to escalate privileges.

**Answer:** `mimikatz.exe`

---

## 6. What is the timestamp of the last execution of the credential extraction tool on the system?

To find the last execution timestamp of Mimikatz, we can use **prefetch logs** via Eric Zimmerman's **PECmd** tool.

Navigate to `C:\Windows\Prefetch` and look for Mimikatz prefetch files.

For both prefetch files, the results are as follows:

![PECmd output for Mimikatz prefetch - file 1](https://cdn-images-1.medium.com/max/800/1*QyJpYYm3qdWx5qE4pvoB0A.png)

![PECmd output for Mimikatz prefetch - file 2](https://cdn-images-1.medium.com/max/800/1*TtjYOcxXLlrkJQvLXCSBPA.png)

**Answer:** `2025-01-21 00:21:41`

---

## 7. What is the timestamp when the attacker first downloaded the credential extraction tool onto the system?

Use the **MFT** file to determine the download time. Navigate to:

`C:\Users\Alpha\Downloads`

![MFT showing download timestamp](https://cdn-images-1.medium.com/max/800/1*0ZOQMMz03qiqhuMT7_R7Kw.png)

**Created On:** `2025-01-21 00:20:15`

**Answer:** `2025-01-21 00:20:15`

---

## 8. After using the previously mentioned tool, the attacker downloaded a script to scan the domain controller. What is the URL from which the attacker downloaded this script?

Since a tool was downloaded, check the **browser history** to find the download source. Edge was being used by the Alpha user, so navigate to:

`HTB-Sherlocks/Whisper/C/Users/Alpha/AppData/Local/Microsoft/Edge/User Data/Default/`

Open the History database with **DB Browser for SQLite** and check the `urls` table.

![Edge browser history showing download URL](https://cdn-images-1.medium.com/max/800/1*3eArpO0atj7fO-lMzGXhSg.png)

**URL:** `https://mega.nz/file/I31zBZTb#H5aUJamEj2xMroi9baoTKCMjQF1jiV8TK9gbjoNGgkw`

---

## 9. What is the filename of the script? (Format: full path starting with drive letter)

First, visit the URL to check the filename, then find its path in the disk image.

![Mega.nz URL showing script filename](https://cdn-images-1.medium.com/max/800/1*lXO5KsMoKV7qE3SkplBssQ.png)

Search the **downloads** table in DB Browser for SQLite:

![DB Browser showing downloads table](https://cdn-images-1.medium.com/max/800/1*ycfbN0A6m8a8V1IiWyVCBg.png)

**Answer:** `C:\Users\Alpha\Downloads\DC-Scan.ps1`

---

## 10. What is the timestamp indicating when the attacker deleted the script after it was downloaded?

The **$J journal** stores information about file modifications and deletions. Use **MFTECmd.exe** to convert it to CSV and analyse with **Timeline Explorer**.

```
.\MFTECmd.exe -f 'Registry_HTB\$J' --csv "J.csv"
```

![MFTECmd command](https://cdn-images-1.medium.com/max/800/1*n-xrvjw0-a_3YZ6HfKiTjA.png)

Open `J.csv` in Timeline Explorer and search for `DC-Scan`:

![Timeline Explorer showing DC-Scan entry 1](https://cdn-images-1.medium.com/max/800/1*41vetW2-NhXEw7phMm7H8A.png)

![Timeline Explorer showing DC-Scan deletion timestamp](https://cdn-images-1.medium.com/max/800/1*Q1dk0-tGLFQwxP3ksEDixQ.png)

**Answer:** `2025-01-21 01:27:47`

---

## 11. What is the name of the shared file that the attacker accessed?

Check for recently accessed shared directories using **Shellbag Explorer**:

![Shellbag Explorer showing shared directories](https://cdn-images-1.medium.com/max/800/1*f4u2fT9eOs0Zmo-3ooWLjg.png)

Then check the Alpha user's **NTUSER.DAT** registry hive and navigate to:

`\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

![RecentDocs registry showing accessed file](https://cdn-images-1.medium.com/max/800/1*vI5agaMFXp9rqH_DJzXqxQ.png)

**Answer:** `\\CYBERUP\Users\Administrator\Desktop\Top-Secret\Secret.xlsx`

---

## 12. To persist, the attacker created a new user account. What is the SID of the newly created account?

Extract Windows event logs from the disk image at:

`Whisper/C/Windows/System32/winevt/Logs`

Open **Security.evtx** in Event Viewer. The event ID for user account creation is **4720**. Filter by that event ID:

![Event Viewer showing Event ID 4720 - new user created](https://cdn-images-1.medium.com/max/800/1*oucqam5p-NaK1xE-8UOpeA.png)

There is one log showing a new user named **Admin** being created.

**Target SID:** `S-1-5-21-953115734-2025219997-3674921352-1002`

---

## 13. How many times has the newly created user logged in?

The event ID for logon is **4624**. Build a filter query for the Admin username:

```xml
<QueryList>
  <Query Id="0" Path="file://C:\Users\bob\Downloads\Forenics\Registry_HTB\Security.evtx">
    <Select Path="file://C:\Users\bob\Downloads\Forenics\Registry_HTB\Security.evtx">*[EventData[Data[@Name='TargetUserName']='Admin']]</Select>
  </Query>
</QueryList>
```

Check for events with event ID 4624 for the Admin user:

![Event Viewer showing logon events for Admin](https://cdn-images-1.medium.com/max/800/1*xDucIjNcdaDHBZwXlNsBQg.png)

No logon events found.

**Answer:** `0`

---

## 14. What is the password of the newly created user?

Use the **impacket-secretsdump** script to extract password hashes. It utilizes the **SAM** and **SYSTEM** registry hives.

Set up a virtual environment and install impacket via pip, then activate it:

![Virtual environment setup](https://cdn-images-1.medium.com/max/800/1*5868-Zc_Llyj6almxvFh9A.png)

Find `secretsdump.py` in the venv:

```bash
find venv -name secretsdump.py
```

![Finding secretsdump.py](https://cdn-images-1.medium.com/max/800/1*ZOHaVcucunKKBLqK8g76XQ.png)

Run secretsdump to extract credentials:

![secretsdump output showing NTLM hashes](https://cdn-images-1.medium.com/max/800/1*9mltxICVIRPkQud6p_bp2A.png)

The Admin NTLM hash to crack is: `58a478135a93ac3bf058a5ea0e8fdb71`

Crack it with **hashcat** against the rockyou wordlist:

```bash
hashcat -m 1000 whisper_admin.txt ../../../Wordlist/rockyou.txt
```

Here `whisper_admin.txt` contains the hash. Use `--show` to display already-cracked results:

![Hashcat cracking result](https://cdn-images-1.medium.com/max/800/1*Eo2IquhrVzE1We_lNLKSlw.png)

**Answer:** `Password123`

---

Congrats — the Whisper Sherlock has been successfully solved! 🎉
