

# Hands-On SIEM Investigation: LSASS Dumping, LOLBins, and C2 Detection

In this lab, I will walk you through how to detect specific attacks within a Splunk environment.

I will not go through installing Splunk, as many excellent tutorials are already available online. I am linking the official documentation here so you can set it up for your system:

[**Splunk Enterprise Installation Instructions**](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/9.4/plan-your-splunk-enterprise-installation/installation-instructions)

---

## Understanding Splunk SIEM Architecture

First, it is important to understand Splunk's basic SIEM architecture for investigations. Splunk relies on three main components:

* **Forwarders:** A Splunk forwarder collects data from remote systems and forwards it to a Splunk indexer for centralized indexing, storage, and analysis. Think of this as the agent that collects application and security logs from endpoints (like your local PC, or all Active Directory components in a large organization). Simply put, it sends logs to a central location so they can be indexed.
* **Indexers:** These handle the next stage of the log lifecycle. They organize and store the logs based on indexes. For example, Windows and Linux application logs could be managed separately using different indexes. Indexers are responsible for processing search queries from the Search Heads.
* **Search Heads:** This is the main application interface we interact with. We provide search queries to the Search Head, which passes them to the Indexers to retrieve the results.

![Diagram 1: Splunk Architecture](https://cdn-images-1.medium.com/max/800/1*Jgjfp6K-7J24Qa2yRcyHyQ.png)

*(Note: There are other components, like deployment servers, but these three are the core components you will need when diving deep into setting up your own SIEM environment.)*

**SPL (Search Processing Language)** is the query language used by Splunk to manipulate, search, and filter data.

---

## Splunk Queries (SPL) Basics

Let's move on to Splunk queries, as we need SPL to interact with the environment.

```spl
search index="main"
```
> **Note:** The `search` command is implicit, so you do not need to type it in the search head.

If `index="main"` contains your logs, you can use that. Alternatively, you can search across all indexes using:

```spl
index=*
```

Running this query fetches the entire log dataset. However, manually reading through an ocean of logs for potential threats makes no sense. Instead, we filter by specific log sources:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode!=1
```
In this query, I am fetching Sysmon logs and using `!=` to exclude events with `EventCode=1` (Process Creation).

* **More information on Sysmon and Event IDs:** [Microsoft Sysmon Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* **Splunk Basic Queries Cheat Sheet:** [StationX Splunk Cheat Sheet](https://www.stationx.net/splunk-cheat-sheet/)

### Table Generation Queries
We can generate basic tables in Splunk to make the data more readable:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image
```
Here, `_time` displays the timestamp, `host` shows the system name, and `Image` represents the process.

---

## Detection Scenario

**Scenario:** Unauthorized LSASS Dumping and C2 Callback Activity within a given timeframe.

> **Note:** This is a basic lab for understanding attacks. In reality, you may not know exactly what happened initially; you might just see alerts in your SIEM. You will need to adjust the timeframe based on when the event was reported.

![Diagram 2: Changing Time in Splunk](https://cdn-images-1.medium.com/max/800/1*fpwmPnH9XFRAaO-00jPN5w.png)
*(You can adjust the time range by clicking on the top right corner, which typically defaults to the last 24 hours.)*

### Step-by-Step Investigation

1.  **Understand the context:** We are provided with details about potential LSASS dumping. This points to a credential dumping scenario and possibly a connection established via a Command and Control (C2) server. We need to investigate what actually happened.
2.  **Start with unexpected activity:** We know there is some unexpected activity involving `lsass.exe`. Let's start there.
3.  **Run the initial query:**
    ```spl
    index=* sourcetype="WinEventLog:Sysmon" EventCode=10 lsass.exe 
    | stats count by SourceImage, TargetImage
    ```
    *Breakdown:* We are looking for events with `EventCode=10` (Process Access), meaning one process is interacting with another. We included `lsass.exe` because we were tipped off about it. The `stats count by SourceImage, TargetImage` command groups the results by the parent process (`SourceImage`) and the target process (`TargetImage`).

    ![Diagram 3: Related Processes](https://cdn-images-1.medium.com/max/800/1*oHIOdb4BrvZrf8LJEmgycw.png)

    Looking at the results, we see `rundll32.exe` appearing twice. This raises suspicion—why is this service calling the process multiple times?

4.  **Investigate the suspicious process:** A quick search reveals that `rundll32.exe` is **frequently abused** in LSASS dumping attacks via LOLBins (Living Off the Land Binaries). We need to dig deeper to see if this is actually malicious or benign.
5.  **Refine the query:**
    ```spl
    index=* sourcetype="WinEventLog:Sysmon" EventCode=10 SourceImage="C:\\Windows\\System32\\rundll32.exe"
    | stats count by SourceImage, TargetImage, CallTrace
    ```
    *Breakdown:* This query is similar to the last, but we've narrowed the `SourceImage` to `rundll32.exe` to see what it executed. Adding `CallTrace` gives us information about the DLLs called during execution.

    ![Diagram 4: Result related to rundll32](https://cdn-images-1.medium.com/max/800/1*uEA22XHMdOjd2Pf3o7E1pA.png)

6.  **Analyze the CallTrace:**
    
    ![Diagram 5: Some unusual DLL being called](https://cdn-images-1.medium.com/max/800/1*kVO3Oyc0iV-EtdiDejyLiQ.png)
    
    Among the DLLs, we notice one that is a common vector for LOLBin attacks. Even though the process itself is legitimate, it is being used to dump the memory of another process. The likelihood of compromise is quite high.
7.  **Check for malicious scripts:** Now that we have a lead, we will check for malicious PowerShell script execution.
8.  **Hunt for `clr.dll`:** We will look for `clr.dll`, a legitimate process often utilized by heavily obfuscated, fileless PowerShell malware.
    ```spl
    index="main" EventCode=7 ImageLoaded="*clr.dll" 
    | stats count by Image
    ```
    
    ![Diagram 6: clr.dll being called by our process](https://cdn-images-1.medium.com/max/800/1*ZrJZQNwXK_Wgqf1ih9hSPw.png)
    
    We find the process, and notably, `notepad.exe` appears suspicious here. It is actually being used for C2 activities, which we will analyze next. We now have strong indicators that malware compromised the system and utilized `lsass.exe` for credential dumping.
9.  **Investigate C2 Communication:** Since the malware dumped credentials, it is likely trying to connect to a remote server to exfiltrate data or receive further commands (RCE).
10. **Analyze Network Traffic:** We will look closely at the attack timeframe and analyze network traffic for C2 indicators:
    ```spl
    index=main sourcetype="WinEventLog:Sysmon" EventCode=3 
    | stats count by SourceIp, DestinationIp, Image
    ```
    *Breakdown:* This query fetches Sysmon logs for network connections (`EventCode=3`) and counts them by Source IP, Destination IP, and the executing Process (`Image`).

    ![Diagram 7: Communications](https://cdn-images-1.medium.com/max/800/1*CcY3hMZuFjq5XIEUoaPe2Q.png)

    Of all the processes, `notepad.exe` stands out. The rest of the traffic appears normal. The obfuscated PowerShell script was utilizing Notepad for C2 communication, leading to 3 unusual network connections that should not be happening.

---

## Next Steps for Incident Response

Now that we have successfully investigated the events, here are the recommended next steps:

1.  **Blocklist:** Blocklist the malicious IPs identified in the network traffic.
2.  **Isolate:** Isolate the affected PC from the network/internet to prevent further lateral movement or exfiltration.
3.  **Capture Volatile Data:** Take a RAM dump and a registry dump to preserve volatile components. This helps analyze persistence mechanisms and important artifacts.
4.  **Forensic Image:** Take a full forensic image of the computer's storage for deeper offline analysis.
5.  **Timeline & Root Cause:** Create a detailed timeline of events and investigate the initial infection vector (e.g., did an employee click a phishing link about winning the lottery?).

---

*This post was originally written in my note-taking software, so there may have been some minor formatting inconsistencies. Please excuse those.*

*I'd really appreciate any feedback or suggestions — feel free to ask questions or share your thoughts in the comments! *
