Hands-On SIEM Investigation: LSASS Dumping, LOLBins, and C2 Detection
In this lab I will be walking you through how to detect some attacks in a Splunk environment.

Splunk Architecture
Firstly, we need to understand what Splunk is and how its SIEM architecture works for investigations.
Splunk has 3 main components:
Forwarders — A Splunk forwarder collects data from remote systems and forwards it to a Splunk indexer for centralized indexing, storage, and analysis. Think of it as the component that collects application logs and security logs from endpoints — whether that's a local PC or all components of an Active Directory environment. In short: it sends logs to a central location for indexing.
Indexers — These handle the incoming logs by organizing and storing them based on indexes. For example, Windows and Linux application logs can be managed separately using different indexes. Indexers are also responsible for processing search queries from Search Heads.
Search Heads — This is the main interface we interact with. We write queries here, which are then passed to the indexers to retrieve results.
Show Image

There are additional components involved in a full deployment, but these three are the core ones you'll encounter first.

SPL (Search Processing Language) is the query language used by Splunk for searching, filtering, and manipulating data.

Splunk Queries (SPL)
splindex="main"

Note: The search command is implicit — you don't need to type it in the Search Head.

To search across all indexes:
splindex=*
To fetch Sysmon logs while excluding Event ID 1 (process creation events):
splindex="main" sourcetype="WinEventLog:Sysmon" EventCode!=1
More information about Sysmon and Event IDs:

Sysmon Documentation
Splunk SPL Cheat Sheet

To generate a table showing time, host, and process image for process creation events:
splindex="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image

Detection Scenario: Unauthorized LSASS Dumping and C2 Callback Activity

Note: This is a basic lab for understanding attack detection. In a real investigation, you won't always know exactly what happened — you may only see alerts in your SIEM. Adjust the time range to match the reported event window.

To change the time range in Splunk, click the time picker in the top-right corner (e.g., "Last 24 hrs").
Show Image
Step 1: Investigate LSASS Access (EventCode 10)
We've been informed of suspicious activity involving lsass.exe, so we start there.
splindex=* sourcetype="WinEventLog:Sysmon" EventCode=10 lsass.exe
| stats count by SourceImage, TargetImage
Query breakdown:

EventCode=10 — a process is opening/accessing another process
lsass.exe — filtering for activity related to the reported process
stats count by SourceImage, TargetImage — counts occurrences grouped by the source and target process

Show Image
rundll32.exe appears twice here, which is suspicious — why would this service be calling the process two times?
Step 2: Investigate rundll32 Further (LOLBin Abuse)
rundll32.exe is frequently abused in LSASS dumping attacks via LOLBins (Living Off the Land Binaries). We dig deeper:
splindex=* sourcetype="WinEventLog:Sysmon" EventCode=10 SourceImage="C:\\Windows\\System32\\rundll32.exe"
| stats count by SourceImage, TargetImage, CallTrace
This query adds CallTrace to show which DLLs were loaded during execution.
Show Image
Analyzing the CallTrace:
Show Image
Among the DLLs, one stands out as a known attack surface for LOLBins. While the DLL itself is legitimate, it is commonly used for dumping memory from other processes. This significantly raises the likelihood of compromise.
Step 3: Look for Malicious PowerShell via clr.dll (EventCode 7)
clr.dll is a legitimate Windows DLL, but it is frequently loaded by fileless malware and heavily obfuscated PowerShell scripts.
splindex="main" EventCode=7 ImageLoaded="*clr.dll"
| stats count by Image
Show Image
We now have strong indications that malware has entered the system. Notably, notepad.exe also appears here — which we'll investigate next as a suspected C2 vector.
Step 4: Investigate C2 Communication (EventCode 3)
With malware confirmed on the system performing credential dumping via lsass.exe, it's likely establishing communication with a remote server (C2). We look at network activity during the attack's time window:
splindex=main sourcetype="WinEventLog:Sysmon" EventCode=3
| stats count by SourceIp, DestinationIp, Image
Most traffic appears normal, but notepad.exe generating network connections is highly suspicious — the obfuscated PowerShell script appears to be using notepad.exe as a C2 communication vehicle.
Show Image
notepad.exe shows 3 network connection results — this should never happen under normal circumstances.

Summary and Recommended Next Steps
Having investigated the events, here are the recommended follow-up actions:

Blocklist the malicious IPs identified in the C2 communication logs.
Isolate the affected machine from the network immediately.
Capture volatile artifacts — take RAM dumps and registry exports to analyze persistence mechanisms before powering down.
Take a full forensic image of the system's disk for deeper offline analysis.
Build a timeline of events — trace back to the initial infection vector (e.g., a suspicious file download, phishing email, etc.).


This post was originally written in note-taking software, so there may be minor formatting inconsistencies. Feedback and questions are welcome!
