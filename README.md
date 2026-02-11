## Log Analysis Using SIEM (Splunk)

## Objectives

* To monitor, analyze, and correlate security logs from multiple data sources using Splunk.
* To detect suspicious activities, security incidents, and potential threats in real time.
* To improve incident response capabilities through timely alerting and investigation.
* To strengthen my understanding of log behavior and attack patterns in a SOC environment on tryhackme.

## Skills Learned

* Security log analysis and event correlation
* Identifying Indicators of Compromise (IOCs)
* Writing and optimizing SPL (Search Processing Language) queries
* Incident detection and triage
* Understanding attacker techniques (brute force, lateral movement, privilege escalation)
* Analyzing authentication, network, and endpoint logs
* Time-based analysis and pattern recognition
* Documentation and reporting of security findings

## Tools Used

* Splunk Enterprise 
* SPL (Search Processing Language)
* Windows Event Logs
* Firewall Logs
* Sysmon Logs
* Linux System Logs

## Steps of Log Analysis Using Splunk

As a SOC Level 1 Analyst, I’ve learned that a SIEM is only as powerful as the person writing the queries. During this investigation on the TryHackMe platform, I analyzed Windows, Linux, and Web logs to hunt down malicious activity. Here is my step-by-step breakdown of the investigation.

## PHASE 1

## Windows Host Analysis:
In this stage, I focused on identifying a command-and-control (C2) connection and how the attacker maintained a foothold in the system. To identify the suspicious network connection, I used the following query:

**​index=task4 EventCode=3 ComputerName=WIN-105 | table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol**

Why I Used This Query:

**​index=task4:** Targets the specific dataset assigned for the Windows investigation.

**​EventCode=3:** This is the Sysmon event code for Network Connection. It allowed me to see exactly which processes were communicating over the network.

**​table ...:** I formatted the results into a table to easily correlate the process name (SharePoInt.exe) with its destination IP (10.10.114.80) and port (5678).


<img width="780" height="282" alt="image" src="https://github.com/user-attachments/assets/c9382a5c-ab4c-4738-984c-354172068daa" />



* Identifying the Suspicious Process: While reviewing Sysmon events, I noticed a process named SharePoInt.exe (note the capital "I" used to masquerade as the legitimate SharePoint application).
* Locating the C2 Connection: I queried for network connections not using standard ports. I found that SharePoInt.exe established a connection to the IP address 10.10.114.80.
* Extracting the Payload Hash: To confirm the file's malicious nature, I extracted its MD5 hash: 770D14FFA142F09730B415506249E7D1.

<img width="780" height="365" alt="image" src="https://github.com/user-attachments/assets/3da9a113-3db6-4701-b160-0b342ba7e6bd" />


* Persistence Mechanism: I searched for scheduled task creations (schtasks.exe) to see how the malware survived reboots. I found a task named Office365 Install that was configured to execute the malicious binary from a temporary folder.



## PHASE 2

## Linux Forensic Analysis:
I pivoted to the Linux logs to track how an attacker gained administrative rights and created a backdoor.

<img width="780" height="274" alt="image" src="https://github.com/user-attachments/assets/6631d0a8-7016-474c-8c71-fd3c8af1741c" />


* Privilege Escalation: By analyzing sudo and su logs in Splunk, I identified that the user jack-brown successfully escalated their privileges to root

* Backdoor Account Creation: Once they had root access, I observed them creating a new account named remote-ssh for persistent access.

<img width="780" height="200" alt="image" src="https://github.com/user-attachments/assets/c049df7c-b536-4cef-9650-c19f05e927d3" />


* Incident Timeline: I recorded the exact timestamp of this account creation as 2025-08-12 09:52:57.
* Origin of Attack: I traced the successful login back to the IP address 10.14.94.82.
* Brute Force Evidence: Before the successful entry, I counted 4 failed login attempts from that same IP, suggesting a targeted attack.


<img width="780" height="274" alt="image" src="https://github.com/user-attachments/assets/2633b540-4544-4d75-8ab8-500ac3a055d7" />

* Listener Configuration: I found a persistence mechanism configured to connect or listen on port 7654.

## PHASE 3

## Web Application Log Analysis:
Finally, I analyzed the web server logs to classify external threats targeting the company's website.

* Targeted URI: I used a statistical query to find the most requested path. The URI wp-login.php had the highest number of requests, indicating a focus on the login portal.

<img width="780" height="425" alt="image" src="https://github.com/user-attachments/assets/4dda9bda-ca05-4c41-a7b4-41a9e84540c3" />

* Attacker Identification: The source of this activity was the IP address 10.10.243.134.
* Attack Classification: Based on the high volume of POST requests to the login page, I classified this activity as a Brute Force attack.
* Tooling Discovery: I examined the User-Agent strings and discovered the attacker was using WPScan (a WordPress security scanner) to automate the attack.

## SUMMARY

By correlating data across different log sources, I was able to piece together a full narrative: an external brute force attack led to initial access, followed by privilege escalation and the establishment of persistent backdoors on both Windows and Linux systems.
