# Soc138 Detected-Suspicious-Xls-File

<img width="1575" height="747" alt="image" src="https://github.com/user-attachments/assets/1b0e5801-47af-4353-8ddf-2c48c9714b53" />

<img width="810" height="625" alt="image" src="https://github.com/user-attachments/assets/27fd0356-beb1-4eb6-9a36-4344dee056b2" />

<img width="1315" height="399" alt="image" src="https://github.com/user-attachments/assets/1364b92f-d0bb-49ce-962d-8e63ea688f62" />

## From Playbook: Define Threat indicator

Threat Indicators, also called Indicators of Compromise (IoCs), are observable traces or artifacts that suggest malicious activity has occurred or is ongoing.
They can exist at multiple layers — file, host, network, and behavioral.

In your specific incident (the suspicious Excel macro file ORDER SHEET & SPEC.xlsm), indicators can come from:

- The file itself (hashes, names, macros, strings),
- The host that interacted with it (process creation, registry keys),
- The network connections made (URLs, IPs, domains),
- The behavior (macro auto-run, PowerShell invocation, persistence, etc.).

<img width="991" height="344" alt="image" src="https://github.com/user-attachments/assets/8e7dc836-dc2b-47bd-8329-b68672866ae5" />

I visited Log Management and investigated Sofia IP address 172.16.17.56. The threat indicator here is unknown or unexpected outgoing traffic because Sofia process interacted with C2 IP address 172.16.17.56 which is a call for further investigation

<img width="1852" height="302" alt="image" src="https://github.com/user-attachments/assets/ac799d28-eb26-409e-9948-9f28e37d1d95" />


## From Playbook: Check if the malware is quarantined/cleaned

With focus on:
- Log Management
- Endpoint

<img width="981" height="459" alt="image" src="https://github.com/user-attachments/assets/def5e322-0fef-485e-abe1-5dbdf39654f8" />


Was it Quarantined?

The Alert Type Malware was not quarantined based on the information from the Investigation channel. The Device Action is "Allowed" which means the malware was executed.

From the Endpoint Security, I the Terminal hisotry shows that command like change directory (CD), DIR, and powershell command was executed with process name powershell.exe

<img width="1446" height="824" alt="image" src="https://github.com/user-attachments/assets/942c04c7-40d1-4bcc-a4de-8c6f951c807e" />


## From Playbook: Analzing Malware with Third Party Tools

<img width="799" height="483" alt="image" src="https://github.com/user-attachments/assets/66424ec7-4a18-47ee-af74-6c3a3a363a45" />

### VIRUS TOTAL


I search with the file hash "7ccf88c0bbe3b29bf19d877c4596a8d4" in Virus Total free tool and the result was mind blowing.
- I can see that 46/66 security vendors flagged this "XLSX" file  named ORDER SHEET & SPEC.xlsm as malicious.
- The file was last analysed jsut 3 days ago from the date of my findings
- The file size is 2.66mb
- The file type is XLSX
- The vedors further labels the xlsx file as trojan generic. 

Also from Virus Total, the Hispasec flagged the file as malcious. It further stated that the macro extracted from the document exhibit several signs of malicous intent such as:

1. Obfuscation: The code contains obfuscated function calls and variable names (e.g., `ShxllExxcute`, `mu38swif2`, `kmhrnbeyftc6uvhegtgrtf23tb3ubh4ienbhgfug3jyh`), which is a common technique used by malware authors to hide the true purpose of their code.

2. Suspicious Function Calls: The use of functions like `ShellExecuteA` and `ShellExecuteEx` indicates that the macro attempts to execute external programs or commands, which is a red flag for potentially malicious behavior.

3. Base64 Decoding and Execution: The presence of Base64 encoded strings (`"bgraHRUcHM6Ly9tdWx0aXdhcmV0ZWNub2xvZ2lhLmNvbS5ici9qcy9Qb2RhbGlyaTQuZXhl"`, `"gy5UG9kYWxpcmk0LmV4ZQ=="`) that are decoded and executed suggests an attempt to download and run external malicious executables.

4. Manipulation of File System Objects: The code attempts to interact with the file system (e.g., checking if certain files exist, writing to files), which can be used for dropping additional malware components or modifying system files.

5. Use of Windows API Calls: The declaration of Windows API functions (`Declare Function ShxllExxcute Lib "SHELL32.dll"`) is another indicator of potentially harmful actions being performed, such as executing shell commands.

6. Auto-Execution Mechanism: The presence of an `Auto_Open()` subroutine suggests an intention to automatically execute the malicious payload when the document is opened, without user interaction.

7. Attempt to Run Shell Commands: The construction of a command line (`veiure5278eu2 = veiure5278eu2 + csc + xcbhnjftr + fgwrfguery`) to be executed via `ShellExecute` or similar functions is indicative of an attempt to perform unauthorized operations on the victim's machine.

8. Stealth Techniques: Attempts to minimize visibility (`SW_SHOWMINIMIZED`) while executing potentially malicious activities further support the conclusion that this macro is intended for harmful purposes.

Given these observations, the macros demonstrate behaviors commonly associated with malware, including obfuscation, execution of external commands, manipulation of security settings, and attempts at persistence. Therefore, the final verdict is that these macros are malicious and pose a significant threat to the security of the system on which they are executed.


<img width="1536" height="996" alt="image" src="https://github.com/user-attachments/assets/2644b96f-b1bd-4afd-957e-6b856cf66de8" />


## Virus Total Cont. (Details section)


<img width="1624" height="938" alt="image" src="https://github.com/user-attachments/assets/a46a75c4-1906-4be6-bf78-61aa6d3cbbe7" />


The detail history section provides the relevant date the events of the file hash was last investigated. The section further revealed that the file hash was firstly investigated on 01.02.2020 up to recently which is 17.10.2025 whcih is a call for sensitization to soc analzýst to take note of the IP address and behavioural informations associated to this threat.
- The details as well has various names which the file has been submitted or seen in the wild jsut to mention a few according to virusTotal
  1. ORDER SHEET
  2. SPEC.xlsm
  3. mal.xlsm
  4. virus.xlsm
  5. infected.xlsm
  6. kaka.xlsm
  7. malware.xlsm


## From Playbook: URlSCAN

from the Urlscan, I can see that there were:
- Two HTTP Transactions recorded from the page
- The doamin was scanned 87 times previously which shows some signs of suspicion
- The doamin IP address 177.11.52.83 and the IP Sofia machine interacted with 177.53.143.89 geographically both in Brazil but not on the same network which somehow represents different stages
I will therefore say that the outcome of the URLSCAN to me is suspicious.

<img width="1209" height="938" alt="image" src="https://github.com/user-attachments/assets/5e213aac-0df8-4260-a3f6-7b513e74499f" />


## From Playbook: Hybrid Analysis

I searched further with the url on Hybrid-analysis.com and the result further justified my conclusion with urlscan.io.
- From  Hybrid Analyses, there are four falcon sandbox reports that occured on windows 10 machines where Threat scores recorded are 4x 100/100 and 99/100.

<img width="1512" height="826" alt="image" src="https://github.com/user-attachments/assets/1fa88886-d5f0-4214-9437-f3d0b22e23e7" />


<img width="1345" height="522" alt="image" src="https://github.com/user-attachments/assets/b1c9ca2e-59e3-4215-93f9-303936cc3ca5" />

With all indicators and findings so far, I can already accept that the file is malicious and therefore a call of response to me to further check if there is the host machine that interacted with the malicous ip.
- From the firewall alert, I can see that the machine interacted with Ip address 177.53.143.89 twice same time on Mar, 13, 2021, 08:20 PM
- The Proxy also revealed interaction with IP 35.189.10.17. I checked URLSCAN.  However, this is pointing me to another Url site that have been part of a campaign and later cleaned up or changed the live scna also returned error 404. I will still treat the domain / IP as suspicious and correlate with your internal logs (downloads). This means Sofia machine actuallz contacted different destination IP address.

<img width="1860" height="351" alt="image" src="https://github.com/user-attachments/assets/19816b69-f850-40c3-a61e-1a02466098ec" />

## Check If Someone Requested the C2

What is “command C2?

C2 (short for Command and Control, often written “C2”) is the infrastructure and communication channel that an attacker uses to issue commands to malware running on compromised machines and to receive data back (logs, stolen files, status). 
- A command C2 refers specifically to the command side of that channel, the mechanisms and messages the attacker sends to control infected hosts
- I checked the C2 used by the malware for beaconing with the IP section of Behaviour in the virus total.
- Also with the image above, we see that sofia machine accessed the malicious IP 177.53.143.89.
- From the alert, with device action is "allowed". It means the log entry verifies that the connection was not blocked at the time of execution.


Therefore, I accepted "accessed" on playbook.



<img width="1101" height="377" alt="image" src="https://github.com/user-attachments/assets/f644c692-6d45-473a-8442-5655c17f2c9c" />


# Containment

<img width="803" height="423" alt="image" src="https://github.com/user-attachments/assets/115a5e80-e9db-4e9d-ad20-5945f9363ba7" />


I searched for the host information in endpoint security with the host IP address of the case 172.16.17.56. I cointained Sofia host machine. This will disconnect the machine from Network and prevent further spread of threats.

<img width="1545" height="704" alt="image" src="https://github.com/user-attachments/assets/b93c0025-9ec5-409a-bb31-11c431c1f4e4" />

# Add Artifacts

## Artifacts = Evidence of behavior.
They’re the traces that show how, when, and what happened on a system or in a network.

- Malicious IP: 177.53.143.89
- File Hash: 7ccf88c0bbe3b29bf19d877c4596a8d4
- Malicious Url: multiwaretecnologia.com.br

<img width="820" height="477" alt="image" src="https://github.com/user-attachments/assets/6d9df989-c59d-444c-b376-6a8b4ea84a41" />

# Analysis Note

- The investigation confirmed that the Excel file ORDER SHEET & SPEC.xlsm was malicious, containing obfuscated VBA macros that executed PowerShell commands to communicate with a remote Command and Control (C2) server at 177.53.143.89.
- The machine Also made HTTP request to the malicious IP.
- The host Sofia (172.16.17.56) was successfully contained to prevent further spread.
- Artifacts and IoCs have been documented for broader environment scanning and future detection tuning.
- Third-Party Threat Intelligence Correlation: VirusTotal, Hybrid Analysis, URLScan.io, Behavioral Analysis.
  
<img width="843" height="462" alt="image" src="https://github.com/user-attachments/assets/1369223e-3bfa-496e-95c4-5611d5f6a588" />

# Finished Playbook

<img width="796" height="377" alt="image" src="https://github.com/user-attachments/assets/25226664-713e-4803-b63c-cd85ff2b8b59" />
<img width="1039" height="641" alt="image" src="https://github.com/user-attachments/assets/5402b2e1-9ae2-488a-ae87-143eec89f664" />

# Closing The Ticket

I closed the alert as "True Positive". Further steps need to be taken by the Tier 2 analysts. Also as shown below, the letsdefend score my analysis with a full point which means all investigation steps are well taken and I haope you will enjoy this project as well. 

<img width="734" height="480" alt="image" src="https://github.com/user-attachments/assets/453e917b-a517-472e-b13b-351933e8a92c" />
<img width="1656" height="614" alt="image" src="https://github.com/user-attachments/assets/d99a0d3b-2547-4086-b5b0-0682a88aacc4" />
