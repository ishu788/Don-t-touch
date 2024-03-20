## What type of controls you can apply to authentication outside of MFA/2FA?

- Implementing strict password policies can strengthen authentication
- Enforcing account lockout policies can help prevent brute-force attacks by temporarily locking out user accounts after a certain number of failed login attempts.
- Implementing CAPTCHA challenges during the authentication process can help prevent automated attacks by verifying that the user is human.
- Implementing strong session management controls, such as session timeouts and single sign-on (SSO) logout functionality

## What endpoint detection products are you familiar with and what do they do?

CrowdStrike Falcon: Falcon is an endpoint detection and response (EDR) platform that utilizes AI-driven threat intelligence and behavioral analytics to detect and respond to threats in real-time. It offers features such as malware detection, endpoint visibility, threat hunting, and incident response capabilities.

McAfee Endpoint Security: McAfee Endpoint Security is a comprehensive endpoint protection platform that offers antivirus, firewall, intrusion prevention, and advanced threat detection capabilities. It uses machine learning and behavioral analysis to identify and block threats in real-time, while also providing centralized management and reporting features for improved security posture.

## How would you harden/protect a Web Server or Firewall

- Patch Management: Regularly update the web server software, operating system, and any installed applications to address known vulnerabilities and security flaws.
- Minimal Installation: Install only the necessary components and services required for the web server to minimize the attack surface.
- Access Control: Use access control lists (ACLs) and role-based access control (RBAC) to restrict access to sensitive files, directories, and administrative functions.
- Regular audits.

### For Firewall
- IDS?IPS
- Stateful inspection


## What happens when you type “google.com” into a brand new computer?
- Dns query sent to resolve domain name
- DNs response with ip address
- http request
- server response back for http
- page render
- display

## How would you troubleshoot a host that is unable to connect to the internet?

- verify the network cable
- ping default gateway to check if user can connect to lan
- nslookup to check if dns is working
- check misconfigured firewall
- check isp for network outage

## Walk through your thought process in examining an alert that appears malicious.
- initial assessment 
     - details provided, timestamps, ip address. details matter.

- priority 
    detemined potential impact on organizzation

- correlate with security logs, logs to check for any anomalies, IOCs.
- develop a response plan based on findings of investigation.
- document your findings.

##  Describe how you would investigate a malware infection or C&C traffic on a workstation in your environment?

- isolate the work environment to prevent further damage or spreading
- document the incident
- collect relevant information, activity logs
- forensics investigation - memory dump, disk image
- analyse network traffic
- check for malware signatures
- restore workstation
- educate users 
- report and document findings.

##  How would you investigate a URL that a customer is saying is malicious?
- gather information
- verify url
- check reputation 
- web dev tools
- ssl certificate
- documnet findings.
- report to authorities

## What sort of behaviors would tell you that an EC2/VM got compromised?

unsual network logs,unusual process execution, suspicious activity , privielge escalation
, high system memory,cpu usage, unusual login attempts.

Secure Physical Access: Ensure servers hosting PKI infrastructure are physically secure with restricted access.

Implement Role-Based Access Control (RBAC): Limit administrative privileges and access to PKI components based on roles.

Secure Key Management: Protect private keys using strong key management practices and hardware security modules (HSMs).

Regularly Update and Patch Systems: Keep PKI components up-to-date with security patches to mitigate vulnerabilities.

Enable Certificate Revocation Checking: Configure clients to check for revoked certificates using CRLs or OCSP.


Backup and Disaster Recovery: Implement regular backups and disaster recovery plans for PKI components.

Periodic Security Assessments: Conduct security assessments and audits to identify and remediate weaknesses.

Employee Training and Awareness

## What sort of behavior would tell you that an Office 365 account has been compromised?

- unusual logina attempt
    - multiple failed attempts
- unexpected email changes
    - forwarding rules, auto-reply
- unauthorized access to data
    - files,documents and share point files, onedrive
- inbox deletion and data loss
- alerts triggered by office

if any of this happens, try to mitigate the impact, restore access, reset password, revoke access.

## How would you prioritize risks for a patch management program?
- asset criticality - how important is asset (server,endpoints)
- higher cvss- patch first (patch according to severity)
- more risk factor - patch first. internet facing stuff




## What strategies would you employ to get an organization through a compliance audit?

- Review regulatory requirements
- follow documents adhere complaince
- conduct risk assessment to find areas of risk
- implement control and remedies.
- educate and train personnal
- conduct perodic audit for health check.


## You run an external scan on the environment and determine port 80, 443, 445 and 3389 are all open to the internet. 

## What are those ports?
- 80   - http
- 443  - https
- 445  - smb secure message block
- 3389 - rdp remote desktop protocol


## Do any concern you?

- 80 - prone to attacks if not secure as exposed to internet
- 445 - common target for malware and exploit, such as eternal blue. Can lead to unauthorize access, privilegde escalate, data breach
- 3389 - exploit to brute force attack

##  What would you do about it?

- enable ssl for 80 and 443
- keep system up to date for 445 and 3389 
- deploy vpn for rdp for secure access
- regular monitor.


## What is a skill you bring that you might consider a differentiator between you and other applicants?

One skill that I believe sets me apart from other applicants is my ability to rapidly adapt to new challenges and environments. I excel in learning and mastering new technologies, methodologies, and domains quickly, allowing me to contribute effectively across a wide range of projects and roles.
I am passionate about continuous learning and personal development, constantly seeking out opportunities to expand my knowledge and skills. Whether it's through formal training, online courses, or self-directed study, I am committed to staying abreast of emerging trends, best practices, and industry advancements.

## Can you name two or three security vulnerabilities as per Open Web Application Security Project (OWASP)?

- SQL injection
    - Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query, leading to unexpected behavior or compromise of data integrity.
- XSS - cross site scripting
    - Cross-Site Scripting vulnerabilities occur when web applications allow untrusted data to be included in a web page without proper validation or encoding, enabling attackers to inject malicious scripts into web pages viewed by other users. Session hijacking
- broken authentication
    - Broken Authentication vulnerabilities occur when web applications fail to properly implement authentication and session management mechanisms, allowing attackers to compromise user credentials, bypass authentication controls,
- IDOR
    - Insecure Direct Object References vulnerabilities occur when a web application exposes internal implementation details, such as file paths, database records, or object identifiers, to users without proper authorization checks.

## Can you name one or more phases of the Cyber Kill Chain?

- Reconnaissance:
    - In this phase, attackers gather information about the target organization, including identifying potential vulnerabilities, weaknesses, and entry points. This may involve passive reconnaissance techniques such as open-source intelligence gathering or active reconnaissance methods such as port scanning and network enumeration.

- Weaponization:
    - During this phase, attackers develop or acquire malicious tools, exploits, or payloads to use in the attack. This may involve creating malware, crafting phishing emails, or weaponizing existing vulnerabilities to gain initial access to the target environment.

- Delivery:
    - In the delivery phase, attackers deliver the weaponized payload to the target environment. This can be done through various delivery mechanisms such as email attachments, malicious links, compromised websites, or removable media.

- Exploitation:
    - Once the payload is delivered, attackers exploit vulnerabilities in the target environment to gain unauthorized access. This may involve exploiting software vulnerabilities, misconfigurations, or weak authentication mechanisms to achieve their objectives.

- Installation:
    - In this phase, attackers establish a foothold in the target environment by installing and executing the malicious payload. This may involve dropping malware, establishing backdoors, or creating persistence mechanisms to maintain access.

- Command and Control (C2):
    - After gaining a foothold, attackers establish communication channels with external command and control infrastructure to receive instructions, exfiltrate data, or further manipulate the compromised systems. This may involve using covert communication protocols or leveraging legitimate network protocols for malicious purposes.

- Actions on Objectives:
    - In the final phase, attackers pursue their objectives, which may include data theft, data manipulation, sabotage, or other malicious activities. This phase may vary depending on the attacker's motives, goals, and targets.

## Have you used MITRE before? Describe how you would MITRE ATT&CK could help an organization?

 ### Metre Adversarial tactics, technique and common knowledge.
- Threat Intelligence: 
    - MITRE ATT&CK provides valuable insights into adversary tactics, techniques, and procedures (TTPs) used in cyberattacks. Organizations can leverage this information to enhance their threat intelligence capabilities, identify emerging threats, and prioritize defensive measures.

- Security Assessment and Red Teaming: 
     - Organizations can use MITRE ATT&CK as a framework for conducting security assessments, red team exercises, and penetration tests. By simulating real-world attack scenarios based on ATT&CK techniques, organizations can evaluate their security posture, identify weaknesses, and validate detection and response capabilities.

- Incident Response and Detection:
    -  MITRE ATT&CK can assist organizations in improving incident response and detection capabilities by providing a standardized taxonomy for categorizing and analyzing cyber threats. Security teams can map observed behaviors to ATT&CK techniques to identify indicators of compromise (IOCs), develop detection rules, and enhance incident triage and response procedures.

- Security Operations and Monitoring:        
    -  Security operations teams can use MITRE ATT&CK to improve threat hunting, monitoring, and alerting capabilities. By mapping security events and log data to ATT&CK techniques, organizations can identify anomalous behavior, detect adversarial tactics, and respond to security incidents more effectively.










