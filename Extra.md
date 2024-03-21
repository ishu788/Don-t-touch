
## Left alone with company computer?

I would like to clarify that I approach computer security with a strong commitment to ethical behavior and adherence to legal and organizational guidelines. If I were to find myself in a situation where I had access to a computer system, my actions would be governed by ethical considerations and organizational policies.

Rather than attempting to exploit the system, I would use my access to identify and report any security vulnerabilities or weaknesses to the appropriate personnel within the organization. This might involve conducting vulnerability assessments, reviewing system configurations, or analyzing security logs to identify potential risks.

I believe that transparency, collaboration, and a proactive approach to security are essential in protecting computer systems and sensitive data. Therefore, my priority would be to work with IT security professionals to address any identified issues and strengthen the overall security posture of the organization."


## Zero Trust

Zero Trust is a security concept and model that assumes that threats may exist both outside and inside the network. Traditional security models typically rely on perimeter-based defenses, assuming that everything inside the network is trustworthy. In contrast, Zero Trust operates on the principle of "never trust, always verify."


## TCP vs UDP 

-  TCP (Transmission Control Protocol):
    - Connection-oriented: Establishes a connection before data transfer.
    - Reliable: Ensures ordered and error-checked delivery of data.
    - Slower but more reliable.
    - Examples: Web browsing, email, FTP.

- UDP (User Datagram Protocol):
    - Connectionless: No prior connection setup.
    - Unreliable: No guaranteed delivery or order of data.
    - Faster but less reliable.
    - Examples: Real-time communication (VoIP, video calls), online gaming, DNS


## Tell me what are the biggest Active Directory vulnerabilities issues? Why

- weak password
- Lack of mfa
- misconfigerations
- Human and insider threats
- Inadequate backup


## Tell me how would you detect and mitigate ddos attack?

- network monitoring
- anamoly detection
- Traffic redirection
- Execute incident response plan

## Tell me how would you optimize and secure a subnet?

- network fragmentation
- vlans
- firewall rules acl rules
- authentication and authorization



## Can you tell me about the main differences between AWS and Azure? When would you use one over the other

AWS and Azure are leading cloud platforms, but they have some key differences. AWS has been around longer and has a larger market share

In terms of service offerings, both platforms are comprehensive, but AWS has a broader range of services. When it comes to pricing, both follow a pay-as-you-go model, but AWS offers more flexibility with pricing options


## What are some of the positives and negatives of having all web traffic route through a proxy

### Positives 
- enhanced security
- anonymity

### Negativies
- single point of failure
- increased latency
- privacy concerns


## How would you design a commercial sized corporate network while keeping security in mind

- DMZ (perimeter security)
- network segmentation
- continous monitoring
- IAM
- Regular Security assessments

## What are the implications of applying MDM solutions to non-corporate owned devices

- ownership problem
- user experience affected
- always keep personal and professional data separated


## What’s the difference between AV and Endpoint Detection?

Antivirus (AV) primarily focuses on detecting and blocking known malware threats using signature-based methods. Endpoint Detection and Response (EDR) provides broader visibility and advanced detection capabilities, including behavioral analysis and threat hunting, to detect and respond to a wide range of security threats, including advanced and zero-day attacks. EDR solutions offer real-time response capabilities and proactive threat hunting, making them essential for modern endpoint security.

## Tell me what Content Network Delivery (CND) tools do you knowledge or experience with?
- cloudflare
- Google CDN
- Akamai

## Tell me how would you secure a database?
- input sanitization always make sure input is sanitized and sending only things we need. If not attacker can inject string to run sql commands from input

- Parameterizd queries = can be useed to restrict direct access of variables.


## Tell me how would you analyze a suspicious email?

Headers  From,To x-headers
Message ID

DKIM signatures
Recived - IP,SMT,TLS