**Tools**

- **SURICATA** - A high performance Network Intrusion Detection System (NIDS), Intrusion Prevention System (IPS), and Network Security Monitoring engine. Suricata inspects the network traffic using a powerful and extensive rules and signature language and has powerful Lua scripting support for detection of complex threats. Suricata implements a complete signature language to match on known threats, policy violations and malicious behavior. Suricata will also detect many anomalies in the traffic it inspects. Suricata can log HTTP requests, log and store TLS certificates, extract files from flows and store them to disk. The full PCAP capture support allows easy analysis. All this makes Suricata a powerful engine for your Network Security Monitoring (NSM).

- **NMAP** - Nmap (Network Mapper) is an open source tool for network exploration and security auditing. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. The output from Nmap is a list of scanned targets, with supplemental information on each depending on the options used. Key among that information is the &quot;interesting ports table&quot;.  That table lists the port number and protocol, service name, and state. The state is either open, filtered, closed, or unfiltered. The port table may also include software version details when version detection has been requested. When an IP protocol scan is requested (-sO), Nmap provides information on supported IP protocols rather than listening ports. In addition to the interesting ports table, Nmap can provide further information on targets, including reverse DNS names, operating system guesses, device types, and MAC addresses.
- **NMAP Useful Commands:**
  - Nmap -sP 10.0.0.0/24
    - Ping scanning, can be used to see what machines are online and respond to a ping over a network
  - Nmap -p 1-65535 -sV -sS -T4 &quot;target&quot; – sV is used for version detection when scanning, - sS is the standard stealth scan that is usually the most popular scan to run. You can scan a range of port by separating the ports with a dash or you can scan multiple ports by separating the ports with commas.
    - sV is used for version detection when scanning
    - sS is the standard SYN stealth scan that is usually the most popular scan to run due to it&#39;s speed and ability to work against all TCP stacks
    - sT is a scan used when the sS SYN scan will not work in cases of scanning IPv6 targets typically
    - sU is used to scan UDP ports
  - Nmap -sA TCP ACK Scan
    - Scan is used to map out a network&#39;s firewall rules typically, cannot see open or closed ports
  - nmap -sW (target)
  - -sW is a windowed scan that is like a TCP ACK scan, but it can see open and closed ports
- **NSLOOKUP – ** The NsLookup tool allows you to query DNS servers for resource records. NsLookup queries the specified DNS server and retrieves the requested records that are associated with the domain name you provided. NsLookup has two modes: interactive and non-interactive. Interactive mode allows the user to query name servers for information about various hosts and domains or to print a list of hosts in a domain. Non-interactive mode is used to print just the name and requested information for a host or domain.
- **NSLOOKUP –**** Useful Commands:**
  - **To use NsLookup enter the following:**** nslookup [domain]**
  - **A**** :** the IPv4 address of the domain.
  - **AAAA**** :** the domain&#39;s IPv6 address.
  - **CNAME**** :** the canonical name — allowing one domain name to map on to another. This allows more than one website to refer to a single web server.
  - **MX**** :** the server that handles email for the domain.
  - **NS**** :** one or more authoritative name server records for the domain.
  - **TXT**** :** a record containing information for use outside the DNS server.

- **WHOIS - ** Whois is a service that provides basic information about a registered domain, such as domain owner contact information, IP address block, domain availability status and the company with which the domain is registered. Whois is a query and response protocol that stores and delivers information related to the registered domain in a human-readable format.

From a Whois search you can find the following information about an IP address or domain:

-
  - IP location
  - ANS information
  - Network range/CIDR information
  - Organization
  - Date registered
  - Physical location (State, city, address)

- **OSCAP -**  Open Security Content Automation Protocol (SCAP) toolkit based on OpenSCAP library. It provides various functions for different SCAP specifications(modules). OpenSCAP tool claims to provide capabilities of Authenticated Configuration Scanner and Authenticated Vulnerability Scanner as defined by The National Institute of Standards and Technology.

- **SCAP-WORKBENCH – ** A graphical utility tool that offers an easy way to perform common OSCAP (Open Security Content Automation Protocol) tasks. The tool allows users to perform configuration and vulnerability scans on a single local or remote system; In addition, the tool can perform remediation of the system in accordance with given XCCDF or SDS files. SCAP-Workbench can also generate reports containing the results of the system scan.

Program shows commands to run in cli to limit access or to log activity for users with specific commands that have authority. Can be used to see if a specific user is doing things that shouldn&#39;t be through tracking or can be used to test and see if certain commands are enabled and if they should be or not for security sake.

- **LASTPASS - ** LastPass is a password manager that stores encrypted passwords online. A user&#39;s content in LastPass, including passwords and secure notes, is protected by one master password. The content is synchronized to any device the user uses the LastPass software or app extensions on. Information is encrypted with AES-256 encryption with PBKDF2 SHA-256, salted hashes, and the ability to increase password iterations value. Encryption and decryption take place at the device level.

- **NETSTAT- ** Netstat is a very powerful tool that can be used to print network connections, routing tables, interface statistics, masquerade connections, and multicast memberships. It is a utility that displays network connections for Transmission Control Protocol, routing tables, and several network interface and network protocol statistics. It is used for finding problems in the network and to determine the amount of traffic on the network as a performance measurement. Netstat can be used to determine incidents such as DoS/DDoS and C&amp;C communications.
- **NETSTAT – Useful Commands:**
- netstat-na
  - This display all active Internet connections to the server and only established connections are included.
- netstat-an|grep :80|sort
  - Show only active Internet connections to the server on port 80, this is the http port and so it&#39;s useful if you have a web server and sort the results. Useful in detecting a single flood by allowing you to recognize many connections coming from one IP.
- netstat-n-p|grep SYN\_REC |wc-l
  - This command is useful to find out how many active SYNC\_REC are occurring on the server. The number should be pretty low, preferably less than 5. On DoS attack incidents or mail bombs, the number can jump to pretty high.
- netstat -ntu | grep ESTAB | awk &#39;{print $5}&#39; | cut -d: -f1 | sort | uniq -c | sort -nr
  - Check on ESTABLISHED connections instead of all connections and displays the connections count for each IP.
- **NETSTAT &amp; NMAP Used Together for Incident Response**
  - Nmap and Netstat can be used together in an incident response scenario to gather information on whether an attacked is actively within an infected machine or network. Using Nmap a user can initiate a port scan on the machine in question. This scan will reveal open and closed ports on this device. After finding the open and closed ports, a user can then use Netstat to see all currently active connections on the machine. These connections are shown through port numbers.

- **OSQUERY – ** OSquery is an operating system instrumentation framework for Windows, macOS, Linux, and FreeBSD. The tools make low-level operating system analytics and monitoring both performant and intuitive. The high-performance and low-footprint distributed host monitoring daemon, OSqueryd, allows you to schedule queries to be executed across your entire infrastructure. The daemon takes care of aggregating the query results over time and generates logs which indicate state changes in your infrastructure. You can use this to maintain insight into the security, performance, configuration, and state of your entire infrastructure. OSqueryd&#39;s logging can integrate into your internal log aggregation pipeline.

- **IPTRAF - ** IPTraf is a network monitoring utility for IP networks. It intercepts packets on the network and gives out various pieces of information about the current IP traffic over it. IPTraf can be used to monitor the load on an IP network, the most used types of network services, the proceedings of TCP connections, and others. IPTraf is software-only and utilizes the built-in raw packet capture interface of the Linux kernel, allowing it to be used with a wide range of Ethernet cards, supported FDDI adapters, supported ISDN adapters, and any asynchronous SLIP/PPP interface. No special hardware is required.
- **How to Use IPTRAF:**
  - Typing iptraf-ng into the cli will launch the iptraf interface, once launched you will be able to select &quot;IP Traffic Monitor&quot;. Here you will see all IP traffic to and from the IP of your machine
    - You may select one of three interfaces or view them all. Lo, ens192 or en224.
    - This can be used to view any network traffic coming across this machine to see where a potential attack could be coming from.
    - You can see the port for each IP address as well and this can be used to isolate ports and close them if the event demands it.

- **IPTRAF – Useful Commands:**
  - i _iface_
    - causes the IP traffic monitor to start immediately on the specified interface. If -i all is specified, all interfaces are monitored.
  - -g
    - starts the general interface statistics
  - -d _iface_
    - shows detailed statistics for the specified interface
  - -s _iface_
    - starts the TCP/UDP traffic monitor for the specified interface
  - -z _iface_
    - starts the packet size breakdown for the specified interface
  - -l _iface_
    - starts the LAN station monitor on the specified interface. If -l all is specified, all LAN interfaces are monitored.
  - -L _filename_
    - Allows you to specify an alternate log file name when the -B parameter is used. Otherwise the default log file name will be used. If an absolute path is not specified, the log file will be created in the default log file directory

- **NTOPNG – ** A passive network monitoring tool focused on flows and statistics that can be obtained from the traffic captured by the server. NTOPNG centers and has been developed around some basic concepts that include network interfaces and hosts. It can generate alerts to report the occurrence of events and user-configurable thresholds.
- **How to use NTOPNG:**

<span style="color: red;">To use Ntopng you must access it via port 3050 within a browser. Upon coming to the login page, you must have an account made to login with. Once logged in Ntopng offers detailed graphs that display information about a network and the hosts on that network. Once you are in the webpage GUI, you will be presented with information about the &quot;Top Flow Talkers&quot; or the assets using the most bandwidth. You can double click on these &#39;talkers&#39; to view detailed information about the active flows for that asset. Some information that can be found here: The application being used, the OSI Layer 4 protocol, the client name &amp; port, the server, a breakdown between the client and server, total bytes of data and additional information.</span>

If you select &#39;Hosts&#39;, you will view a pie graph with the &quot;top hosts&quot; that have sent and received connection from the machine this program is installed on. Additionally, you can click on the host IP address, and this will take you to a page that displays more detailed information about that host. This includes the OS of the device connected, the sent and received traffic broken down, the MAC address of the device, etc. You can also view the ports that this device connects via, the protocols that the device uses to connect, the packets sent back and forth, etc.

- **OPENVAS – ** OpenVAS is a full-featured vulnerability scanner. Its capabilities include unauthenticated testing, authenticated testing, various high level and low-level Internet and industrial protocols, performance tuning for large-scale scans and a powerful internal programming language to implement any type of vulnerability test. The scanner is accompanied by a vulnerability tests feed with a long history and daily updates. This Greenbone Community Feed includes more than 50,000 vulnerability tests.

OpenVAS offers a multitude of services such as:

-
  -
    - Scanning a machine to detect potential vulnerabilities to see how an intruder may have gained access to the system.
    - In incident response, it is important to investigate the vulnerabilities to determine where an intruder may have gotten in from. This information can be used to patch vulnerabilities on the system to prevent future incidents.
    - OpenVAS can be used to scan for vulnerabilities that may be present so they can be remediated before an incident occurs.

- **WIRESHARK/TSHARK – ** Wireshark is the world&#39;s most foremost and widely-used network packet analyzer. It is a free and open-source packet analyzer. A network packet analyzer presents captured packet data in as much detail as possible. Wireshark can capture traffic from many different network media types, including Ethernet, Wireless LAN, Bluetooth, USB, and more.

Tshark allows for a live capture of network traffic in the CLI. The capture can be used for incident response to determine where connections are being established from and where data is being sent too.

- **How to use Tshark:**

In the CLI you can just run sudo tshark to begin capturing live traffic on your machine. To stop this capture you must press CTRL + C

You can filter by protocol by entering tshark [name of protocol] For a full list of protocols enter tshark -G protocols

- **NODEJS - **** Node.js** is an open-source, cross-platform, JavaScript runtime environment that executes JavaScript code outside of a browser. Node.js lets developers use JavaScript to write command line tools and for server-side scripting—running scripts server-side to produce dynamic web page content before the page is sent to the user&#39;s web browser. Consequently, Node.js represents a &quot;JavaScript everywhere&quot; paradigm, unifying web-application development around a single programming language, rather than different languages for server- and client-side scripts.

**Types of Incidents**

**DoS/DDoS Categories:**

- **Volume Based Attacks**
Includes UDP floods, ICMP floods, and other spoofed-packet floods. The attack&#39;s goal is to saturate the bandwidth of the attacked site, and magnitude is measured in bits per second (Bps).
- **Protocol Attacks **
Includes SYN floods, fragmented packet attacks, Ping of Death, Smurf DDoS and more. This type of attack consumes actual server resources, or intermediate communication equipment, such as firewalls and load balancers. This is measured in packets per second (Pps).
- **Application Layer Attacks **
Includes low-and-slow attacks, GET/POST floods, attacks that target Apache, Windows or OpenBSD vulnerabilities and more. Comprised of seemingly legitimate and innocent requests, the goal of these attacks is to crash the web server, and the magnitude is measured in Requests per second (Rps).

**Common DDoS Attack Types:**

- **UDP Flood**

A UDP flood is any DDoS attack that floods a target with User Datagram Protocol (UDP) packets. The goal of the attack is to flood random ports on a remote host. This causes the host to repeatedly check for the application listening at that port, and (when no application is found) reply with an ICMP &#39;Destination Unreachable&#39; packet. This process saps host resources, which can ultimately lead to inaccessibility.

- **ICMP (Ping) Flood**

An ICMP flood overwhelms the target resource with ICMP Echo Request (ping) packets, generally sending packets as fast as possible without waiting for replies. This type of attack can consume both outgoing and incoming bandwidth, since the victim&#39;s servers will often attempt to respond with ICMP Echo Reply packets, resulting a significant overall system slowdown.

- **SYN Flood**

A SYN flood DDoS attack exploits a known weakness in the TCP connection sequence (the &quot;three-way handshake&quot;), wherein a SYN request to initiate a TCP connection with a host must be answered by a SYN-ACK response from that host, and then confirmed by an ACK response from the requester. In a SYN flood scenario, the requester sends multiple SYN requests, but either does not respond to the host&#39;s SYN-ACK response or sends the SYN requests from a spoofed IP address. Either way, the host system continues to wait for acknowledgement for each of the requests, binding resources until no new connections can be made, and ultimately resulting in denial of service.

- **Ping of Death**

A ping of death (&quot;POD&quot;) attack involves the attacker sending multiple malformed or malicious pings to a computer. The maximum packet length of an IP packet (including header) is 65,535 bytes. However, the Data Link Layer usually poses limits to the maximum frame size – for example 1500 bytes over an Ethernet network. In this case, a large IP packet is split across multiple IP packets (known as fragments), and the recipient host reassembles the IP fragments into the complete packet. In a Ping of Death scenario, following malicious manipulation of fragment content, the recipient ends up with an IP packet which is larger than 65,535 bytes when reassembled. This can overflow memory buffers allocated for the packet, causing denial of service for legitimate packets.

- **Slowloris**

Slowloris is a highly-targeted attack, enabling one web server to take down another server, without affecting other services or ports on the target network. Slowloris does this by holding as many connections to the target web server open for as long as possible. It accomplishes this by creating connections to the target server but sending only a partial request. Slowloris constantly sends more HTTP headers, but never completes a request. The targeted server keeps each of these false connections open. This eventually overflows the maximum concurrent connection pool and leads to denial of additional connections from legitimate clients.

- **NTP Amplification**

In NTP amplification attacks, the perpetrator exploits publicly-accessible Network Time Protocol (NTP) servers to overwhelm a targeted server with UDP traffic. The attack is defined as an amplification assault because the query-to-response ratio in such scenarios is anywhere between 1:20 and 1:200 or more. This means that any attacker that obtains a list of open NTP servers (e.g., by a using tool like Metasploit or data from the Open NTP Project) can easily generate a devastating high-bandwidth, high-volume DDoS attack.

- **HTTP Flood**

In an HTTP flood DDoS attack, the attacker exploits seemingly-legitimate HTTP GET or POST requests to attack a web server or application. HTTP floods do not use malformed packets, spoofing or reflection techniques, and require less bandwidth than other attacks to bring down the targeted site or server. The attack is most effective when it forces the server or application to allocate the maximum resources possible in response to every single request.

**Tools &amp; Commands for DoS/DDoS Incident Response:**

- **Tshark**

Using **Tshark** you can monitor network traffic to find out if you are getting DDoS&#39;d or not through filtering and commands in CLI. Filtering by SYN and ACK Flags will show all inbound network traffic containing a SYN and ACK flag. If you compare this traffic to traffic that ONLY contains SYN flags, and this amount of traffic is rather unusual, then you could be experiencing a SYN Flood attack.

- You can filter by protocol (tshark  \*name of protocol\*) to help determine just specific types of attacks. For example, you can run _tshark ICMP_ to try and view all ICMP related traffic. For a full list of all protocols type: _tshark –G_ _protocols_

- **SYN flood** attacks try to overwhelm a server&#39;s buffer. Use the following tips to detect a SYN flood on your network:
  - Look out for an immense number of TCP connection requests. The proper display filter is **tcp.flags.syn == 1 and tcp.flags.ack == 0**
  - The server, that is under attack, will respond with a smaller number of SYN/ACKs. These can be spotted with the display filter **tcp.flags.syn == 1 and tcp.flags.ack == 1**
  - Try to compare the number of SYNs with the number of SYN/ACKs. If the numbers are identical your firewall or server is holding up.
  - Very often, the source addresses are spoofed. A good indicator of a spoofed source address is a packet with the RST bit set in response to the SYN/ACK from your server. The normal response would be a packet with just the ACK flag being set.
- **IPtraf**

Use the command iptraf-ng; a GUI should appear. Select IP traffic monitor, you will then be displayed the all interfaces, the ethernet and WiFi network cards. Lo is the loopback address. If you select all interfaces, you will see all network traffic on the machine or server. You will be able to see the number of packets and bytes within those packets and where they are coming from and where they are going. You can use this to look for an abnormally large number of packets or bytes of data. If you see something abnormal, you can select it and view information about the traffic in the bottom area of the GUI.

You can also determine the type of DoS attack or DDoS attack you are suffering from based on the protocols from the traffic that can be seen in the bottom of the GUI.

You can decide to enable the logging option within the configuration settings. This will allow the network log to be saved in real time in the file specified when choosing the monitoring type. By logging the network traffic, you can go back to analyze the traffic that was captured. The default location of the logs when enabled can be found in the &quot;/var/log/iptraff/&quot; folder.

- **Netstat**
  - Netstat is used to monitor network connections and traffic. You can use netstat -r to display a routing table of the data stored in a router or a network host. This will allow you to see routes to particular network destinations and metrics associated with those routes. Once you have the routing table displayed in front of you, you want to look for any suspicious network connections.
  -   netstat-na is another useful command which will display all active internet connections to the asset. Only established connections are included here.
  -   netstat -p will display all of the process ID&#39;s/Program name for the sockets.
  -   netstat -an grep :\*PORT YOU WANT TO SEARCH FOR\* sort This command will show active internet connections to the server on which ever port you are searching for. This is useful in detecting a single flood by allowing you to recognize many connections coming from a single IP address. An example of this command for port 80 (http) would look like this: netstat -an grep :80 sort
- **NTopPng**

An extremely resourceful tool that allows you to monitor the bandwidth being used on your network. To use Ntopng you must access it via port 3050 within a browser. Once logged in Ntopng offers detailed graphs that display information about a network and the hosts on that network. Once you are in the webpage GUI, you will be presented with information about the &quot;Top Flow Talkers&quot; or the assets using the most bandwidth. You can double click on these &#39;talkers&#39; to view detailed information about the active flows for that asset. Some information that can be found here: The application being used, the OSI Layer 4 protocol, the client name &amp; port, the server, a breakdown between the client and server, total bytes of data and additional information.

If you select &#39;Hosts&#39;, you will view a pie graph with the &quot;top hosts&quot; that have sent and received connection from the machine this program is installed on. Additionally, you can click on the host IP address, and this will take you to a page that displays more detailed information about that host.

You want to look for any kind of abnormal bandwidth usage on your network. If you discover something that seems to be abnormal, investigate the source and destination of the traffic so you can determine if this is the result of a DoS or DDoS attack.




- **OSquery**

You can see logs of all endpoint processes and events in real time. OSquery will put these logs and events into a database which you can query using a SQL-like language. OSquery puts all that metadata within a table so you can easily determine what is happening on your network or on your machine.

During a DoS or DDoS attack, you can use the following command to search for unusual source and destination IP addresses:

This command will display a chart listing the chain and policy of a source and destination IP address. With this information, you can start to analyze IP addresses that look suspicious.

**********************************************************Ransomware********************************************************************

When trying to determine if you have been the target of a ransomware attack, you should begin by looking for a ransom note. When ransomware encrypts a file, it usually takes ownership of the file. To identifiy the source of the attack is to identify the file owner&#39;s domain user account from which the ransomware was launched. You can then look for the computers on the network that are using that account. To find the owner, open the file properties of the file and look for the owner field.

**Types of Ransomware:**

- **CryptoLocker**

CyptoLocker ransomware is the most destructive form of ransomware since it uses strong encryption algorithms. It is often impossible to decrypt (restore) the Crypto ransomware-infected computer and files without paying the ransom.

- **WannaCry**

WannaCry is the most widely known ransomware variant across the globe. The WannaCry ransomware has infected nearly 125,000 organizations in over 150 countries. Some of the alternative names given to the WannaCry ransomware are WCry or WanaCrypt0r.

- **Bad Rabbit**

Bad Rabbit is another strain of ransomware which has infected organizations across Russia and Eastern Europe. It usually spreads through a fake Adobe Flash update on compromised websites.

- **Cerber**

Cerber is another ransomware variant which targets cloud-based Office 365 users. Millions of Office 365 users have fallen prey to an elaborate phishing campaign carried out by the Cerber ransomware.

- **Crysis**

Crysis is a special type of ransomware which encrypts files on fixed drives, removable drives, and network drives. It spreads through malicious email attachments with double-file extension. It uses strong encryption algorithms making it difficult to decrypt within a fair amount of time.

- **CryptoWall**

CryptoWall is an advanced form of CryptoLocker ransomware. It came into existence since early 2014 after the downfall of the original CryptoLocker variant. Today, there are multiple variants of CryptoWall in existence. It includes CryptoDefense, CryptoBit, CryptoWall 2.0, and CryptoWall 3.0.

- ****** GoldenEye**

GoldenEye is similar to the infamous Petya ransomware. It spreads through a massive social engineering campaign that targets human resources departments. When a user downloads a GoldenEye-infected file, it silently launches a macro which encrypts files on the victim&#39;s computer.

- ****** Jigsaw**

Jigsaw is one of the most destructive types of ransomware which encrypts and progressively deletes the encrypted files until a ransom is paid. It starts deleting the files one after the other on an hourly basis until the 72-hour mark- when all the remaining files are deleted.

- ****** Locky**

Locky is another ransomware variant which is designed to lock the victim&#39;s computer and prevent them from using it until a ransom is paid. It usually spread through seemingly benign email message disguised as an invoice.

When a user opens the email attachment, the invoice gets deleted automatically, and the victim is directed to enable macros to read the document. When the victim enables macros, Locky begins encrypting multiple file types using AES encryption.

- ****** Petya**

Unlike some other types of ransomware, Petya encrypts entire computer systems. Petya overwrites the master boot record, rendering the operating system unbootable.

- ****** ZCryptor**

ZCryptor is a self-propagating malware strain that exhibits worm-like behavior, encrypting files and also infecting external drives and flash drives so it can be distributed to other computers.

**Tools &amp; Commands for Ransomware Incident Response:**

- ****** OSquery**

OSquery can be used for malware analysis as well as ransomware analysis. OSquery can detect anomalous behavior on endpoints. When using OSquery you must know what you are looking for when trying to investigate an incident or possible incident.

Many types of Ransomware will use a Command and Control (C&amp;C) server to initially launch and monitor the attack. This C&amp;C server will act as the headquarters in the attack, allowing for the hacker to begin communicating with the victims&#39; computer. The hacker can then start compromising the victims&#39; computer. Once the victim&#39;s computer is compromised, the filesystem is encrypted, and the malware sends the encryption key and host-specific info back to the C&amp;C server. Because of this C&amp;C server communicating with the victim&#39;s machine, OSquery can be used to identify the connection for further analysis and remediation.

By using OSquery, you can view which processes are making which network connections and using what port. To do this, you must type (sudo) osqueryi to open OSquery in the CLI, then you can enter the following command: select processes.name, process\_open\_sockets.remote\_address, process\_open\_sockets.remote\_port from process\_open\_sockets LEFT JOIN processes ON process\_open\_sockets.pid = processes.pid WHERE process\_open\_sockets.remote\_port != 0 AND processes.name != &#39;&#39;; Ensure that you use two single quotes at the end of the command before the semicolon.

This command will result in a table which will allow you to investigate what processes are currently being ran on the machine, what remote IP address they are using, and through what port. You can use this to determine if a process running is malicious or if the remote address is malicious. OSquery extracts this valuable information in a table so that you can investigate anything that may look abnormal. If a process is running on your computer and you&#39;re not sure what it is, perform research on the process to see if it is a known malicious process.

If you see a remote address that you do not know, perform a Whois search on the IP address to gain more information about the IP. Also run a VirusTotal ([www.virustotal.com](http://www.virustotal.com)) scan on the remote address and see if it has any malicious affiliations.

- ****** Netstat**
  - Netstat can be used to identify connections being made to a C&amp;C server. You can use netstat -r to display a routing table of the data stored in a router or a network host. This will allow you to see routes to network destinations and metrics associated with those routes. Once you have the routing table displayed in front of you, you want to look for any suspicious network connections, and perform a Whois search on any suspicious IP addresses. You may also choose to perform a VirusTotal (www.virustotal.com) scan to determine if an IP address has any malicious affiliations.
  -   netstat-na is another useful command which will display all active internet connections to the asset. Only established connections are included here.
  -   netstat -p will display all of the process ID&#39;s/Program name for the sockets.
  -   netstat -an grep :\*PORT YOU WANT TO SEARCH FOR\* sort This command will show active internet connections to the server on which ever port you are searching for. This is useful in detecting a single flood by allowing you to recognize many connections coming from a single IP address. An example of this command for port 80 (http) would look like this: netstat -an grep :80 sort



**Malware**

**Types of Malware:**

- ****** Virus -** A virus is a type of malware that, when executed, self-replicates by modifying other computer programs and inserting their own code. When this replication succeeds, the affected areas are then said to be infected.

Virus writers use social engineering and exploit vulnerabilities to infect systems and spread the virus. The Microsoft Windows and Mac operating systems are the targets of most viruses that often use complex anti-detection strategies to evade antivirus software.

- ****** Worm –** A computer worm is a self-replicating malware program whose primary purpose is to infect other computers by duplicating itself while remaining active on infected systems.

Often, worms use computer networks to spread, relying on vulnerabilities or security failures on the target computer to access it. Worms almost always cause at least some harm to a network, even if only by consuming bandwidth. This is different to viruses which almost always corrupt or modify files on the victim&#39;s computer.

- ****** Trojan –** A trojan is any malware that misleads users of its true intent by pretending to be a legitimate program. Trojans are generally spread with social engineering such as phishing.

For example, a user may be tricked into executing an email attachment disguised to appear genuine (e.g. an Excel spreadsheet). Once the executable file is opened, the trojan is installed.

While the payload of a trojan can be anything, most act as a backdoor giving the attacker unauthorized access to the infected computer. Trojans can give access to personal information such as internet activity, banking login credentials, passwords or personally identifiable information (PII). Ransomware attacks are also carried out using trojans.

- ****** Rootkit -** A rootkit is a collection of malware designed to give unauthorized access to a computer or area of its software and often masks its existence or the existence of other software.  Rootkit installation can be automated, or the attacker can install it with administrator access.

Access can be obtained by a result of a direct attack on the system, such as exploiting vulnerabilities, cracking passwords or phishing.

Rootkit detection is difficult because it can subvert the antivirus program intended to find it. Detection methods include using trusted operating systems, behavioral methods, signature scanning, difference scanning and memory dump analysis. Rootkit removal can be complicated or practically impossible, especially when rootkits reside in the kernel. Firmware rootkits may require hardware replacement or specialized equipment.

- ****** Backdoor -** A backdoor is a covert method of bypassing normal authentication or encryption in a computer, product, embedded device (e.g. router) or other part of a computer.

Backdoors are commonly used to secure remote access to a computer or gain access to encrypted files. From there, it can be used to gain access to, corrupt, delete or transfer sensitive data.

Backdoors can take the form a hidden part of a program (a trojan horse), a separate program or code in firmware and operating systems.

- ****** Keylogger -** Keyloggers, keystroke loggers or system monitoring are a type of malware used to monitor and record each keystroke typed on a specific computer&#39;s keyboard. Keyloggers are also available for smartphones.

Keyloggers store gathered information and send it to the attacker who can then extract sensitive information like login credentials and credit card details.

- ****** Adware -** Adware is a type of grayware (unwanted applications or software that aren&#39;t malware but worsen the performance of your computer) designed to put advertisements on your screen, often in a web browser or popup.

Typically, it distinguishes itself as legitimate or piggybacks on another program to trick you into installing it on your computer.

Adware is one of the most profitable, least harmful forms of malware and is becoming increasingly popular on mobile devices. Adware generates revenue by automatically displaying advertisement to the user of the software.

- ****** Spyware -** Malware that gathers information about a person or organization, sometimes without their knowledge, and sends the information to the attacker without the victim&#39;s consent.

Spyware usually aims to track and sell your internet usage data, capture your credit card or bank account information or steal personally identifiable information (PII).

Some types of spyware can install additional software and change the settings on your device. Spyware is usually simple to remove because it is not as nefarious as other types of malware.

**Tools &amp; Commands for Malware Incident Response:**

Many types of malware rely on a Command and Control (C&amp;C) server to initially launch, monitor, and continue the attack. A C&amp;C server will act as the headquarters in the attack, allowing for the hacker to begin communicating with the victims&#39; computer. The hacker can then start compromising the victims&#39; computer. Once the victim&#39;s computer is compromised, the filesystem is encrypted, and the malware sends the encryption key and host-specific info back to the C&amp;C server. Because of this C&amp;C server communicating with the victim&#39;s machine, different tools and commands within DIRT can be used to determine if your assets are infected with malware.



- ****** Osquery**

By using OSquery, you can view which processes are making which network connections and using what port. To do this, you must type (sudo) osqueryi to open OSquery in the CLI, then you can enter the following command: select processes.name, process\_open\_sockets.remote\_address, process\_open\_sockets.remote\_port from process\_open\_sockets LEFT JOIN processes ON process\_open\_sockets.pid = processes.pid WHERE process\_open\_sockets.remote\_port != 0 AND processes.name != &#39;&#39;; Ensure that you use two single quotes at the end of the command before the semicolon.

This command will result in a table which will allow you to investigate what processes are currently being ran on the machine, what remote IP address they are using, and through what port. You can use this to determine if a process running is malicious or if the remote address is malicious. OSquery extracts this valuable information in a table so that you can investigate anything that may look abnormal. If a process is running on your computer and you&#39;re not sure what it is, perform research on the process to see if it is a known malicious process.





- ****** Netstat**

Netstat can be used to identify connections being made to a C&amp;C server. You can use netstat -r to display a routing table of the data stored in a router or a network host. This will allow you to see routes to network destinations and metrics associated with those routes. Once you have the routing table displayed in front of you, you want to look for any suspicious network connections, and perform a Whois search on any suspicious IP addresses. You may also choose to perform a VirusTotal (www.virustotal.com) scan to determine if an IP address has any malicious affiliations.

netstat-na is another useful command which will display all active internet connections to the asset. Only established connections are included here.

netstat -p will display all of the process ID&#39;s/Program name for the sockets.

netstat -an grep :\*PORT YOU WANT TO SEARCH FOR\* sort This command will show active internet connections to the server on which ever port you are searching for. This is useful in detecting a single flood by allowing you to recognize many connections coming from a single IP address. An example of this command for port 80 (http) would look like this: netstat -an grep :80 sort

- ****** Nmap**

Nmap uses raw IP packets in novel ways to determine what hosts are running, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. The output from Nmap is a list of scanned targets, with supplemental information on each depending on the options used. Key among that information is the &quot;interesting ports table&quot;.  That table lists the port number and protocol, service name, and state. The state is either open, filtered, closed, or unfiltered.

Nmap -sP 10.0.0.0/24 - Ping scanning, can be used to see what machines are online and respond to a ping over a network

Nmap -p 1-65535 -sV -sS -T4 &quot;target&quot; – sV is used for version detection when scanning, - sS is the standard stealth scan that is usually the most popular scan to run. You can scan a range of port by separating the ports with a dash or you can scan multiple ports by separating the ports with commas.

-sV is used for version detection when scanning

-sS is the standard SYN stealth scan that is usually the most popular scan to run due to it&#39;s speed and ability to work against all TCP stacks

-sT is a scan used when the sS SYN scan will not work in cases of scanning IPv6 targets typically.

-sU is used to scan UDP ports

-sA TCP ACK Scan is used to map out a network&#39;s firewall rules typically, cannot see open or closed ports

-sW (target) -sW is a windowed scan that is like a TCP ACK scan, but it can see open and closed ports
