**Tools**

- **SURICATA** - A high performance Network Intrusion Detection System (NIDS), Intrusion Prevention System (IPS), and Network Security Monitoring engine. Suricata inspects the network traffic using a powerful and extensive rules and signature language and has powerful Lua scripting support for detection of complex threats. Suricata implements a complete signature language to match on known threats, policy violations and malicious behavior. Suricata will also detect many anomalies in the traffic it inspects. Suricata can log HTTP requests, log and store TLS certificates, extract files from flows and store them to disk. The full PCAP capture support allows easy analysis. All this makes Suricata a powerful engine for your Network Security Monitoring (NSM).

- **NMAP** - Nmap (Network Mapper) is an open source tool for network exploration and security auditing. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. The output from Nmap is a list of scanned targets, with supplemental information on each depending on the options used. Key among that information is the &quot;interesting ports table&quot;.  That table lists the port number and protocol, service name, and state. The state is either open, filtered, closed, or unfiltered. The port table may also include software version details when version detection has been requested. When an IP protocol scan is requested (-sO), Nmap provides information on supported IP protocols rather than listening ports. In addition to the interesting ports table, Nmap can provide further information on targets, including reverse DNS names, operating system guesses, device types, and MAC addresses.
- **NMAP - Useful Commands:**
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
- **NSLOOKUP** - The NsLookup tool allows you to query DNS servers for resource records. NsLookup queries the specified DNS server and retrieves the requested records that are associated with the domain name you provided. NsLookup has two modes: interactive and non-interactive. Interactive mode allows the user to query name servers for information about various hosts and domains or to print a list of hosts in a domain. Non-interactive mode is used to print just the name and requested information for a host or domain.
- **NSLOOKUP ** - Useful Commands:**
  - **To use NsLookup enter the following:** nslookup [domain]
  - **A** : the IPv4 address of the domain.
  - **AAAA** : the domain&#39;s IPv6 address.
  - **CNAME** : the canonical name — allowing one domain name to map on to another. This allows more than one website to refer to a single web server.
  - **MX**** :** the server that handles email for the domain.
  - **NS**** :** one or more authoritative name server records for the domain.
  - **TXT**** :** a record containing information for use outside the DNS server.

- **WHOIS** - Whois is a service that provides basic information about a registered domain, such as domain owner contact information, IP address block, domain availability status and the company with which the domain is registered. Whois is a query and response protocol that stores and delivers information related to the registered domain in a human-readable format.

From a Whois search you can find the following information about an IP address or domain:

-
  - IP location
  - ANS information
  - Network range/CIDR information
  - Organization
  - Date registered
  - Physical location (State, city, address)

- **OSCAP** - Open Security Content Automation Protocol (SCAP) toolkit based on OpenSCAP library. It provides various functions for different SCAP specifications(modules). OpenSCAP tool claims to provide capabilities of Authenticated Configuration Scanner and Authenticated Vulnerability Scanner as defined by The National Institute of Standards and Technology.

- **SCAP-WORKBENCH** - A graphical utility tool that offers an easy way to perform common OSCAP (Open Security Content Automation Protocol) tasks. The tool allows users to perform configuration and vulnerability scans on a single local or remote system; In addition, the tool can perform remediation of the system in accordance with given XCCDF or SDS files. SCAP-Workbench can also generate reports containing the results of the system scan.

Program shows commands to run in cli to limit access or to log activity for users with specific commands that have authority. Can be used to see if a specific user is doing things that shouldn&#39;t be through tracking or can be used to test and see if certain commands are enabled and if they should be or not for security sake.

- **LASTPASS** - LastPass is a password manager that stores encrypted passwords online. A user&#39;s content in LastPass, including passwords and secure notes, is protected by one master password. The content is synchronized to any device the user uses the LastPass software or app extensions on. Information is encrypted with AES-256 encryption with PBKDF2 SHA-256, salted hashes, and the ability to increase password iterations value. Encryption and decryption take place at the device level.

- **NETSTAT** Netstat is a very powerful tool that can be used to print network connections, routing tables, interface statistics, masquerade connections, and multicast memberships. It is a utility that displays network connections for Transmission Control Protocol, routing tables, and several network interface and network protocol statistics. It is used for finding problems in the network and to determine the amount of traffic on the network as a performance measurement. Netstat can be used to determine incidents such as DoS/DDoS and C&amp;C communications.
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

- **OSQUERY** - OSquery is an operating system instrumentation framework for Windows, macOS, Linux, and FreeBSD. The tools make low-level operating system analytics and monitoring both performant and intuitive. The high-performance and low-footprint distributed host monitoring daemon, OSqueryd, allows you to schedule queries to be executed across your entire infrastructure. The daemon takes care of aggregating the query results over time and generates logs which indicate state changes in your infrastructure. You can use this to maintain insight into the security, performance, configuration, and state of your entire infrastructure. OSqueryd&#39;s logging can integrate into your internal log aggregation pipeline.

- **IPTRAF** - IPTraf is a network monitoring utility for IP networks. It intercepts packets on the network and gives out various pieces of information about the current IP traffic over it. IPTraf can be used to monitor the load on an IP network, the most used types of network services, the proceedings of TCP connections, and others. IPTraf is software-only and utilizes the built-in raw packet capture interface of the Linux kernel, allowing it to be used with a wide range of Ethernet cards, supported FDDI adapters, supported ISDN adapters, and any asynchronous SLIP/PPP interface. No special hardware is required.
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

- **NTOPNG** - A passive network monitoring tool focused on flows and statistics that can be obtained from the traffic captured by the server. NTOPNG centers and has been developed around some basic concepts that include network interfaces and hosts. It can generate alerts to report the occurrence of events and user-configurable thresholds.
- **How to use NTOPNG:**

To use Ntopng you must access it via port 3050 within a browser. Upon coming to the login page, you must have an account made to login with. Once logged in Ntopng offers detailed graphs that display information about a network and the hosts on that network. Once you are in the webpage GUI, you will be presented with information about the &quot;Top Flow Talkers&quot; or the assets using the most bandwidth. You can double click on these &#39;talkers&#39; to view detailed information about the active flows for that asset. Some information that can be found here: The application being used, the OSI Layer 4 protocol, the client name &amp; port, the server, a breakdown between the client and server, total bytes of data and additional information.

If you select &#39;Hosts&#39;, you will view a pie graph with the &quot;top hosts&quot; that have sent and received connection from the machine this program is installed on. Additionally, you can click on the host IP address, and this will take you to a page that displays more detailed information about that host. This includes the OS of the device connected, the sent and received traffic broken down, the MAC address of the device, etc. You can also view the ports that this device connects via, the protocols that the device uses to connect, the packets sent back and forth, etc.

- **OPENVAS** - OpenVAS is a full-featured vulnerability scanner. Its capabilities include unauthenticated testing, authenticated testing, various high level and low-level Internet and industrial protocols, performance tuning for large-scale scans and a powerful internal programming language to implement any type of vulnerability test. The scanner is accompanied by a vulnerability tests feed with a long history and daily updates. This Greenbone Community Feed includes more than 50,000 vulnerability tests.

OpenVAS offers a multitude of services such as:

-
  -
    - Scanning a machine to detect potential vulnerabilities to see how an intruder may have gained access to the system.
    - In incident response, it is important to investigate the vulnerabilities to determine where an intruder may have gotten in from. This information can be used to patch vulnerabilities on the system to prevent future incidents.
    - OpenVAS can be used to scan for vulnerabilities that may be present so they can be remediated before an incident occurs.

- **WIRESHARK/TSHARK** - Wireshark is the world&#39;s most foremost and widely-used network packet analyzer. It is a free and open-source packet analyzer. A network packet analyzer presents captured packet data in as much detail as possible. Wireshark can capture traffic from many different network media types, including Ethernet, Wireless LAN, Bluetooth, USB, and more.

Tshark allows for a live capture of network traffic in the CLI. The capture can be used for incident response to determine where connections are being established from and where data is being sent too.

- **How to use Tshark:**

In the CLI you can just run sudo tshark to begin capturing live traffic on your machine. To stop this capture you must press CTRL + C

You can filter by protocol by entering tshark [name of protocol] For a full list of protocols enter tshark -G protocols

- **NODEJS** - is an open-source, cross-platform, JavaScript runtime environment that executes JavaScript code outside of a browser. Node.js lets developers use JavaScript to write command line tools and for server-side scripting—running scripts server-side to produce dynamic web page content before the page is sent to the user&#39;s web browser. Consequently, Node.js represents a &quot;JavaScript everywhere&quot; paradigm, unifying web-application development around a single programming language, rather than different languages for server- and client-side scripts.

**Malware**

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
