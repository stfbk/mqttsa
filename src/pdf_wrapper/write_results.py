import src.pdf_wrapper as pdfw

'''
This functions are used to dynamically create the report based
on the results of the attacks performed by MQTTSA.
'''

outdated_broker = "No"

# Authentication mechanism section
def authentication_report(pdfw, no_authentication, broker_info, credentials_sniffed, credentials_bruteforced, interface, host, port):
    pdfw.add_paragraph("Authentication")

    # No authentication mechanism detected -> write mitigations
    if (no_authentication):
        pdfw.add_to_existing_paragraph("<b>[!] MQTTSA did not detect any authentication mechanism<b>")

        # Suggest X.509 certificates 
        pdfw.add_to_existing_paragraph('The tool was able to connect to the broker without specifying any kind of credential information. This may cause remote attackers to successfully connect to the broker. It is strongly advised to support authentication via X.509 client certificates.')
        
        if (credentials_sniffed==True):
            pdfw.add_to_existing_paragraph('The tool was able to intercept and use valid client credentials: refer to the Sniffing section for additional details.')
        if (credentials_bruteforced==True):
            pdfw.add_to_existing_paragraph('The tool was able to bruteforce and use valid client credentials: refer to the Brute force section for additional details.')
            
        # Mitigations sections
        pdfw.add_sub_paragraph("Suggested mitigations")
        
        if (broker_info != None):
            if ("mosquitto" in broker_info):
                pdfw.add_to_existing_paragraph('Please modify Mosquitto\'s configuration ("/etc/mosquitto/mosquitto.conf" by default) according to the <a href="https://mosquitto.org/man/mosquitto-conf-5.html">official documentation</a>. For further authentication or authorization mechanisms refer to <a href="https://github.com/iegomez/mosquitto-go-auth">mosquitto-go-auth</a>. An excerpt of "mosquitto.conf" is provided below:<br><font size=7> <p>\
                listener '+str(port)+' '+str(host)+'          #Binds Mosquitto to a specific IP/Port<br>\
                cafile   &lt; path to the certificate authority certificate &gt;     #Tipically /etc/mosquitto/certs/ca.crt<br>\
                certfile &lt; path to Mosquitto X.509 certificate &gt;               #Tipically /etc/mosquitto/certs/hostname.crt<br>\
                keyfile  &lt; path to Mosquitto private key &gt;                       #Tipically /etc/mosquitto/certs/hostname.key<br>\
                crlfile  &lt; path to Mosquitto certificate revocation list &gt;   #Tipically /etc/mosquitto/certs/ca.crl<br>\
                require_certificate true                    #The client must present a certificate<br>\
                use_identity_as_username true       #- And the certificate Common Name (CN) is used as username<br>\
                use_username_as_clientid true       #- And the username is used as the unique client ID<br>\
                </p></font>')
                
                pdfw.add_to_existing_paragraph('By using "require_certificate", an attacker need to have access to a valid certificate (and the corresponding private key), rather than the less secure username and password (that can be possibly bruteforced). In addition, by indicating both "use_identity_as_username" and "use_username_as_clientid", an attacker that steals and use the client certificate (and the key) cannot be connected together with the client (as the client ID is unique); hence, the client will be disconnected and possibly detect the attack. Upon detection (or if the client is not authorised anymore), the certificate can be revoked via the certificate revocation list.')
            elif ("verne" in broker_info):
                pdfw.add_to_existing_paragraph('Please modify VerneMQ\'s configuration ("/etc/vernemq/vernemq.conf" by default) according to the <a href="https://docs.vernemq.com/configuration/introduction">official documentation</a>. For supported authentication or authorization mechanisms refer to <a href="https://docs.vernemq.com/configuration/file-auth">file-based</a> authentication and authorization, or <a href="https://docs.vernemq.com/configuration/db-auth">database-oriented</a> option. An excerpt of the important options to set or verify in "vernemq.conf" is provided below:<br><font size=7> <p>\
                allow_anonymous = off                             #Prevents connections from unauthenticated clients<br>\
                allow_multiple_sessions = off                    #Would allow multiple clients with the same client ID<br>\
                listener.ssl.default = '+str(host)+':'+str(port)+' #Enforces the use of TLS (via the ssl listener)<br>\
                listener.ssl.cafile = &lt; path to the certificate authority certificate &gt;     #Tipically /etc/vernemq/ca.crt<br>\
                listener.ssl.certfile = &lt; path to VerneMQ X.509 certificate &gt;                #Tipically /etc/vernemq/server.crt<br>\
                listener.ssl.keyfile = &lt; path to VerneMQ private key &gt;                        #Tipically /etc/vernemq/server.key<br>\
                listener.ssl.crlfile = &lt; path to VerneMQ certificate revocation list &gt;   #To be set e.g., as /etc/vernemq/ca.crl<br>\
                listener.ssl.require_certificate = on                    #The client must present a certificate<br>\
                listener.ssl.use_identity_as_username = on       #- And the certificate Common Name (CN) is used as username<br>\
                </p></font>')
                pdfw.add_to_existing_paragraph('By using "require_certificate", an attacker need to have access to a valid certificate (and the corresponding private key), rather than the less secure username and password (that can be possibly bruteforced). The "crlfile" is used in case the certificate is compromised')
            elif ("emqx" in broker_info):
                pdfw.add_to_existing_paragraph('Please modify EMQ X\'s configuration ("/etc/emqx/emqx.conf" by default) according to the <a href="https://docs.emqx.io/en/broker/v4.3/getting-started/config.html">official documentation</a>. For supported authentication or authorization mechanisms refer to the <a href="https://docs.emqx.io/en/broker/v4.3/advanced/auth.html">authentication</a> section. An excerpt of the important options to set or verify in "emqx.conf" is provided below:<br><font size=7> <p>\
                allow_anonymous = false                               #Prevents connections from unauthenticated clients<br>\
                listener.ssl.external = '+str(host)+':'+str(port)+'   #Enforces the use of TLS (via the ssl listener)<br>\
                listener.ssl.external.cacertfile = &lt; path to the certificate authority certificate &gt;     #Tipically /etc/emqx/certs/cacert.pem<br>\
                listener.ssl.external.certfile &lt; path to VerneMQ X.509 certificate &gt;                   #Tipically /etc/emqx/certs/cert.pem<br>\
                listener.ssl.external.keyfile  &lt; path to VerneMQ private key &gt;                           #Tipically /etc/emqx/certs/key.pem<br>\
                listener.ssl.crlfile  &lt; path to VerneMQ certificate revocation list &gt;            #To be set e.g., as /etc/vernemq/ca.crl<br>\
                listener.ssl.external.fail_if_no_peer_cert = true                    #The client must present a certificate<br>\
                listener.ssl.external.verify = verify_peer                             #- And the certificate chain is valid <br>\
                listener.ssl.external.peer_cert_as_username = cn          #- Use the CN, DN or CRT field from the client certificate as a username<br>\
                zone.external.use_username_as_clientid = true             #- And the username is used as the unique client ID<br>\
                </p></font>')
                pdfw.add_to_existing_paragraph('By using "fail_if_no_peer_cert", an attacker need to have access to a valid certificate (and the corresponding private key), rather than the less secure username and password (that can be possibly bruteforced). In addition, by indicating both "peer_cert_as_username" and "use_username_as_clientid", an attacker that steals and use the client certificate (and the key) cannot be connected together with the client (as the client ID is unique); hence, the client will be disconnected and possibly detect the attack. Upon detection (or if the client is not authorised anymore), the certificate can be revoked via the certificate revocation list.')
        else:
            pdfw.add_to_existing_paragraph('Refer here for additional informations:')
            pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-x509-client-certificate-authentication">MQTT Security Fundamentals: X509 Client Certificate Authentication</a>')
            pdfw.add_to_existing_paragraph('<a href="https://thingsboard.io/docs/user-guide/certificates/">ThingsBoard: X.509 Certificate Based Authentication</a>')
    else:
        # Authentication mechanism detected
        pdfw.add_to_existing_paragraph("MQTTSA detected an authentication mechanism.")
        if (interface == None):
            pdfw.add_to_existing_paragraph('Try to listen on a network interface to assess the possibility to sniff credentials.')
        if (credentials_sniffed==True):
            pdfw.add_to_existing_paragraph('<b>[!] The tool was able to intercept and use valid client credentials: refer to the Sniffing section for additional details.<b>')
        if (credentials_bruteforced==True):
            pdfw.add_to_existing_paragraph('<b>[!] The tool was able to bruteforce and use valid client credentials: refer to the Brute force section for additional details.<b>')
            
# Information disclosure section
def information_disclosure_report(pdfw, topics_readable, sys_topics_readable, listening_time, broker_info, no_authentication):
    pdfw.add_paragraph("Information disclosure")
    
    # Description of the test performed by MQTTSA
    if (no_authentication):
        pdfw.add_to_existing_paragraph("MQTTSA waited for "+str(listening_time)+" seconds after having subscribed to the '#' and '$SYS/#' topics. By default, clients who subscribe to the '#' topic can read to all the messages exchanged between devices and the ones subscribed to '$SYS/#' can read all the messages which includes statistics of the broker. Remote attackers could obtain specific information about the version of the broker to carry on more specific attacks or read messages exchanged by clients. <br>")

    # MQTTSA found readable topics -> suggest mitigations
    if (len(topics_readable)+len(sys_topics_readable)>0):
        pdfw.add_to_existing_paragraph("<b>[!] MQTTSA successfully intercepted all the messages belonging to " +str(len(topics_readable)+len(sys_topics_readable)) + " topics, "+str(len(topics_readable))+" of them non $SYS. Intercepted data was stored in the 'messages' folder.</b>")
        if (len(topics_readable)>0):
            pdfw.add_to_existing_paragraph("The non-SYS topics are: "+str(list(topics_readable)))
        if (len(sys_topics_readable)>0):
            pdfw.add_to_existing_paragraph("The SYS topics are: "+str(list(sys_topics_readable)))

        # Mitigations    
        pdfw.add_sub_paragraph("Suggested mitigations")
        pdfw.add_to_existing_paragraph('It is strongly recommended to enforce an authorization mechanism in order to grant the access to confidential resources only to the specified users or devices. There are two possible approaches: Access Control List (ACL) and Role-based Access Control (RBAC).')
        
        if (broker_info != None):
            if ("mosquitto" in broker_info):
                pdfw.add_to_existing_paragraph('If restricting access via ACLs, please follow those <a href="http://www.steves-internet-guide.com/topic-restriction-mosquitto-configuration/">guidelines</a> and modify Mosquitto\'s configuration according to the <a href="https://mosquitto.org/man/mosquitto-conf-5.html">official documentation</a>. For instance, integrate the <i>acl_file</i> parameter (<i>acl_file /mosquitto/config/acls</i>) and restict a client to interact only on topics with his clientname as prefix (ACL <i>pattern readwrite topic/%c/#</i>).')
                pdfw.add_to_existing_paragraph('In addition, consider the adoption of TLS 1.3 by setting <i>tls_version tlsv1.3</i> in "mosquitto.conf" - the strongest cipher is used by default, but the client may require a weak one: use <i>ciphers_tls1.3</i> in "mosquitto.conf" to indicate a <a href="https://wiki.mozilla.org/Security/Server_Side_TLS">secure cipher list</a> (if not working, use TLS 1.2 and the <i>ciphers</i> parameter).')
            elif ("verne" in broker_info):
                pdfw.add_to_existing_paragraph('If restricting access via ACLs, please modify VerneMQ\'s configuration according to the <a href="https://docs.vernemq.com/configuration/file-auth">official documentation</a>. For instance, integrate in <i>vmq.acl</i> a policy per client that consider its <a href="https://docs.vernemq.com/configuration/file-auth#simple-acl-example">username</a>.')
                pdfw.add_to_existing_paragraph('In addition, consider the adoption of TLS 1.2 by setting <i>listener.ssl.tls_version = tlsv1.2</i> in "vernemq.conf" - the strongest cipher is used by default, but the client may require a weak one: use <i>listener.ssl.ciphers</i> in "vernemq.conf" to indicate a <a href="https://wiki.mozilla.org/Security/Server_Side_TLS">secure cipher list</a>.')
            elif ("emqx" in broker_info):
                pdfw.add_to_existing_paragraph('If restricting access via ACLs, please modify EMQ X\'s configuration according to the <a href="https://docs.emqx.io/en/broker/v4.3/advanced/acl.html#acl-plugins">official documentation</a>. For instance, add a username-based rule, remove <i>{allow, all}.</i> and set <i>acl_nomatch = deny</i> in "emqx.conf" to effectively use ACLs; the documentation provide additional setting such as the behaviour (by default ignore but not disconnect the client).')
                pdfw.add_to_existing_paragraph('In addition, consider the adoption of TLS 1.2 by setting <i>listener.wss.external.tls_versions = tlsv1.2</i> in "emqx.conf" - the strongest cipher is used by default, but the client may require a weak one: use <i>listener.wss.external.ciphers</i> in "emqx.conf" to indicate a <a href="https://wiki.mozilla.org/Security/Server_Side_TLS">secure cipher list</a>.')
        else: 
            # additional information section
            pdfw.add_to_existing_paragraph('Additional information here:')
            pdfw.add_to_existing_paragraph('<a href="https://en.wikipedia.org/wiki/Access_control_list">Wikipedia: Access Control List</a>')
            pdfw.add_to_existing_paragraph('<a href="https://en.wikipedia.org/wiki/Role-based_access_control">Wikipedia: Role-based Access Control</a>')
            pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-authorization/">MQTT Security Fundamentals: Authorization</a>')
            pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-oauth-2-0-mqtt">MQTT Security Fundamentals: OAuth 2.0 & MQTT</a>')
            pdfw.add_to_existing_paragraph('<a href="http://www.steves-internet-guide.com/topic-restriction-mosquitto-configuration/">Configuring and Testing Mosquitto MQTT Topic Restrictions</a>')

        # MQTTSA did not found readable topics -> try to increase listening_time
    else:
        pdfw.add_to_existing_paragraph("MQTTSA was not able to intercept messages exchanged by clients.<br>As no messages might have been published during the listening time, try to perform the assessment again increasing the 'listening_time' parameter.")

# Tampering data section
def tampering_data_report(pdfw, topics_writable, sys_topics_writable, topics_readable, sys_topics_readable, text_message):
    pdfw.add_paragraph("Tampering data")

    # MQTTSA found readable topics -> check if there are writable topics
    if (len(topics_readable)+len(sys_topics_readable)>0):
        pdfw.add_to_existing_paragraph("After having successfully intercepted some messages, MQTTSA automatically created a new message (having as a payload the string '"+text_message+"') and attempted sending it to every topic it was able to intercept. Remote attackers could exploit it to write in specific topics pretending to be a client (by his ID); e.g., send tampered measures to a sensor. <br>")

        # MQTTSA found writable topics -> Suggestions (as in the information disclosure section)
        if (len(sys_topics_writable)+len(topics_writable)>0):
            pdfw.add_to_existing_paragraph("<b>[!] MQTTSA was able to write in "+str(len(topics_writable)+len(sys_topics_writable))+" topics, with "+str(len(topics_writable))+" of them being non-$SYS.</b>") 
            pdfw.add_to_existing_paragraph("The topics were: "+str(list(topics_writable))+" "+str(list(sys_topics_writable)))
            pdfw.add_sub_paragraph("<br>Suggested mitigations")
            pdfw.add_to_existing_paragraph('The implementation of an authorization mechanism can mitigate this risk. Check the "Mitigations" paragraph in the section "Information disclosure".')

        # MQTTSA did not found writable topics
        else:
            pdfw.add_to_existing_paragraph("<b>MQTTSA was not able to write in any topic.</b>")

    # MQTTSA did not found readable topics -> try to repeat the assessment increasing the listening_time parameter
    else:
        pdfw.add_to_existing_paragraph("Since MQTTSA was not able to intercept any topic, this vulnerability was not tested.<br>Try to perform the assessment again, increasing the 'listening_time' parameter.</b>")
    
# Broker fingerprinting section
def fingerprinting_report(pdfw, broker_info):
    global outdated_broker
    pdfw.add_paragraph("Broker Fingerprinting")
    
    if(broker_info != None):
        brokers = {}
        with open("src/brokers_last_version.txt") as brokers_last_version:
            for line in brokers_last_version:
                name, version = line.partition("=")[::2]
                brokers[name.strip()] = version.strip()
            
        # Found informations regarding broker type and version -> check CVEs
        pdfw.add_to_existing_paragraph("MQTTSA detected the following MQTT broker: "+str(broker_info)+". ")
        if ("mosquitto" in broker_info):
            if (not brokers["mosquitto"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]Mosquitto version is not updated</b>: please refer to the last <a href="https://mosquitto.org/ChangeLog.txt">Change log</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                # The version detected is the last one
                pdfw.add_to_existing_paragraph('Mosquitto version is up-to-date.')
        elif ("hivemq" in broker_info):
            if (not brokers ["hivemq"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]HiveMQ version is not updated</b>: please refer to the last <a href="https://www.hivemq.com/changelog/">Change log</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                pdfw.add_to_existing_paragraph('HiveMQ version is up-to-date.')
        elif ("vernemq" in broker_info):
            if (not brokers ["vernemq"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]VerneMQ version is not updated</b>: please refer to the last <a href="https://github.com/vernemq/vernemq/blob/master/changelog.md">Change log</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                pdfw.add_to_existing_paragraph('VerneMQ version is up-to-date.')
        elif ("emqx" in broker_info):
            if (not brokers ["emqx"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]EMQ X version is not updated</b>: please refer to the last <a href="http://emqtt.io/changelogs">Change log</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                pdfw.add_to_existing_paragraph('EMQ X version is up-to-date.')
        elif ("adafruit" in broker_info):
            if (not brokers ["adafruit"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]Adafruit IO version is not updated</b>: please refer to the last <a href="https://io.adafruit.com/blog/">Change log</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                pdfw.add_to_existing_paragraph('Adafruit IO is up-to-date.')
        elif ("machine_head" in broker_info):
            if (not brokers ["machine_head"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]Machine Head version is not updated</b>: please refer to the last <a href="https://github.com/clojurewerkz/machine_head/blob/master/ChangeLog.md">Change log</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                pdfw.add_to_existing_paragraph('Machine Head is up-to-date.')
        elif ("moquette" in broker_info):
            if (not brokers ["moquette"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]Moquette version is not updated</b>: please refer to the last <a href="https://github.com/andsel/moquette/blob/master/ChangeLog.txt">Change log</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                pdfw.add_to_existing_paragraph('Moquette is up-to-date.')
        elif ("solace" in broker_info):
            if (not brokers ["solace"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]Solace PubSub+ version is not updated</b>: please refer to the last <a href="https://products.solace.com/download/PUBSUB_STAND_RN">Release notes</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                pdfw.add_to_existing_paragraph('Solace PubSub+ is up-to-date.')
        elif ("thingstream" in broker_info):
            if (not brokers ["thingstream"] in broker_info):
                pdfw.add_to_existing_paragraph('<b>[!]Thingstream version is not updated</b>: please refer to the last <a href="https://sites.google.com/thingstream.io/docs/release-notes">Release notes</a> for bugs and security issues.')
                outdated_broker = "Yes"
            else:
                pdfw.add_to_existing_paragraph('Thingstream is up-to-date.')
        else:
            outdated_broker = "/"
            pdfw.add_to_existing_paragraph('MQTTSA was not able to detect if the broker is up-to-date. Please verify manually.')
    else:
        pdfw.add_to_existing_paragraph('MQTTSA was not able to identify the broker.')

# Sniffing data section
def sniffing_report(pdfw, interface, cred_string, listening_time, broker_info):
    pdfw.add_paragraph("Sniffing")

    # Description
    pdfw.add_to_existing_paragraph("MQTTSA used the adapter "+ interface +" to sniff for "+str(listening_time)+" seconds and try to intercept credential information, such as <i>client-id, usernames</i> and <i>passwords</i>. <br> ")

    # MQTTSA found credential information -> mitigations
    if(not cred_string):
        pdfw.add_to_existing_paragraph("MQTTSA was not able to intercept any credential information.") 
    else:
        pdfw.add_to_existing_paragraph("<b>[!] MQTTSA was able to intercept the following credentials.<b>")
        
        for s in cred_string:
            pdfw.add_to_existing_paragraph(s+"<br>")
        
        # Mitigations
        pdfw.add_sub_paragraph("<br>Suggested mitigations")
        pdfw.add_to_existing_paragraph('We strongly suggest to enforce TLS in MQTT (secure-MQTT). TLS provides a secure communication channel between clients and server: assuming the correct configuration of TLS (secure version and cipher suites), the content of the communication cannot be read or altered by third parties.')
           
        if (broker_info != None):
            if ("mosquitto" in broker_info):
                pdfw.add_to_existing_paragraph('In Mosquitto it is possible to set the <i>tls_version</i> parameter (e.g. to tlsv1.2). Refer to the <a href="https://mosquitto.org/man/mosquitto-conf-5.html">official documentation</a> for details')

        pdfw.add_to_existing_paragraph('<br>Warning: using MQTT over TLS could lead to a communication overhead and an increase in CPU usage, especially during the connection handshake. In devices with constrained resources, supporting TLS can have a severe impact. In these cases there are other (but less secure) solutions that could be used to secure the communication, such as encrypting only specific messages (for instance CONNECT and PUBLISH).')
        pdfw.add_to_existing_paragraph('<br>Additional information here:')
        pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-tls-ssl">MQTT security fundamentals: TLS / SSL</a>')
        pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/how-does-tls-affect-mqtt-performance/">MQTT security fundamentals: how does TLS affect MQTT performance?</a>')
        pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-payload-encryption">MQTT Security Fundamentals: MQTT Payload Encryption</a>')
        pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-mqtt-message-data-integrity">MQTT Security Fundamentals: MQTT Message Data Integrity</a>')
        pdfw.add_to_existing_paragraph('<a href="https://dzone.com/articles/secure-communication-with-tls-and-the-mosquitto-broker">DZone: Secure Communication With TLS and the Mosquitto Broker</a>')

# Brute force section
def brute_force_report(pdfw, username, wordlist, password, no_pass):
    pdfw.add_paragraph("Brute force")

    # No password required to login
    if (no_pass):
        pdfw.add_to_existing_paragraph("<b>[!] The brute force test was not needed. Authentication mechanism in use is enforced through only username.</b>")
    # Password required to login
    else:
        pdfw.add_to_existing_paragraph("<b>[!] The brute force test was succesfull.</b>")
        # No password found
        if (password == None):
            pdfw.add_to_existing_paragraph("The brute force test was not able to determine a correct password to authenticate. Try to provide another wordlist.")
            pdfw.add_to_existing_paragraph("Username provided: "+ username)
            pdfw.add_to_existing_paragraph("Wordlist path provided: "+ wordlist)
        
        # Password found
        else:
            pdfw.add_to_existing_paragraph("The brute force test was able to find a password to authenticate.")
            pdfw.add_to_existing_paragraph("Username provided: "+ username)
            pdfw.add_to_existing_paragraph("Wordlist path provided: "+ wordlist)
            pdfw.add_to_existing_paragraph("Password found: "+ password)

        # Mitigations
        pdfw.add_sub_paragraph("<br>Suggested mitigations")
        pdfw.add_to_existing_paragraph('It is strongly recommended to implement a secure authentication mechanism. We suggest to implement authentication through X.509 certificates, however, a username/password enforcement can work as well, if a strong password is used.')
        pdfw.add_to_existing_paragraph('Additional information here:')
        pdfw.add_to_existing_paragraph('<br><a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-authentication-username-password">MQTT Security Fundamentals: Authentication with Username and Password</a>')
        pdfw.add_to_existing_paragraph('<a href="https://en.wikipedia.org/wiki/Password_strength">Wikipedia: Password Strenght</a>')
        pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-x509-client-certificate-authentication">MQTT Security Fundamentals: X509 Client Certificate Authentication</a>')
        pdfw.add_to_existing_paragraph('<a href="https://thingsboard.io/docs/user-guide/certificates/">ThingsBoard: X.509 Certificate Based Authentication</a>')

# Denial of Service section
def dos_report(pdfw, dos_flooding_connections, dos_flooding_size, connection_difference, percentage_increment, dos_slow_connections, slow_connection_difference, max_queue, tested_max_queue, max_payload, tested_max_payload, broker_info):
    pdfw.add_paragraph("Denial of service")
    
    # Report if flooding-based DoS has been performed
    if(dos_flooding_connections != None):
        pdfw.add_to_existing_paragraph("MQTTSA tried to limit the availability of the service by issuing clients connection and incrementing the processing time: it attempted connecting with "+str(dos_flooding_connections)+" clients, each publishing a "+ str(dos_flooding_size) +"MB QoS 0 message.") 
    
        pdfw.add_to_existing_paragraph("<b>[!]"+((str(connection_difference)+" clients were not able") if (connection_difference > 0) else ("All clients were able")) + " to connect; "+ str(int(percentage_increment)) +"% is the overhead on publishing time caused by the heavy test messages.<b>")
    
    # Report if slow DoS has been performed
    if(dos_slow_connections != None):
        pdfw.add_to_existing_paragraph("MQTTSA tried to saturate the number of connections on the broker or the remote endpoint by connecting "+ str(dos_slow_connections)+ " clients.")
       
        pdfw.add_to_existing_paragraph(("<b>[!]"+(str(slow_connection_difference)+" clients were not able") if (slow_connection_difference > 0) else ("All clients were able")) + " to connect.<b>")
        
            
    pdfw.add_to_existing_paragraph("<br>The tool is not currently able to determine if an existing client was disconnected: the user should check the other clients or the logfile of the broker for any reconnection attempts. In case the test did not result in disconnections or delays, the test can be performed again increasing the number of flooding-based and slow DoS connections.")
        
    # Mitigations 
    pdfw.add_sub_paragraph("<br>Suggested mitigations")
    pdfw.add_to_existing_paragraph('In case of MQTT environments with limited bandwidth capacity, it is recommended to prevent Denial of Service attacks by: implementing a firewall with appropriate rules, use a load balancer, limit the number of clients and packet dimension. Bear in mind that, if limiting the number of clients without supporting any authentication mechanism (and restricting the use of credentials to a single client) enables a slow DoS attack.')
    
    if (broker_info != None):
        if ("mosquitto" in broker_info):
            pdfw.add_to_existing_paragraph('In Mosquitto it is possible to limit in accordance with the use case:<br><br>\
    <b>The messages size</b> with <i>max_inflight_bytes</i>,  <i>max_packet_size</i> and <i>message_size_limit</i>;<br>\
    <b>The message rate</b> with <i>max_inflight_messages</i>;<br>\
    <b>The active connections</b> with <i>max_connections</i> and <i>persistent_client_expiration</i> ;<br>\
    <b>The number of messages queued by the broker</b> with <i>max_queued_messages</i>, <i>max_queued_bytes</i>, <i>upgrade_outgoing_qos (M)</i> and <i>queue_qos0_messages (M)</i>;<br>\
    <b>The logging level</b> with log_dest (M);<br>\
    <b>The Memory use</b> with <i>memory_limit</i>;<br>\
    <b>Prevent Slow DoS</b> with <i>max_keepalive</i>.<br>')

            pdfw.add_to_existing_paragraph('The (M) notation indicates that the parameter is considered secure by-default. Refer to the <a href="https://mosquitto.org/man/mosquitto-conf-5.html">official documentation</a> for further details. Retained messages can be disabled via <i>retain_available</i> and <i>check_retain_source (M)</i> allows to avoid the sending of retained messages from clients whose access have been revoked.')
        elif ("verne" in broker_info):
            pdfw.add_to_existing_paragraph('In VerneMQ it is possible to limit in accordance with the use case:<br><br>\
    <b>The messages size</b> with <i>max_message_size</i> and <i>tcp.buffer_sizes</i>;<br>\
    <b>The message rate</b> with <i>max_inflight_messages</i> and <i>max_message_rate</i>;<br>\
    <b>The active connections</b> with <i>max_connections</i>, <i>persistent_client_expiration</i> and <i>allow_multiple_sessions (M)</i>;<br>\
    <b>The number of messages queued by the broker</b> with <i>max_online_messages</i>, <i>max_offline_messages</i> and <i>upgrade_outgoing_qos (M)</i>;<br>\
    <b>The logging level</b> with <i>log.console.level</i>;<br>\
    <b>The CPU multi-processing and memory use</b> with <i>nr_of_acceptors</i> and <i>maximum_memory.percent</i> (respectively).<br>')

            pdfw.add_to_existing_paragraph('The (M) notation indicates that the parameter is considered secure by-default; "*." that is applied to the listener (that constitutes the prefix). Refer to the <a href="https://docs.vernemq.com/configuration/introduction">official documentation</a> for further details. Retained messages cannot be disabled but the retry interval for QoS 1 and 2 messages can be delayed (with <i>retry_interval</i>).')
        elif ("emqx" in broker_info):
            pdfw.add_to_existing_paragraph('In EMQ X it is possible to limit in accordance with the use case:<br><br>\
    <b>The messages size</b> with the settings <i>*.max_packet_size (M)</i>, <i>*.rate_limit.conn_bytes_in (M)</i>, <i>*.tcp.external.buffer (*.tcp.external.recbuf and *.tcp.external.sndbuf)</i> and <i>*.ws.external.max_frame_size</i> (if using the WebSockets);<br>\
    <b>The message rate</b> with the setting <i>*.max_inflight</i>;<br>\
    <b>The active connections</b> with the settings <i>*.tcp.external.max_connections</i>, <i>*.tcp.external.active_n</i>, <i>*.tcp.external.max_conn_rate</i>, <i>*.rate_limit.conn_messages_in</i> and <i>*.session_expiry_interval</i>;<br>\
    <b>The number of messages queued by the broker</b> with the settings <i>*.max_mqueue_len</i> and <i>*.force_shutdown_policy</i>. Remember also to disable the use of queues for QoS 0 messages (<i>mqueue_store_qos0</i>) if not necessary;<br>\
    <b>The logging level</b> with <i>log.to</i>, <i>log.chars_limit</i>, <i>log.$level (M)</i>, <i>log.sync_mode_qlen (M)</i>, <i>log.drop_mode_qlen (M)</i>, <i>log.flush_qlen (M)</i>, <i>log.overload_kill (M)</i>, <i>log.overload_kill_qlen (M) and <i>log.burst_limit (M)</i>;<br>\
    <b>The CPU multi-processing and memory use</b> with <i>*.tcp.external.acceptors</i>, <i>node.async_threads</i>, <i>node.process_limit</i>, <i>node.dist_buffer_size</i>, <i>node.max_ets_tables</i>, <i>node.global_gc_interval and node.fullsweep_after</i>,  log.overload_kill_mem_size (M)</i>, <i>*.force_gc_policy</i> and <i>*.force_shutdown_policy</i>;<br>\
    <b>Prevent Slow DoS</b> with <i>*.server_keepalive and .keepalive_backoff (M)</i>, <i>max_awaiting_rel and await_rel_timeout</i> and <i>external.send_timeout and tcp.external.send_timeout_close (M)</i>.<br>')

            pdfw.add_to_existing_paragraph('The (M) notation indicates that the parameter is considered secure by-default; "*." that is applied to the listener (that constitutes the prefix). Refer to the <a href="https://docs.emqx.io/en/broker/v4.3/getting-started/config.html">official documentation</a> for further details. Retained messages can be disabled via <i>mqtt.retain_available</i> and the retry interval for QoS 1 and 2 messages set with the <i>*.retry_interval</i> parameter. Try also to set suitable threasholds on the host resources (sysmon.*, os_mon.*, vm_mon.*) and the corresponding alarms.')
                
    pdfw.add_to_existing_paragraph('Additional information here:')
    pdfw.add_to_existing_paragraph('<a href="https://www.hivemq.com/blog/mqtt-security-fundamentals-securing-mqtt-systems">MQTT Security Fundamentals: Securing MQTT Systems</a>')


# Malformed data section
def malformed_data_report(pdfw, mal_data, topic):
    pdfw.add_paragraph("Malformed data")
    # Description
    pdfw.add_to_existing_paragraph("MQTTSA tried to stress the broker by sending malformed packets in the "+str(topic)+" topic.")
    pdfw.add_to_existing_paragraph("An attacker could send malformed packets aiming at triggering errors to cause DoS or obtain information about the broker. We suggest to perform a full fuzzing test to stress the implementation with random well-crafted values. A fuzzer designed for MQTT is developed by F-Secure and can be found on the following link:")
    pdfw.add_to_existing_paragraph('<a href="https://github.com/F-Secure/mqtt_fuzz">Fuzzer F-Secure</a>')
    
    for malformed_data_object in mal_data:
        # print results
        pdfw.add_sub_paragraph("Parameter of the "+ malformed_data_object.packet +" packet tested: " + malformed_data_object.parameter)
        successful_values = "Values that did not generate an error: <br>"
        for val in malformed_data_object.successes:
            successful_values += str(val) + ", "
        successful_values = successful_values[:-2]
        pdfw.add_to_existing_paragraph(successful_values)
        error_values = "Values that generated an error and the related error: <br>"
        for val in malformed_data_object.errors:
            error_values += "Value: " + str(val.err_value) + ", Error: " + str(val.err_message) + "<br>"
        #ee = ee[:-2]
        pdfw.add_to_existing_paragraph("<br>"+error_values)

    pdfw.add_to_existing_paragraph("In case the report refer to values like '$' or '$topic', it might be possible to be exploit a bug included in an old version of Mosquitto. We strongly suggest to always keep the broker updated to avoid similar issues.")
