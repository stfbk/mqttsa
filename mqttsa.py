import src.utils.utils as utils
import src.bruteforce.brute_force as bruteforce
import src.dos.broker_dos as dos
import src.pdf_wrapper.pdf_wrapper as pdfw
import src.pdf_wrapper.write_results as write_results
import src.sniff.sniff_packets as sniff
import src.malformed_data.malformed_data as md
import src.regex_patterns as patterns

from time import sleep
import paho.mqtt.client as mqtt

import os, ssl, sys

#Set stdout to print UTF8-encoded messages
sys.stdout.reconfigure(encoding='utf-8')

# Function called after MQTTSA connects with the broker, whether the connection was successful or not
def on_connect_3(client, userdata, flags, rc):

    # Set to True if the authentication is not required
    global no_authentication
    # set to True if the user wants to perform a brute force attack, otherwise is False
    global do_bruteforce
    # set to True if connecting with intercepted credential succeeds
    global credentials_sniffed
    # set to True if connecting with brute-forced credential succeeds
    global credentials_bruteforced
    # set to True if connecting with only the username
    global no_pass
    # set to True if connecting via provided certificates    
    global via_certs
    
    # Return codes
    # 0 - Connection accepted
    # 1 - Connection refused, unacceptable protocol version (es. MQTT 5)
    # 2 - Connection refused, client identifier is UTF-8 but not allowed by the server
    # 3 - Connection refused, server unavailable
    # 4 - Connection refused, malformed username or password
    # 5 - Connection refused, not authorized
    
    if (rc == 0):
        # userdata = 0 means no username and passwords
        # userdata = 1 means username but no password
        # userdata = 2 means username and password
        if (userdata == 0):
            print('Connected successfully without authentication.')
            no_authentication = True
            if(do_bruteforce):
                print('Brute force not required!')
                do_bruteforce = False
        elif (userdata== 1):
            print('Connected successfully using a usename and password found with sniffing.')
            credentials_sniffed = True
            if(do_bruteforce):
                print('Brute force not required!')
                do_bruteforce = False
        elif (userdata== 2):
            print('Connected successfully with provided certificates.')
            via_certs = True
            if(do_bruteforce):
                print('Brute force not required!')
                do_bruteforce = False
        elif (userdata== 3):
            print('Connected successfully without providing a password.')
            no_pass = True
        elif (userdata == 4):
            print('Connected successfully using password found with brute force.')
            credentials_bruteforced = True
    elif (rc == 1):
        print('[!] Error: protocol version not supported.')
        sys.exit()
    elif (rc == 2):
        print('[!] Error: Client ID notallowed by the server. Possible inconsistent results.')
    elif (rc == 3):
        print('[!] Error: connected but server unavailable. Try again later.')
    elif (rc == 4):
        print('[!] Warning: malformed username or password.')
    else:
        #A password- or certificate-based authentication mechanism prevents the connection
        #print("Connection refused, not authorized")
        pass

def on_connect_5(client, userdata, flags, reasonCode, properties):
    if (properties):
        print("- Properties from the broker"+ str(properties))
    on_connect_3(client, userdata, flags, reasonCode.value)

# Function called after the reception of a message
def on_message(client, userdata, message):

    # set of readable topics
    global topics_readable
    # set of writable topics
    global topics_writable
    # set of readable topics (SYS)
    global sys_topics_readable
    # set of writable topics (SYS)
    global sys_topics_writable
    # we set this variable to True so that we indicate that we were able to read a message, with a possibe disclosure of information
    global information_disclosure
    information_disclosure = True

    # number of connected clients
    global connected_clients
    # the version of the broker
    global broker_info
    # contains the message used for testing purposes (can be set by the user)
    global text_message

    # Parse the message
    payload = message.payload.decode('utf-8','ignore')
    topic = str(message.topic)
    
    # Add the topic in the corresponding readable set
    if ('$SYS' in topic):
        sys_topics_readable.add(topic)
        # Set the following only the first time
        if(connected_clients == None and topic == '$SYS/broker/clients/connected'):
            connected_clients = payload
        if(broker_info == None and topic == '$SYS/broker/version'):
            broker_info = payload
    else:
        if(not 'MQTTSA/Client_flooding' in topic):
            topics_readable.add(topic)
            if(len(payload) < 1000 and not str(payload).startswith('DoSMessage')): # Avoid printing on console DoS messages or long ones
                print('Non-sys message received ' + payload)

    # This function parses the content of the message to extract useful information
    if(not 'MQTTSA/Client_flooding' in topic):
        parse_message(payload, message.topic)

    # If the test message is found, this means that we can write in the topic -> add it to the corresponding writable list
    try:
        if (text_message==payload):
            if ('$SYS' in str(message.topic)):
                sys_topics_writable.add(str(message.topic))
            else:
                topics_writable.add(str(message.topic))
    except:
        pass

# When a message arrive, it will be parsed by this function to extract useful information and later store them in external files
def parse_message(payload, topic):
    global mac_address
    global ipv4
    global domain_names
    global email
    global passw
    global iot
    global msg
    global status
    global endpoint
    global dates
    global phones
    global cards
    global dir
    global gps
    global test
    global raw_messages

    if (patterns.pattern_test.match(payload)):
        test.append(payload)
    if (patterns.pattern_domain_names.match(payload)):
        domain_names.append(payload)
    if (patterns.pattern_email.match(payload)):
        email.append(payload)
    if (patterns.pattern_passw.match(payload)):
        passw.append(payload)
    if (patterns.pattern_iot.match(payload)):
        iot.append(payload)
    if (patterns.pattern_iot_2.match(topic)):
        iot.append(payload)
    if (patterns.pattern_msg.match(payload)):
        msg.append(payload)
    if (patterns.pattern_status.match(payload)):
        status.append(payload)
    if (patterns.pattern_endpoint.match(payload)):
        endpoint.append(payload)
    if (patterns.pattern_dates.match(payload)):
        dates.append(payload)
    if (patterns.pattern_phones.match(payload)):
        phones.append(payload)
    if (patterns.pattern_cards.match(payload)):
        cards.append(payload)
    if (patterns.pattern_dir.match(payload)):
        dir.append(payload)
    if (patterns.pattern_gps.match(payload)):
        gps.append(payload)
    if (patterns.pattern_mac_address.match(payload)):
        mac_address.append(payload)
    if (patterns.pattern_ipv4.match(payload)):
        ipv4.append(payload)

    raw_messages.append(payload)

# this function writes the extracted content of messages in external files
def save_list(list, type):
    if not os.path.exists("messages"):
        os.makedirs("messages")
    with open('messages/'+type+'.txt', 'w+', encoding='utf-8') as f:
        for item in list:
            f.write("%s\n" % item)

def save_messages(mac_address, ipv4, domain_names, email, passw, iot, msg, status, endpoint, phones, cards, dir, gps, test, raw_messages):
    # We save all the information extracted from messages in external files
    if mac_address:
        save_list(mac_address, 'mac_addresses')
    if ipv4:
        save_list(ipv4, 'ipv4_addresses')
    if domain_names:
        save_list(domain_names, 'domain_names')
    if email:
        save_list(email, 'email_addresses')
    if passw:
        save_list(passw, 'password_keywords')
    if iot:
        save_list(iot, 'iot_keywords')
    if msg:
        save_list(msg, 'message_keywords')
    if status:
        save_list(status, 'status_keywords')
    if endpoint:
        save_list(endpoint, 'endpoint_keywords')
    if dates:
        save_list(dates, 'dates')
    if phones:
        save_list(phones, 'phones')
    if cards:
        save_list(cards, 'credit_card_keywords')
    if dir:
        save_list(dir, 'directories')
    if gps:
        save_list(gps, 'gps_keywords')
    if test:
        save_list(test, 'test')
    if raw_messages:
        save_list(raw_messages, 'raw_messages')

def connect_listen_publish(broker_address, version, port, credentials, cert_key_paths, state):
    global listening_time
    global non_intrusive
    global topics_readable
    global sys_topics_readable
    
    protocol_version = mqtt.MQTTv5 if version == '5' else mqtt.MQTTv311
    
    #If providing credentials use them to configure the client (client ID might not be provided)
    if(credentials != None and not credentials.empty):
        if (credentials.clientID != None):
            client = mqtt.Client(credentials.clientID, userdata=state, protocol = protocol_version)
        else:
            client = mqtt.Client(userdata=state, protocol = protocol_version) 
        client.username_pw_set(credentials.username, credentials.password)
    else:
        client = mqtt.Client(userdata=state, protocol = protocol_version) 

    #If providing certificates use them to configure TLS
    if(cert_key_paths!=None):
        client.tls_set(cert_key_paths[0], cert_key_paths[1], cert_key_paths[2], ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
        client.tls_insecure_set(True)       
        
    if version == '5':
        client.on_connect = on_connect_5
    else:
        client.on_connect = on_connect_3
        
    client.on_message = on_message
    
    client.connect_async(broker_address, port, 60)
    client.loop_start()
    
    try:
        print("10 seconds connection timeout (press ctrl+c once to skip)")
        for x in range (10):
            if(client.is_connected()):
                # Subscribe to all topics and $SYS topics
                client.subscribe('#')
                client.subscribe('$SYS/#')

                # Listen for messages
                print("Listening " + str(listening_time)+" seconds for messages")
                for x in range(listening_time):
                    if (x % 10 == 0):
                        print(str(listening_time-x) + " seconds remaining") # print each 10s
                    sleep(1)

                # If the non intrusive flag was not set, attempt to write on intercepted topics
                if (not non_intrusive):
                    all_topics = topics_readable.union(sys_topics_readable)
                    if(len(all_topics)>0):
                        print('\nTrying to publish in '+str(len(all_topics))+' topics.')
                        for i in all_topics:
                            print('trying to write in: '+str(i))
                            client.publish(i,text_message)
                            sleep(.1) #check
                client.loop_stop()
                client.disconnect()
                return True
            else:
                sleep(1)
    except KeyboardInterrupt:
        return False
        
    client.loop_stop()
    print("Connection timeout")
    return False

# main function
if __name__== "__main__":

    # Sets of readable and writable topics
    topics_readable = set()
    topics_writable = set()
    # Sets of readable and writable SYS topics
    sys_topics_readable = set()
    sys_topics_writable = set()
    
    # Set to True if the tool is able to intercept at least one message
    information_disclosure = False
    # Set to True if the tool is able to connect without password- or certificate-based authentication
    no_authentication = False    
    # Set to True if the tool is able to connect only with username or the username bug is present (it manages to connect with '#' username)
    no_pass = False
    # Set to True if the username bug is present (the tool manages to connect with '#' username)
    username_bug = False
    # Number of clients connected to the broker (if the tool manages to subscribe to the $SYS/broker/clients/connected topic)
    connected_clients = None
    # Version of the broker (if the tool manages to subscribe to the $SYS/broker/version topic)
    broker_info = None
    # Set to True if a set of sniffed username and password works 
    credentials_sniffed = False
    # Set to True if brute-forcing works 
    credentials_bruteforced = False
    # Set to True if connecting via provided certificates
    via_certs = False
    # Stores sniffed or brute-forced credentials
    credential_list = []
    # Stores the malformed data and DoS test results
    mal_data = None
    dos_result = None
        
    # List of intercepted messages (parsed with regexes) by types 
    mac_address = []
    ipv4 = []
    domain_names = []
    email = []
    passw = []
    iot = []
    msg = []
    status = []
    endpoint = []
    dates = []
    phones = []
    cards = []
    dir = []
    gps = []
    test = []
    raw_messages = []
    clientIds = []

    # Initialization of the object to write the PDF with the results of the attacks
    pdf = pdfw.init()
    
    # Getting all command-line values parsing the arguments
    args = utils.create_parser().parse_args()
    broker_address            = args.broker_address
    version                   = args.version
    listening_time            = args.listening_time
    dos_flooding_connections  = args.dos_fooding_conn
    dos_flooding_size         = args.dos_size
    dos_slow_connections      = args.dos_slow_conn
    max_queue                 = args.max_queue
    max_payload               = args.max_payload
    username                  = args.username
    wordlist_path             = args.wordlist_path
    text_message              = args.text_message
    interface                 = args.interface
    port                      = args.port
    malformed_data            = args.malformed_data
    non_intrusive             = args.non_intrusive
    ca_cert                   = args.ca_cert
    client_cert               = args.client_cert
    client_key                = args.client_key
    max_user_properties       = args.max_user_properties
    
    print('')
    
    # Printing errors or setting default values
    if (listening_time == None or listening_time < 1):
        print('[!] "t" parameter < 1 or not specified, setting listening time to 60s')
        listening_time = 60

    if (dos_flooding_connections == None or dos_flooding_connections < 1):
        print('[!] "dos_fooding_conn" parameter < 1 or not specified, no flooding-based DoS attack')
        dos_flooding_connections = None
    if (dos_slow_connections == None or dos_slow_connections < 1):
        print('[!] "dos_slow_conn" parameter < 1 or not specified, no slow DoS attack')
        dos_slow_connections = None
    if (max_queue == None or max_queue < 1):
        print('[!] "max_queue" parameter < 0 or null, no message queue test')
        max_queue = None
    if (max_payload == None or max_payload < 1):
        print('[!] "max_payload" parameter < 0 or null, no payload size test')
        max_payload = None
        
    if (username == None):
        print('[!] "u" parameters not specified, no Bruteforce attack')
        do_bruteforce = False
    else:
        if(wordlist_path == None):
            wordlist_path = os.path.join(os.getcwd(), "src", "words.txt") #Use the one provided
            print('[!] "w" parameters not specified, using the default one')
            
        if(os.path.exists(wordlist_path)):
            do_bruteforce = True
        else:
            print('[!] Error: verify the wordlist path '+ wordlist_path)
            sys.exit() 

    if (text_message == None):
        print('[!] text_message not specified, setting it to "testtesttest"')
        text_message='testtesttest'

    if (interface == None):
        print('[!] interface not specified, no Sniffing attack')

    if (port == None):
        print('[!] port not specified, setting it to 1883')
        port = 1883

    if (ca_cert == None):
        print('[!] no CA certificate path specified, not connecting using TLS')
    elif (not os.path.exists(ca_cert)):
        print('[!] Error: verify the CA certificate path')
        sys.exit()
    if(client_cert != None and not os.path.exists(ca_cert)):
        print('[!] Error: verify the Client certificate path')
        sys.exit()
    if(client_key != None and not os.path.exists(client_key)):
        print('[!] Error: verify the Client key path')
        sys.exit()

    if max_user_properties == None or max_user_properties < 1:
        print('[!] "max_user_properties" parameter < 0 or null, no user properties test')
        max_user_properties = None

    if (malformed_data == False):
        print('[!] --md flag not specified, no Malformed-data attack')

    if(non_intrusive == True):
        print('[!] Performing only non-intrusive tests')

    # Print recap of tests
    print('\n\n[*] TARGET:                      ' + str(args.broker_address))
    print('[*] LISTENING TIME:              ' + str(listening_time))
    print('[*] DOING DOS ATTACKS:           ' + str(dos_flooding_connections != None or dos_slow_connections != None))
    print('[*] DETECTING MAX PAYLOAD/QUEUE: ' + str(max_queue != None or max_payload != None))
    print('[*] DOING SNIFFING ATTACK:       ' + str(interface != None))
    print('[*] DOING BRUTEFORCE:            ' + str(do_bruteforce))
    print('[*] DOING MALFORMED DATA:        ' + str(malformed_data))
    print('[*] TEXT MESSAGE                 ' + text_message+'\n')

    print("Attempting the connection without credentials or TLS")
    connect_listen_publish(broker_address, version, port, None, None, 0)

    if (interface!=None):
        print("Attempting to intercept credentials on the " + interface + " adapter for "+ str(listening_time) +"s and use them to connect (unskippable)")
        credential_list = sniff.sniffing_attack(interface, listening_time, port)
        for cred in credential_list:
            connect_listen_publish(broker_address, version, port, cred, None, 1)
    
    if(ca_cert != None):
        print("Attempting the connection with certificate(s)")
        connect_listen_publish(broker_address, version, port, None, [ca_cert, client_cert, client_key], 2)
    
    # If the user wants to perform the bruteforce and it is possible according to the return code
    # (the connection with no credentials failed and no credentials have been retrieved via the sniffing attack)
    if (do_bruteforce):
        
        cred = sniff.Credentials()
        cred.add_clientID(username)
        cred.add_username(username)
        
        print("Attempting the connection with only the username (set also as client ID)")
        connect_listen_publish(broker_address, version, port, cred, None, 3)
        
        if(ca_cert != None):
            print("-Also with provided certificates")
            connect_listen_publish(broker_address, version, port, cred, [ca_cert, client_cert, client_key], 3)       
        
        if(no_pass):
            credential_list.append(cred)
        else:
        # The password is required
            print('\nPerforming brute force (press ctrl+c once to skip)')
            # Perform brute force: bruteforce_results is an array containing two variables, 
            # a boolean set to True if the attack was successful and the password's value if it was able to find it
            bruteforce_results = bruteforce.brute_force(broker_address,version,port,username,wordlist_path, ca_cert, client_cert,client_key)
            username_bug = bruteforce.username_bug(broker_address,version,port, ca_cert, client_cert, client_key)

            #Brute-force succesfull -> sniff some packets
            if(bruteforce_results[0]):
                cred.add_password(bruteforce_results[1])
                
                print("Attempting the connection with: ["+ username +","+ bruteforce_results[1] +"]")
                connect_listen_publish(broker_address, version, port, cred, None, 4)
                
                if(ca_cert != None):
                    print("-Also with provided certificates")
                    connect_listen_publish(broker_address, version, port, cred, [ca_cert, client_cert, client_key], 4)
                    
                credential_list.append(cred)

    connected = (no_authentication or credentials_sniffed or credentials_bruteforced or via_certs)

    # Perform malformed-data and DoS only if the tool was able to connect somehow
    if (malformed_data): #flag is set
        if (connected):
            # in case no writable topics are found, try with a random one (e.g., Topic1)
            if (len(topics_writable)!=0):
                mal_data_topic = next(iter(topics_writable))
            elif (len(sys_topics_writable)!=0):
                mal_data_topic = next(iter(sys_topics_writable))
            else:
                mal_data_topic = "Topic1" # check
                
            print('\nPerforming malformed data on '+ mal_data_topic +' topic...\n')
            mal_data = md.malformed_data(broker_address, version, port, mal_data_topic, ca_cert, client_cert, client_key, credential_list)
            
            if(version == '5'):
                malformed_result_5 = md.malformed_data_5(broker_address, port, ca_cert, client_cert, client_key, credential_list)
        else:
            print("Skipping malformed-data test as the tool was not able to connect")
                 
    # Perform the attack if flooding-based or slow DoS connections have been provided; or if investigating the max message queue/payload
    if (dos_flooding_connections!=None or dos_slow_connections!=None or max_queue != None or max_payload != None or max_user_properties != None):
        if (connected):
            print('\nPerforming Denial of Service...\n')
            # If there is a topic in which we can write we use that topic; if no credentials, pass an empty set
            if (len(topics_writable)!=0):
                dos_result = dos.broker_dos(broker_address,
                                            version,
                                            port,
                                            credential_list[0] if(credential_list) else sniff.Credentials(),
                                            dos_flooding_connections,
                                            dos_flooding_size,
                                            dos_slow_connections,
                                            max_queue,
                                            max_payload,
                                            next(iter(topics_writable)),
                                            [ca_cert, client_cert, client_key])
            # Otherwise we will use an empty string as the topic
            else:
                dos_result = dos.broker_dos(broker_address,
                                            version,
                                            port,
                                            credential_list[0] if(credential_list) else sniff.Credentials(),
                                            dos_flooding_connections,
                                            dos_flooding_size,
                                            dos_slow_connections,
                                            max_queue,
                                            max_payload,
                                            "MQTTSA",
                                            [ca_cert, client_cert, client_key])
            if(version == '5'):
                dos_result_5 = dos.broker_dos_5(broker_address, port, max_user_properties,
                                                credential_list[0] if(credential_list) else sniff.Credentials(), 
                                                [ca_cert, client_cert, client_key])
        else:
            print("Skipping DoS test as the tool was not able to connect")
        
    # We start adding paragraphs to the pdf with the result of the attacks
    pdfw.add_summary_table("Details of the assessment", 
        broker_address, 
        str(port), 
        str(listening_time), 
        (text_message[:18] + '..') if len(text_message) > 18 else text_message, 
        ("None") if (interface == None) else ((interface[:18] + '..') if len(interface) > 18 else interface),
        str(not mal_data == None),
        ("None") if (dos_flooding_connections == None or dos_result==None) else (str(dos_flooding_connections)),
        ("None") if (dos_flooding_connections == None or dos_result==None) else str(dos_flooding_size)+" MB",
        ("None") if (dos_slow_connections == None or dos_result==None) else (str(dos_slow_connections)),
        [dos.max_queue, max_queue, dos.max_payload, max_payload, dos.connected, dos_slow_connections] if (dos.max_queue>0 or dos.max_payload>0 or dos.connected>0) else [],
        str(do_bruteforce),
        "Replace_up_to_date",
        (ca_cert != None),
        str(information_disclosure),
        no_authentication,
        no_pass,
        credential_list,
        client_key
        )
        
    # Print the results in the report only if it manages to connect
    if(connected):
        # Authentication mechanism results
        write_results.authentication_report(pdfw, no_authentication, broker_info, credentials_sniffed, credentials_bruteforced, interface, broker_address, port)

        # Information disclosure results
        write_results.information_disclosure_report(pdfw, topics_readable, sys_topics_readable, listening_time, broker_info, no_authentication)

        # Data tampering results
        write_results.tampering_data_report(pdfw, topics_writable, sys_topics_writable, topics_readable, sys_topics_readable, text_message)

        # Broker fingerprinting
        write_results.fingerprinting_report(pdfw, broker_info)
        
        # Sniffing attack results
        if (interface!=None):
            cred_string = []
            for c in credential_list:
                if (do_bruteforce and c.password == bruteforce_results[1]): # exclude bruteforced passwords
                    continue
                if(c.clientID == "ClientID: "): # to be fixed
                    continue
                cred_string.append(sniff.print_credentials(c))
            write_results.sniffing_report(pdfw, interface, cred_string, listening_time, broker_info)
        else:
            cred_string = []
            
        # Bruteforce results
        if (do_bruteforce):
            write_results.brute_force_report(pdfw, username, wordlist_path, bruteforce_results[1], no_pass)

        # DoS results
        if(dos_result != None):
            write_results.dos_report(pdfw, 
                dos_flooding_connections, dos_flooding_size, dos.connection_difference, dos.percentage_increment, 
                dos_slow_connections,  dos.slow_connection_difference,
                max_queue, dos.max_queue,
                max_payload, dos.max_payload,
                broker_info)

            if(version == '5' and dos_result_5 != None):
                max_pack_size_result = dos_result_5[0]
                us_prop_result = dos_result_5[1]
                will_delay_result = dos_result_5[2]
                write_results.dos_report_5(pdfw, max_pack_size_result, us_prop_result, dos.max_user_properties, will_delay_result)

        # malformed data results
        if (mal_data):
            write_results.malformed_data_report(pdfw, mal_data, mal_data_topic)
            if(version == '5'):
                double_result = malformed_result_5[0]
                wrong_result = malformed_result_5[1]
                share_result = malformed_result_5[2]
                write_results.malformed_data_report_5(pdfw, double_result, wrong_result, share_result)
    else:
        pdfw.add_sub_paragraph("Error", "Unable to connect to the broker. Please verify host/port.")
    # function that generates the pdf report
    pdfw.output_pdf(write_results.outdated_broker)

    save_messages(mac_address, ipv4, domain_names, email, passw, iot, msg, status, endpoint, phones, cards, dir, gps, test, raw_messages)

    # Printing a brief summary of the attacks on the console
    print('\n\n')
    
    print('**************************************************')
    print('                     REPORT\n')
    print('            Target: '+str(broker_address))
    print('            Listening time: '+str(listening_time))
    print('**************************************************\n')
    print('     + Authentication required:           '+str(not no_authentication))
    if (interface != None):
        if(credentials_sniffed):
            print('         + Intercepted credentials:')
            for c in cred_string:
                print("             "+c)      
    print('\n     + Information disclosure:           '+str(information_disclosure))
    if len(topics_readable)>0 or len(sys_topics_readable)>0:
        print('         + # of Topics we read:          '+str(len(topics_readable)))
        print('         + # of Topics we wrote:         '+str(len(topics_writable)))
        print('         + # of SYS Topics we read:      '+str(len(sys_topics_readable)))
        print('         + # of SYS Topics we wrote:     '+str(len(sys_topics_writable)))
        if(not connected_clients == None):
            print('         + # of Connected Clients:       '+str(connected_clients))
        if(not broker_info == None):
            print('         + broker info:                  '+str(broker_info))
    else:
        print('         + No topics detected')
    print('')

    if (not dos_flooding_connections == None):
        print('     + Floding-based DOS successful:     '+(("Skipped") if (dos_result == None) else str(dos_result)))
        print('         + # payload size (MB):          '+str(dos_flooding_size))
        print('         + # connections for the attack: '+str(dos_flooding_connections))
        print('         + # connections failed:         '+ (("0") if (dos.connection_difference < 0) else str(dos.connection_difference)))
        print('         + # overhead on publish time:   '+str(int(dos.percentage_increment))+"%")
        print('')

    if (not dos_slow_connections == None):
        print('     + Slow DOS successful:              '+(("Skipped") if (dos_result == None) else str(dos.slow_connection_difference != 0)))
        print('         + Max supported connections:    '+str(dos_slow_connections-dos.slow_connection_difference))
        print('')

    if(not max_queue == None or not max_payload == None):
        print('     + Test for unlimited msg. queues or payload:')
        print('         + # Max supported payload: ' + (f"{dos.max_payload}MB" if (max_payload) else "Skipped"))
        print('         + # Messages queues:       ' + (f"{dos.max_queue}/{max_queue}" if (max_queue) else "Skipped"))
        
    if (do_bruteforce):
        print('     + Brute force successful:           '+str(bruteforce_results[0]))
        print('         + username used:                '+username)
        if no_pass:
            print('     + password not required!')
        if bruteforce_results[0]:
            print('         + password found:               '+str(bruteforce_results[1]))
        if username_bug:
            print('         + ACL bypassed using as username:   "#"')

    print('**************************************************')
