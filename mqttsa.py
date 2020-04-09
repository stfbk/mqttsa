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

import os, optparse, ssl, sys

# function called after MQTTSA connects with the broker, whether the connection was successful or not
def on_connect(client, userdata, flags, rc):

    # set to True if the authentication is not required
    global no_authentication
    # set to True if the user wants to perform a brute force attack, otherwise is False
    global brute_force_dec
    # set to True if the password is not required
    global no_pass
    # set to True if the authentication with intercepted credential succeeds
    global auth_anyway

    global weak_ac
    
    # if return code is 0, connected!
    if rc==0:
        # the state variable is used to trace how we connected to the broker
        # state = 0 means no username and passwords
        # state = 1 means username but no password
        # state = 2 means username and password
        weak_ac = True
        if state==0:
            print('Connected! Returned code: ' +str(rc))
            print('Brute force not required!')
            brute_force_dec = False
            no_authentication = True
            no_pass = True
            
        elif state==1:
            print('No password required!')
            no_pass = True
        elif state ==2:
            print('Connected successfully using password found with brute force')
        elif state ==4:
            auth_anyway = True
            print('Connected successfully using a usename and password found with sniffing')
    elif (rc!=4):
        if(state != 0):
            print('Not connected, Returned code: '+str(rc)+'')

# function called after the reception of a message
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

    # INFO OF THE BROKER

    # number of connected clients
    global connected_clients
    # the version of the broker
    global broker_info
    # contains the message used for testing purposes (can be set by the user)
    global text_message

    # print message and topic
    try:
        # contains the content of the message
        payload = message.payload.decode("utf-8")
    except:
        payload = str(message.payload, 'utf-8')
        print('message received but cannot decode as utf-8: ' + payload)

    # If we can read, we add the topic in the corresponding readable set
    if '$SYS' in str(message.topic):
        sys_topics_readable.add(str(message.topic.replace('#','')))
        if(connected_clients == None and str(message.topic) == '$SYS/broker/clients/connected'):
            connected_clients = payload
        if(broker_info == None and str(message.topic) == '$SYS/broker/version'):
            broker_info = payload
    else:
        print('non-sys message received '+ payload)
        topics_readable.add(str(message.topic.replace('#','')))

    # this function parses the content of the message to extract useful information
    parse_message(payload)
    if (patterns.pattern_iot_2.match(message.topic)):
        iot.append(payload)

    # If we found the test message, this means that we can write, so we add the topic to the corresponding writable list
    try:
        if (text_message==payload):
            if '$SYS' in str(message.topic):
                sys_topics_writable.add(str(message.topic))
            else:
                topics_writable.add(str(message.topic))
    except:
        pass

# when a message is intercepted, it will be parsed by this function to extract useful information and store them in external files
def parse_message(message):
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

    if (patterns.pattern_test.match(message)):
        test.append(message)
    if (patterns.pattern_domain_names.match(message)):
        domain_names.append(message)
    if (patterns.pattern_email.match(message)):
        email.append(message)
    if (patterns.pattern_passw.match(message)):
        passw.append(message)
    if (patterns.pattern_iot.match(message)):
        iot.append(message)
    if (patterns.pattern_msg.match(message)):
        msg.append(message)
    if (patterns.pattern_status.match(message)):
        status.append(message)
    if (patterns.pattern_endpoint.match(message)):
        endpoint.append(message)
    if (patterns.pattern_dates.match(message)):
        dates.append(message)
    if (patterns.pattern_phones.match(message)):
        phones.append(message)
    if (patterns.pattern_cards.match(message)):
        cards.append(message)
    if (patterns.pattern_dir.match(message)):
        dir.append(message)
    if (patterns.pattern_gps.match(message)):
        gps.append(message)
    if (patterns.pattern_mac_address.match(message)):
        mac_address.append(message)
    if (patterns.pattern_ipv4.match(message)):
        ipv4.append(message)

    raw_messages.append(message)

# this function writes the extracted content of messages in external files
def save_list(list, type):
    if not os.path.exists("messages"):
        os.makedirs("messages")
    with open('messages/'+type+'.txt', 'w+', encoding='utf-8') as f:
        for item in list:
            f.write("%s\n" % item)

# main function
if __name__== "__main__":
    # set of readable topics
    global topics_readable
    # set of writable topics
    global topics_writable
    # set of readable topics (SYS)
    global sys_topics_readable
    # set of writable topics (SYS)
    global sys_topics_writable
    # set to True if we could read at least one message
    global information_disclosure
    # number of clients connected to the broker (if we can get this info)
    global connected_clients
    # version of the broker (if we can get this info)
    global broker_info
    
    # initialization of the parser
    parser = utils.create_parser()
    # initialization of the object to write the pdf with the results of the attacks
    pdf = pdfw.init()

    # if no broker_ip is specified: error!
    if len(sys.argv)<2:
        print('[!] No broker IP specified')
        print(parser.print_help())
        quit(42)

    # getting all values parsing the arguments
    (options, args)     = parser.parse_args()
    listening_time      = options.listening_time
    dos_connections     = options.dos_connections
    username            = options.username
    wordlist_path       = options.wordlist_path
    text_message        = options.text_message
    interface           = options.interface
    port                = options.port
    malformed_data      = options.malformed_data
    non_intrusive       = options.non_intrusive
    tls_cert            = options.tls_cert
    client_cert         = options.client_cert
    client_key          = options.client_key
    brute_force_dec     = True

    connected_clients = None
    broker_info = None
    
    # Printing errors or setting default values
    print('')
    if listening_time == None or listening_time < 1:
        print('[!] listening_time wrong or not specified, setting it to 60')
        listening_time = 60

    if dos_connections == None or dos_connections < 1:
        print('[!] dos_connections wrong or not specified, no DoS attack')
        dos_connections = None

    if username == None or wordlist_path == None:
        print('[!] username or wordlist_path not specified, no brute force')
        brute_force_dec = False
    elif not os.path.exists(wordlist_path):
        print('[!] path for the wordlist not found!')
        quit(42)

    if text_message == None or len(text_message)<1:
        print('[!] text_message not specified, setting it to "testtesttest"')
        text_message='testtesttest'

    if interface == None:
        print('[!] interface not specified, no sniffing attack')

    if port == None:
        print('[!] port not specified, setting it to 1883')
        port = 1883

    if malformed_data == None:
        print('[!] --md flag not specified, no malformed data attack')

    if tls_cert == None:
        print('[!] no path for the certificate specified, not connecting using tls')

    print('\n\n[*] TARGET:                  ' + sys.argv[1])
    print('[*] LISTENING TIME:          ' + str(listening_time))
    print('[*] DOING DOS:               ' + str(not dos_connections == None))
    print('[*] DOING SNIFFING ATTACK:   ' + str(not interface == None))
    print('[*] DOING BRUTEFORCE:        ' + str(brute_force_dec))
    print('[*] DOING MALFORMED DATA:    ' + str(not malformed_data == None))
    print('[*] TEXT MESSAGE             ' + text_message+'\n')

    # VARIABLES

    # Initialization of variables

    no_authentication = False
    information_disclosure = False
    topics_readable = set()
    topics_writable = set()
    sys_topics_readable = set()
    sys_topics_writable = set()
    no_pass = False
    bruteforce_results = [False]
    username_bug = False
    password = None
    auth_anyway = False
    
    weak_ac = False
    
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

    # SCRIPT

    # get broker IP as string from arguments
    broker_ip = sys.argv[1]

    # state 0 -> No username, No password
    state = 0

    # first we sniff on a specific interface (if specified) and we try to intercept credentials
    if interface!=None:
        credentials, clientIds = sniff.sniffing_attack(interface, listening_time, port)
    else:
        credentials = None
        
    # try to connect
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    # if the user specified a path to a tls certificate, we try to connect using that certificate
    if tls_cert != None:
        client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
        client.tls_insecure_set(True)

    # connect to the specified broker
    client.connect(broker_ip,port,60)
    client.loop_start()
    print('\nTrying to connect...')
    sleep(5)

    # in case connection worked ('no_authentication' variable will be set to True)
    if (no_authentication):
        # Subscribe to all topics
        client.subscribe('#')

        # Subscribe to all SYS topics
        client.subscribe('$SYS/#')

        # client will start receiving some messages
        sleep(listening_time)

        # iterate in the available topics

        # if the non intrusive flag was set, we just listen for messages but we don't try to write onto them
        if non_intrusive != True:
            all_topics = topics_readable.union(sys_topics_readable)
            print('\nTrying to publish in '+str(len(all_topics))+' topics.\nExtimated time: '+str(len(all_topics))+' seconds\n')
            for i in all_topics:
                # publish test message
                if '#' in i:
                    i = i.replace('#','')
                print('trying to write in: '+str(i))
                client.publish(i,text_message)
                sleep(1)

    client.loop_stop()
    client.disconnect()

    # state 4 -> Attempt authentication with intercepted data
    state = 4

    if (clientIds):
        list_IDs = list(clientIds)
        
    if (credentials):
        sniff_username = list(credentials)[0].username
        sniff_pw = list(credentials)[0].password
    else:
        sniff_username = None
        sniff_pw = None
    
    # in case we were not able to connect first we try to use credentials intercepted with the 
    # sniffing attack (if specified), otherwise we will proceed with the other attacks
    if interface!=None:
        i = 0
        for c in credentials:
            
            if (list_IDs and len(list_IDs)>i):
                client.reinitialise(list_IDs[i], clean_session=True, userdata=None)
            
            i += 1
            u = c.username
            p = c.password

            print('Trying to connect with username: ' + u + ' and password: ' + p)
            client.username_pw_set(u, p)

            # if the path to a CA certificate is available, we try to connect over TLS
            if tls_cert != None:
                client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True)

            client.connect(broker_ip,port)
            client.loop_start()

            # we subscribe to all topics
            client.subscribe('#')
            # we subscribe to all SYS topics
            client.subscribe('$SYS/#')

            # client will start receiving some messages
            sleep(listening_time)

            # if the non intrusive flag was set, we just listen for messages but we don't try to write onto them
            all_topics = topics_readable.union(sys_topics_readable)
            if (non_intrusive != True and (len(all_topics))!=0):
                for i in all_topics:
                    # publish test message
                    if '#' in i:
                        i = i.replace('#','')
                    print('Trying to write in: '+str(i) +' as '+u)
                    client.publish(i,text_message)
                    sleep(1)

            client.loop_stop()
            client.disconnect()

    # if the user wants to perform the brute force and if it is possible based on the return codes from the broker
    if brute_force_dec == True and client_cert == None:
        # No pass trial
        # state 1 -> username, No password
        state = 1

        # Use the first ClientID with provided username
        #if (list_IDs):
        #    client.mqtt.Client(list_IDs[1])
        #else:
        #    client = mqtt.Client()
        
        client = mqtt.Client(username)
        
        client.on_connect = on_connect
        client.on_message = on_message
        client.username_pw_set(username,password=None)

        # if the path to a CA certificate is available, we try to connect over TLS
        if tls_cert != None:
            client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
            client.tls_insecure_set(True)

        # connect to the specified broker
        client.connect(broker_ip,port)
        client.loop_start()
        sleep(5)
        client.loop_stop()
        client.disconnect()

        # if the password is actually required
        if not no_pass:
            print('\nPerforming brute force...')
            # perform brute force
            bruteforce_results = bruteforce.brute_force(broker_ip,port,username,wordlist_path, tls_cert, client_cert,client_key)
            username_bug = bruteforce.username_bug(broker_ip,port, tls_cert, client_cert, client_key)
            # bruteforce_results is an array containing two variables, a boolean set to True if the attack was successful and the password's value if it was able to find it
            if bruteforce_results[0]:
                # state 2 -> username, password
                state = 2

                # Use the first ClientID with provided username
                #if (list_IDs):
                #    client.mqtt.Client(list_IDs[1])
                #else:
                #    client = mqtt.Client()
                
                client = mqtt.Client(username)
                    
                client.on_connect = on_connect
                client.on_message = on_message
                password = bruteforce_results[1]
                client.username_pw_set(username,password)

                # if the path to a CA certificate is available, we try to connect over TLS
                if tls_cert != None:
                    client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                    client.tls_insecure_set(True)

                # connect to the specified broker
                client.connect(broker_ip,port)
                client.loop_start()
                sleep(3)
                client.loop_stop()
                client.disconnect()
            else:
                print('[!] Brute force was not successful\n')

        # if bruteforce was successful or the state variable is different from 2
        if not ((not bruteforce_results[0]) and state==2):
            
            # Use the first ClientID with provided username
            #if (list_IDs):
            #    client.mqtt.Client(list_IDs[1])
            #else:
            #    client = mqtt.Client()
            
            client = mqtt.Client(username)
            
            client.on_connect = on_connect
            client.on_message = on_message
            # state = 1 -> username but no password
            if state == 1:
                client.username_pw_set(username,password=None)
            # state = 2 -> username and password
            elif state == 2:
                client.username_pw_set(username,password)

            # if the path to a CA certificate is available, we try to connect over TLS
            if tls_cert != None:
                client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True)

            client.connect(broker_ip,port)
            client.loop_start()
            # Subscribe to all
            client.subscribe('#')
            # Subscribe to SYS topics
            client.subscribe('$SYS/#')
            # client will start receiving some messages
            sleep(listening_time)

            # iterate in the available topics
            all_topics = topics_readable.union(sys_topics_readable)
            print('Trying to publish in '+str(len(all_topics))+' topics.\nExtimated time: '+str(len(all_topics))+' seconds\n')
            for i in all_topics:
                # publish test message
                if '#' in i:
                    i = i.replace('#','')
                print('trying to write in: '+str(i))
                client.publish(i,text_message)
                sleep(1)
            # test publish on defined topic
            # client.publish('customtopic',text_message)
            client.loop_stop()
            client.disconnect()

    # check if there are writable topics and in case perform data tampering attack
    # in case no writable topics are found, try with a default topic name
    if malformed_data:
        if len(topics_writable)!=0:
            mal_data_topic = next(iter(topics_writable))
        elif len(sys_topics_writable)!=0:
            mal_data_topic = next(iter(sys_topics_writable))
        else:
            mal_data_topic = "Topic1"
            
        mal_data = md.malformed_data(broker_ip, port, mal_data_topic, tls_cert, client_cert, client_key, credentials)
    else:
        mal_data = None

    # check if number of connections for a dos attack are specified 
    # and in case perform the attack
    if dos_connections!=None:

        print('\nPerforming Denial of Service...\n')
        
        if (sniff_username):
            cred = [sniff_username, sniff_pw]
        elif (bruteforce_results[0]):
            cred = [username, bruteforce_results[1]]
        else:
           cred = []
            
        # if there is a topic in which we can write we use that topic
        if len(topics_writable)!=0:
            dos_result = dos.broker_dos(broker_ip,
                                             port,
                                             cred,
                                             dos_connections,
                                             next(iter(topics_writable)),
                                             tls_cert,
                                             client_cert,
                                             client_key)
        # otherwise we will use an empty string as the topic
        else:
            dos_result = dos.broker_dos(broker_ip,
                                             port,
                                             cred,
                                             dos_connections,
                                             "MQTTSA",
                                             tls_cert,
                                             client_cert,
                                             client_key)

    # We print some information on the console
    print('[*] LISTENING TIME:      ' + str(listening_time))
    print('[*] DOING DOS:           ' + str(not dos_connections == None))
    print('[*] DOING BRUTEFORCE:    ' + str(brute_force_dec))
    print('[*] TEXT MESSAGE         ' + text_message+'\n')
    
    # We start adding paragraphs to the pdf with the result of the attacks
    pdfw.add_summary_table("Details of the assessment", 
        str(broker_ip), 
        str(port), 
        str(listening_time), 
        str(text_message), 
        str(interface),
        str(not mal_data == None),
        ("None") if (dos_connections == None) else (str(dos_connections)),
        str(bruteforce_results[0]),
        "Replace_up_to_date",
        (tls_cert != None),
        str(information_disclosure),
        weak_ac,
        no_pass,
        (bruteforce_results[0] or sniff_pw != None),
        client_key
        )

    # authorization mechanism results
    write_results.authorization_report(pdfw, no_authentication, broker_info, auth_anyway, interface)

    # information disclosure results
    write_results.information_disclosure_report(pdfw, topics_readable, sys_topics_readable, listening_time, broker_info, no_authentication)
    write_results.tampering_data_report(pdfw, topics_writable, sys_topics_writable, topics_readable, sys_topics_readable, text_message)

    # fingerprinting
    if broker_info != None:
        write_results.fingerprinting_report(pdfw, broker_info)
    
    # sniffing attack results
    if interface!=None:

        # we get the usernames and passwords from the sniffing attack (if any) and we pass them to the function which inserts them into the final report
        usernames = []
        passwords = []
        for c in credentials:
            u = c.username
            p = c.password
            if u != '':
                usernames.append(u)
            if p != '':
                passwords.append(p)

        write_results.sniffing_report(pdfw, usernames, passwords, clientIds, listening_time, broker_info)

    # brute force results
    if bruteforce_results[0]:
        write_results.brute_force_report(pdfw, username, wordlist_path, bruteforce_results[1], no_pass)

    # dos results
    write_results.dos_report(pdfw, dos_connections, dos.connection_difference, dos.percentage_increment, broker_info)

    # malformed data results
    if mal_data!=None:
        write_results.malformed_data_report(pdfw, mal_data, mal_data_topic)
    
    # function that generates the pdf report
    pdfw.output_pdf(write_results.outdated_broker)

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

    # Printing a brief summary of the attacks on the console
    print('\n\n')

    print('**************************************************')
    print('                     REPORT\n')
    print('            Target: '+str(broker_ip))
    print('            Listening time: '+str(listening_time))
    print('**************************************************\n')
    print('     + Authentication required: '+str(not no_authentication))
    if interface != None:
        print('         + Intercepted usernames:        '+str(usernames))
        print('         + Intercepted passwords:        '+str(passwords))
    print('\n     + Information disclosure:           '+str(information_disclosure))
    if len(topics_readable)>0 or len(sys_topics_readable)>0:
        print('         + # of Topics we read:          '+str(len(topics_readable)))
        print('         + # of Topics we wrote:         '+str(len(topics_writable)))
        print('         + # of SYS Topics we read:      '+str(len(sys_topics_readable)))
        print('         + # of SYS Topics we wrote:     '+str(len(sys_topics_writable)))
        if(not connected_clients == None):
            print('         + # of Connected Clients:       '+str(connected_clients))
        if(not broker_info == None):
            print('         + broker info:                 '+str(broker_info))
    else:
        print('         + No topics detected')
    print('')

    if (not dos_connections == None):
        print('     + DOS successful:                   '+str(dos_result))
        print('         + # connections for the attack: '+str(dos_connections))
        print('         + # connections failed:         '+ (("0") if (dos.connection_difference < 0) else str(dos.connection_difference)))
        print('         + # overhead on publish time:   '+str(dos.percentage_increment))
        print('')

    if (brute_force_dec):
        print('     + Brute force successful:           '+str(bruteforce_results[0]))
        print('         + username used:                '+username)
        if no_pass:
            print('     + password not required!')
        if bruteforce_results[0]:
            print('         + password found:               '+str(bruteforce_results[1]))
        if username_bug:
            print('         + ACL bypassed using as username:   "#"')

    print('**************************************************')
