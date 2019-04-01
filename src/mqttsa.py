import utils.utils as utils
import bruteforce.brute_force as bruteforce
import dos.broker_dos as dos
import pdf_wrapper.pdf_wrapper as pdfw
import pdf_wrapper.write_results as write_results
import sniff.sniff_packets as sniff
import os
import optparse
import ssl
import sys
import malformed_data.malformed_data as md
from time import sleep
import paho.mqtt.client as mqtt

# function called after the connection
def on_connect(client, userdata, flags, rc):
    global no_authentication

    # brute_foce_dec is a boolean that is True if the user wants to perform a brute force attack, otherwise is False
    # here we check the return code of the response of the broker and if the brute force is not required, we set that variable to False
    global brute_force_dec
    global brute_force_cannot_be_executed
    global no_pass

    #Set to true if the authentication with intercepted credential succeeds
    global auth_anyway
        
    # if return code is 0, connected!
    if rc==0:
        # the state variable is used to trace how we connected to the broker
        # state = 0 means no username and passwords
        # state = 1 means username but no password
        # state = 2 means username and password
        if state==0:
            print('Connected! Returned code: ' +str(rc)+'\n')
            if brute_force_dec:
                # User asked bruteforce, but not needed
                brute_force_cannot_be_executed = True
            print('Brute force not required!')
            brute_force_dec = False
            # authentication is not required
            no_authentication = True
            no_pass = True
        elif state==1:
            print('No password required!')
            no_pass = True
        elif state ==2:
            print('Connected successfully using password found with brute force\n')
        elif state ==4:
            auth_anyway = True
            print('Connected successfully using a usename and password found with sniffing\n')
    elif (rc!=4):
        brute_force_dec = False
        # we create a special flag to have an appropriate section in the final report
        brute_force_cannot_be_executed = True
        # authentication may be required
        if(state != 0):
            print('Not connected, Returned code: '+str(rc)+'\n')

# function called after the reception of a message
def on_message(client, userdata, message):
    global topics_readable
    global topics_writable
    global sys_topics_readable
    global sys_topics_writable
    global information_disclosure
    global connected_clients
    global brocker_info

    # print message and topic
    try:
        print('message received '+ message.payload.decode("utf-8"))
    except:
        print('message received but cannot decode in utf-8: ' + str(message.payload))

    # If we can read, add in readable set
    if '$SYS' in str(message.topic):
        sys_topics_readable.add(str(message.topic.replace('#','')))
        if(connected_clients == None and str(message.topic) == '$SYS/broker/clients/connected'):
            connected_clients = message.payload
        if(brocker_info == None and str(message.topic) == '$SYS/broker/version'):
            brocker_info = message.payload
    else:
        # add topic in the set of topic
        topics_readable.add(str(message.topic.replace('#','')))

    information_disclosure = True

    # If we found the test message, we can write, so add to writable list
    try:
        if (text_message==str(message.payload.decode("utf-8"))):
            if '$SYS' in str(message.topic):
                sys_topics_writable.add(str(message.topic))
            else:
                # add topic in the set of topic
                topics_writable.add(str(message.topic))
    except:
        pass

if __name__== "__main__":
    global topics_readable
    global topics_writable
    global sys_topics_readable
    global sys_topics_writable
    global information_disclosure
    global brute_force_cannot_be_executed
    global connected_clients
    global brocker_info
    
    # PARSING INPUT
    parser = utils.create_parser()
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
    threads             = options.threads
    interface           = options.interface
    port                = options.port
    malformed_data      = options.malformed_data
    non_intrusive       = options.non_intrusive
    tls_cert            = options.tls_cert
    client_cert         = options.client_cert
    client_key          = options.client_key
    brute_force_dec     = True

    connected_clients = None
    brocker_info = None

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
    
    if threads== None or threads<1:
        print('[!] threads wrong or not specified, setting it to 10')
        threads=10

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

    # authentication may be required - Set to true if it is able to connect
    no_authentication = False
    # information disclosure
    information_disclosure = False
    # topics available
    topics_readable = set()
    topics_writable = set()
    sys_topics_readable = set()
    sys_topics_writable = set()
    # Password is required for login
    no_pass = False
    bruteforce_results = [False]
    username_bug = False
    brute_force_cannot_be_executed = False
    password = None
    auth_anyway = False

    # SCRIPT
    
    # get broker IP as string in argv
    broker_ip = sys.argv[1]

    # state 0 -> No username, No password
    state = 0

    # first we sniff on a specific interface (if specified) and we try to intercept credentials
    if interface!=None:
        credentials, clientIds = sniff.sniffing_attack(interface, listening_time, port)

    # try to connect
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    if tls_cert != None:
        if hasattr(ssl, "PROTOCOL_TLS"):
            tls_prot_v = ssl.PROTOCOL_TLS
        else:
            tls_prot_v = ssl.PROTOCOL_TLSv1
        client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_prot_v, ciphers=None)
        client.tls_insecure_set(True)

    # connect to the specified broker
    client.connect(broker_ip,port,60)
    client.loop_start()
    print('Trying to connect...\n')
    sleep(5)
    
    # in case connection worked
    if (no_authentication):
        # Subscribe to all
        client.subscribe('#')

        # Subscribe to SYS topics
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
    
    # in case we were not able to connect first we try to use credentials intercepted with the 
    # sniffing attack (if specified), otherwise we will proceed with the other attacks
    if interface!=None:
        for c in credentials:
            u = c.username
            p = c.password
            print('Trying to connect with username: ' + u + ' and password: ' + p)
            client.username_pw_set(u, p)

            # if the path to a CA certificate is available, we try to connect over TLS
            if tls_cert != None:
                if hasattr(ssl, "PROTOCOL_TLS"):
                    tls_prot_v = ssl.PROTOCOL_TLS
                else:
                    tls_prot_v = ssl.PROTOCOL_TLSv1
                client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_prot_v, ciphers=None)
                client.tls_insecure_set(True)

            client.connect(broker_ip,port)
            client.loop_start()
            
            client.subscribe('#')
            client.subscribe('$SYS/#')
            
            sleep(5)
            
            # if the non intrusive flag was set, we just listen for messages but we don't try to write onto them
            if non_intrusive != True and (len(topics_writable.union(sys_topics_writable))!=0):
                all_topics = topics_readable.union(sys_topics_readable)
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

        client = mqtt.Client()
        client.on_connect = on_connect
        client.on_message = on_message
        client.username_pw_set(username,password=None)

        # if the path to a CA certificate is available, we try to connect over TLS
        if tls_cert != None:
            if hasattr(ssl, "PROTOCOL_TLS"):
                tls_prot_v = ssl.PROTOCOL_TLS
            else:
                tls_prot_v = ssl.PROTOCOL_TLSv1
            client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_prot_v, ciphers=None)
            client.tls_insecure_set(True)

        # connect to the specified broker
        client.connect(broker_ip,port)
        client.loop_start()
        sleep(5)
        client.loop_stop()
        client.disconnect()
        if not no_pass:
            print('\nPerforming brute force...\n')
            # perform brute force
            bruteforce_results = bruteforce.brute_force(broker_ip,port,username,wordlist_path, tls_cert, client_cert)
            username_bug = bruteforce.username_bug(broker_ip,port, tls_cert, client_cert)
                
            if bruteforce_results[0]:
                # state 2 -> username, password
                state = 2

                client = mqtt.Client()
                client.on_connect = on_connect
                client.on_message = on_message
                password = bruteforce_results[1]
                client.username_pw_set(username,password)

                # if the path to a CA certificate is available, we try to connect over TLS
                if tls_cert != None:
                    if hasattr(ssl, "PROTOCOL_TLS"):
                        tls_prot_v = ssl.PROTOCOL_TLS
                    else:
                        tls_prot_v = ssl.PROTOCOL_TLSv1
                    client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_prot_v, ciphers=None)
                    client.tls_insecure_set(True)

                # connect to the specified broker
                client.connect(broker_ip,port)
                client.loop_start()
                sleep(3)
                client.loop_stop()
                client.disconnect()
            else:
                print('[!] Brute force was not successful\n')

        if not ((not bruteforce_results[0]) and state==2):
            client = mqtt.Client()
            client.on_connect = on_connect
            client.on_message = on_message
            if state == 1:
                client.username_pw_set(username,password=None)
            elif state == 2:
                client.username_pw_set(username,password)

            # if the path to a CA certificate is available, we try to connect over TLS
            if tls_cert != None:
                if hasattr(ssl, "PROTOCOL_TLS"):
                    tls_prot_v = ssl.PROTOCOL_TLS
                else:
                    tls_prot_v = ssl.PROTOCOL_TLSv1
                client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_prot_v, ciphers=None)
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
    # in case no writable topics are found, try with a default one
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

        # if there is a topic in which we can write we use that topic
        if len(topics_writable)!=0:
            dos_result = dos.threaded_broker_dos(broker_ip,
                                                 port,
                                                 threads,
                                                 dos_connections,
                                                 topic=next(iter(topics_writable)),
                                                 tls_cert=tls_cert,
                                                 client_cert=client_cert)
        # otherwise we will use an empty string as the topic
        else:
            dos_result = dos.threaded_broker_dos(broker_ip,
                                                 port,
                                                 threads,
                                                 dos_connections,
                                                 tls_cert=tls_cert,
                                                 client_cert=client_cert)


    print('[*] LISTENING TIME:      ' + str(listening_time))
    print('[*] DOING DOS:           ' + str(not dos_connections == None))
    print('[*] DOING BRUTEFORCE:    ' + str(brute_force_dec))
    print('[*] TEXT MESSAGE         ' + text_message+'\n')

    pdfw.add_paragraph("Details of the assessment")
    pdfw.add_to_existing_paragraph("Broker ip: "+str(broker_ip))
    pdfw.add_to_existing_paragraph("Listening time: "+str(listening_time))
    pdfw.add_to_existing_paragraph("Text message: "+str(text_message))
    pdfw.add_to_existing_paragraph("Denial of Service performed: "+str(not dos_connections == None))
    pdfw.add_to_existing_paragraph("Brute force performed: "+str(brute_force_dec))

    # authorization mechanism results
    write_results.authorization_report(pdfw, no_authentication, brocker_info, auth_anyway, interface)

    # information disclosure results
    write_results.information_disclosure_report(pdfw, topics_readable, sys_topics_readable, listening_time, brocker_info, no_authentication)
    write_results.tampering_data_report(pdfw, topics_writable, sys_topics_writable, topics_readable, sys_topics_readable, text_message)

    # fingerprinting
    if brocker_info != None:
        write_results.fingerprinting_report(pdfw, brocker_info)
    
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

        write_results.sniffing_report(pdfw, usernames, passwords, clientIds, listening_time, brocker_info)

    # brute force results
    if brute_force_dec == True and brute_force_cannot_be_executed == False:
        write_results.brute_force_report(pdfw, username, wordlist_path, password, no_pass, brute_force_dec)


    # dos results
    write_results.dos_report(pdfw, dos_connections, brocker_info)

    # malformed data results
    if mal_data!=None:
        write_results.malformed_data_report(pdfw, mal_data, mal_data_topic)

    # function that generates the pdf report
    pdfw.output_pdf()

    # Printing a brief summary of the attacks on the console
    print

    print('**************************************************')
    print('                     REPORT\n')
    print('            Target: '+str(broker_ip))
    print('            Listening time: '+str(listening_time))
    print('**************************************************\n')
    print('     + Authentication required: '+str(not no_authentication)+'\n')
    print('     + Information disclosure:           '+str(information_disclosure))
    if len(topics_readable)>0 or len(sys_topics_readable)>0:
        print('         + # of Topics we read:          '+str(len(topics_readable)))
        print('         + # of Topics we wrote:         '+str(len(topics_writable)))
        print('         + # of SYS Topics we read:      '+str(len(sys_topics_readable)))
        print('         + # of SYS Topics we wrote:     '+str(len(sys_topics_writable)))

        #print('        + Topics in which we read:     '+str(topics_readable))
        #print('        + Topics in which we wrote:    '+str(topics_writable))

        #print('        + SYS topics in which we read:     '+str(sys_topics_readable))
        #print('        + SYS topics in which we wrote:    '+str(sys_topics_writable))
        if(not connected_clients == None):
            print('         + # of Connected Clients:       '+str(connected_clients))
        if(not brocker_info == None):
            print('         + brocker info:                 '+str(brocker_info))
    else:
        print('         + No topics detected')
    print('')

    if (not dos_connections == None):
        print('     + DOS successful:                   '+str(dos_result))
        print('         + # connections for the attack: '+str(dos_connections))
        print('')

    if (brute_force_dec):
        print('     + Brute force successful:           '+str(bruteforce_results[0]))
        print('         + username used:                '+username)
        if no_pass:
            print('     + password not required!')
        if bruteforce_results[0]:
            print('     + password found:   '+str(bruteforce_results[1]))
        if username_bug:
            print('     + ACL bypassed using as username:   "#"')

    print('**************************************************')
