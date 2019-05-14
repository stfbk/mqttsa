import utils.utils as utils
import bruteforce.brute_force as bruteforce
import dos.broker_dos as dos
import pdf_wrapper.pdf_wrapper as pdfw
import pdf_wrapper.write_results as write_results
import sniff.sniff_packets as sniff
import os
import re
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
    #temp    brute_force_dec = False
        # we create a special flag to have an appropriate section in the final report
    #temp    brute_force_cannot_be_executed = True
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
    global broker_info
    global pattern_iot_2
    global text_message
    
    # print message and topic
    try:
        payload = message.payload.decode("utf-8")
        print('message received '+ payload)
    except:
        payload = str(message.payload, 'utf-8')
        print('message received but cannot decode as utf-8: ' + payload)

    # If we can read, add in readable set
    if '$SYS' in str(message.topic):
        sys_topics_readable.add(str(message.topic.replace('#','')))
        if(connected_clients == None and str(message.topic) == '$SYS/broker/clients/connected'):
            connected_clients = payload
        if(broker_info == None and str(message.topic) == '$SYS/broker/version'):
            broker_info = payload
    else:
        # add topic in the set of topic
        topics_readable.add(str(message.topic.replace('#','')))

    information_disclosure = True

    parse_message(payload)
    if (pattern_iot_2.match(message.topic)):
        iot.append(payload)  
    
    # If we found the test message, we can write, so add to writable list
    try:
        if (text_message==payload):
            if '$SYS' in str(message.topic):
                sys_topics_writable.add(str(message.topic))
            else:
                # add topic in the set of topic
                topics_writable.add(str(message.topic))
    except:
        pass

def parse_message(message):
    global mac_address
    global pattern_mac_address
    global ipv4
    global pattern_ipv4
    global domain_names
    global pattern_domain_names
    global email
    global pattern_email
    global passw
    global pattern_passw
    global iot
    global pattern_iot
    global pattern_iot_2
    global msg
    global pattern_msg
    global status
    global pattern_status
    global endpoint
    global pattern_endpoint
    global dates
    global pattern_dates
    global phones
    global pattern_phones
    global cards
    global pattern_cards
    global dir
    global pattern_dir
    global gps
    global pattern_gps
    global test
    global pattern_test
    global raw_messages

    if (pattern_test.match(message)):
        test.append(message)
    if (pattern_domain_names.match(message)):
        domain_names.append(message)
    if (pattern_email.match(message)):
        email.append(message)
    if (pattern_passw.match(message)):
        passw.append(message)
    if (pattern_iot.match(message)):
        iot.append(message)      
    if (pattern_msg.match(message)):
        msg.append(message)
    if (pattern_status.match(message)):
        status.append(message)
    if (pattern_endpoint.match(message)):
        endpoint.append(message)
    if (pattern_dates.match(message)):
        dates.append(message)
    if (pattern_phones.match(message)):
        phones.append(message)
    if (pattern_cards.match(message)):
        cards.append(message)
    if (pattern_dir.match(message)):
        dir.append(message)
    if (pattern_gps.match(message)):
        gps.append(message)
    if (pattern_mac_address.match(message)):
        mac_address.append(message)
    if (pattern_ipv4.match(message)):
        ipv4.append(message)
        
    raw_messages.append(message)
    
def save_list(list, type):
    with open('messages/'+type+'.txt', 'w', encoding='utf-8') as f:
        for item in list:
            f.write("%s\n" % item)
    
if __name__== "__main__":
    global topics_readable
    global topics_writable
    global sys_topics_readable
    global sys_topics_writable
    global information_disclosure
    global brute_force_cannot_be_executed
    global connected_clients
    global broker_info
    
    #Define regex patters to parse intercepted messages
    pattern_test = re.compile("^([A-Z][0-9]+)+$")
    # Regex for Mac addresses
    pattern_mac_address = re.compile("([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])")
    # Regex for IPv4 addresses
    pattern_ipv4 = re.compile("([0-9]{1,3}[\.]){3}[0-9]{1,3}")
    # Regex for Domain names
    pattern_domain_names = re.compile("(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?")
    # Regex for email addresses
    pattern_email = re.compile("\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
    # Regex for "pass/pss/key"
    pattern_passw = re.compile("(pass|pss|key)")
    # Regex for "device/iot/board"
    pattern_iot = re.compile("(device|iot|board)")
    # Regex from MQTT PWN
    pattern_iot_2 = re.compile("(openHAB|HomeAssistant|Domoticz|HomeBridge|HomeSeer|SmartThings|SonWEB|Yeti|NodeRed|harmony|iobroker|zwave|sonoff|itead|owntracks)")
    # Regex for "message/msg"
    pattern_msg = re.compile("(message|msg)")
    # Regex for "online/offline/state/statu"
    pattern_status = re.compile("(online|offline|state|statu)")
    # Regex for "endpoint/end-point/api"
    pattern_endpoint = re.compile("(endpoint|end\-point|api)")
    # Regex for dates
    pattern_dates = re.compile("(([1-9]|[0-2][0-9]|(3)[0-1])(\/|\-|\.|\\\\)((0)?[1-9]|((1)[0-2]))(\/|\-|\.|\\\\)[0-9]{2,4})|(([0-9]{2,4})(\/|\-|\.|\\\\)(((0)?[1-9])|((1)[0-2]))(\/|\-|\.|\\\\)([1-9]|[0-2][0-9]|(3)[0-1]))")
    # Regex for phone numbers with country codes
    pattern_phones = re.compile("(\+263[0-9]{5,}|\+260[0-9]{5,}|\+967[0-9]{5,}|\+212[0-9]{5,}|\+681[0-9]{5,}|\+1-340[0-9]{5,}|\+84[0-9]{5,}|\+58[0-9]{5,}|\+379[0-9]{5,}|\+678[0-9]{5,}|\+998[0-9]{5,}|\+1[0-9]{5,}|\+598[0-9]{5,}|\+380[0-9]{5,}|\+44[0-9]{5,}|\+256[0-9]{5,}|\+971[0-9]{5,}|\+688[0-9]{5,}|\+1-649[0-9]{5,}|\+993[0-9]{5,}|\+90[0-9]{5,}|\+216[0-9]{5,}|\+1-868[0-9]{5,}|\+676[0-9]{5,}|\+690[0-9]{5,}|\+228[0-9]{5,}|\+66[0-9]{5,}|\+255[0-9]{5,}|\+992[0-9]{5,}|\+886[0-9]{5,}|\+963[0-9]{5,}|\+41[0-9]{5,}|\+46[0-9]{5,}|\+268[0-9]{5,}|\+47[0-9]{5,}|\+597[0-9]{5,}|\+249[0-9]{5,}|\+1-784[0-9]{5,}|\+508[0-9]{5,}|\+590[0-9]{5,}|\+1-758[0-9]{5,}|\+1-869[0-9]{5,}|\+290[0-9]{5,}|\+94[0-9]{5,}|\+34[0-9]{5,}|\+211[0-9]{5,}|\+82[0-9]{5,}|\+27[0-9]{5,}|\+252[0-9]{5,}|\+677[0-9]{5,}|\+386[0-9]{5,}|\+421[0-9]{5,}|\+1-721[0-9]{5,}|\+65[0-9]{5,}|\+232[0-9]{5,}|\+248[0-9]{5,}|\+381[0-9]{5,}|\+221[0-9]{5,}|\+966[0-9]{5,}|\+239[0-9]{5,}|\+378[0-9]{5,}|\+685[0-9]{5,}|\+590[0-9]{5,}|\+250[0-9]{5,}|\+7[0-9]{5,}|\+40[0-9]{5,}|\+262[0-9]{5,}|\+974[0-9]{5,}|\+1-787[0-9]{5,}|1-939[0-9]{5,}|\+351[0-9]{5,}|\+48[0-9]{5,}|\+64[0-9]{5,}|\+63[0-9]{5,}|\+51[0-9]{5,}|\+595[0-9]{5,}|\+675[0-9]{5,}|\+507[0-9]{5,}|\+970[0-9]{5,}|\+680[0-9]{5,}|\+92[0-9]{5,}|\+968[0-9]{5,}|\+47[0-9]{5,}|\+850[0-9]{5,}|\+1-670[0-9]{5,}|\+683[0-9]{5,}|\+234[0-9]{5,}|\+227[0-9]{5,}|\+505[0-9]{5,}|\+64[0-9]{5,}|\+687[0-9]{5,}|\+599[0-9]{5,}|\+31[0-9]{5,}|\+977[0-9]{5,}|\+674[0-9]{5,}|\+264[0-9]{5,}|\+258[0-9]{5,}|\+212[0-9]{5,}|\+1-664[0-9]{5,}|\+382[0-9]{5,}|\+976[0-9]{5,}|\+377[0-9]{5,}|\+373[0-9]{5,}|\+691[0-9]{5,}|\+52[0-9]{5,}|\+262[0-9]{5,}|\+230[0-9]{5,}|\+222[0-9]{5,}|\+692[0-9]{5,}|\+356[0-9]{5,}|\+223[0-9]{5,}|\+960[0-9]{5,}|\+60[0-9]{5,}|\+265[0-9]{5,}|\+261[0-9]{5,}|\+389[0-9]{5,}|\+853[0-9]{5,}|\+352[0-9]{5,}|\+370[0-9]{5,}|\+423[0-9]{5,}|\+218[0-9]{5,}|\+231[0-9]{5,}|\+266[0-9]{5,}|\+961[0-9]{5,}|\+371[0-9]{5,}|\+856[0-9]{5,}|\+996[0-9]{5,}|\+965[0-9]{5,}|\+383[0-9]{5,}|\+686[0-9]{5,}|\+254[0-9]{5,}|\+7[0-9]{5,}|\+962[0-9]{5,}|\+44-1534[0-9]{5,}|\+81[0-9]{5,}|\+1-876[0-9]{5,}|\+225[0-9]{5,}|\+39[0-9]{5,}|\+972[0-9]{5,}|\+44-1624[0-9]{5,}|\+353[0-9]{5,}|\+964[0-9]{5,}|\+98[0-9]{5,}|\+62[0-9]{5,}|\+91[0-9]{5,}|\+354[0-9]{5,}|\+36[0-9]{5,}|\+852[0-9]{5,}|\+504[0-9]{5,}|\+509[0-9]{5,}|\+592[0-9]{5,}|\+245[0-9]{5,}|\+224[0-9]{5,}|\+44-1481[0-9]{5,}|\+502[0-9]{5,}|\+1-671[0-9]{5,}|\+1-473[0-9]{5,}|\+299[0-9]{5,}|\+30[0-9]{5,}|\+350[0-9]{5,}|\+233[0-9]{5,}|\+49[0-9]{5,}|\+995[0-9]{5,}|\+220[0-9]{5,}|\+241[0-9]{5,}|\+689[0-9]{5,}|\+33[0-9]{5,}|\+358[0-9]{5,}|\+679[0-9]{5,}|\+298[0-9]{5,}|\+500[0-9]{5,}|\+251[0-9]{5,}|\+372[0-9]{5,}|\+291[0-9]{5,}|\+240[0-9]{5,}|\+503[0-9]{5,}|\+20[0-9]{5,}|\+593[0-9]{5,}|\+670[0-9]{5,}|\+1-809[0-9]{5,}|1-829[0-9]{5,}|1-849[0-9]{5,}|\+1-767[0-9]{5,}|\+253[0-9]{5,}|\+45[0-9]{5,}|\+420[0-9]{5,}|\+357[0-9]{5,}|\+599[0-9]{5,}|\+53[0-9]{5,}|\+385[0-9]{5,}|\+506[0-9]{5,}|\+682[0-9]{5,}|\+243[0-9]{5,}|\+242[0-9]{5,}|\+269[0-9]{5,}|\+57[0-9]{5,}|\+61[0-9]{5,}|\+61[0-9]{5,}|\+86[0-9]{5,}|\+56[0-9]{5,}|\+235[0-9]{5,}|\+236[0-9]{5,}|\+1-345[0-9]{5,}|\+238[0-9]{5,}|\+1[0-9]{5,}|\+237[0-9]{5,}|\+855[0-9]{5,}|\+257[0-9]{5,}|\+95[0-9]{5,}|\+226[0-9]{5,}|\+359[0-9]{5,}|\+673[0-9]{5,}|\+1-284[0-9]{5,}|\+246[0-9]{5,}|\+55[0-9]{5,}|\+267[0-9]{5,}|\+387[0-9]{5,}|\+591[0-9]{5,}|\+975[0-9]{5,}|\+1-441[0-9]{5,}|\+229[0-9]{5,}|\+501[0-9]{5,}|\+32[0-9]{5,}|\+375[0-9]{5,}|\+1-246[0-9]{5,}|\+880[0-9]{5,}|\+973[0-9]{5,}|\+1-242[0-9]{5,}|\+994[0-9]{5,}|\+43[0-9]{5,}|\+61[0-9]{5,}|\+297[0-9]{5,}|\+374[0-9]{5,}|\+54[0-9]{5,}|\+1-268[0-9]{5,}|\+672[0-9]{5,}|\+1-264[0-9]{5,}|\+244[0-9]{5,}|\+376[0-9]{5,}|\+1-684[0-9]{5,}|\+213[0-9]{5,}|\+355[0-9]{5,}|\+93[0-9]{5,})")
    # Regex for mastercard/visa/american express numbers
    pattern_cards = re.compile("(^4[0-9]{12}(?:[0-9]{3})?$|^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$|^3[47][0-9]{13}$|^3(?:0[0-5]|[68][0-9])[0-9]{11}$|^6(?:011|5[0-9]{2})[0-9]{12}$)")
    # Regex for directories
    pattern_dir = re.compile("((\.)*((\\\\)+[A-Za-z0-9_\s]{1,})+(\.[A-Za-z0-9_\s]{1,})?)|((\.)*((\/)+[A-Za-z0-9_\s]{1,})+(\.[A-Za-z0-9_\s]{1,})?|path)")
    # Regex for "lat/long/loc"
    pattern_gps = re.compile("(lat|lon|loc)")
    
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
        client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
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
                client.tls_set(tls_cert, client_cert, client_key, ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True)

            client.connect(broker_ip,port)
            client.loop_start()
            
            client.subscribe('#')
            client.subscribe('$SYS/#')
            
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

        client = mqtt.Client()
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
        if not no_pass:
            print('\nPerforming brute force...\n')
            # perform brute force
            bruteforce_results = bruteforce.brute_force(broker_ip,port,username,wordlist_path, tls_cert, client_cert,client_key)
            username_bug = bruteforce.username_bug(broker_ip,port, tls_cert, client_cert, client_key)
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
    if brute_force_dec == True and brute_force_cannot_be_executed == False:
        write_results.brute_force_report(pdfw, username, wordlist_path, password, no_pass, brute_force_dec)

    # dos results
    write_results.dos_report(pdfw, dos_connections, broker_info)

    # malformed data results
    if mal_data!=None:
        write_results.malformed_data_report(pdfw, mal_data, mal_data_topic)

    # function that generates the pdf report
    pdfw.output_pdf()

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
        if(not broker_info == None):
            print('         + broker info:                 '+str(brcker_info))
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
