import ssl
import paho.mqtt.client as mqtt
from paho.mqtt.reasoncodes import ReasonCodes
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from time import sleep

class Mqtt5Client:
    CONNECTION = 0; DISCONNECTION = 1; PUBLISH = 2; SUBSCRIBE = 3; UNSUBSCRIBE = 4; MESSAGE = 5

def on_connect(client, userdata, flags, reasonCode, properties):
    client.on_connect_received = True

def on_disconnect(client, userdata, reasonCode, properties):
    client.on_disconnect_received = True
    if(not client.ready_to_disconnect):
        print("Broker Disconnection...")
        client.broker_disconnection = True
        client.reason_disconnection = reasonCode

def on_publish(client, userdata, mid):    
    client.on_publish_received = True

def on_subscribe(client, userdata, mid, reasonCodes, properties):
    client.on_subscribe_received = True
    client.subscription_rc = reasonCodes[0]

def on_unsubscribe(client, userdata, mid, reasonCodes, properties):
    client.on_unsubscribe_received = True

def on_message(client, userdata, msg):    
    client.received_payload = True


def init_parameters(client):
    client.on_connect_received = False
    client.on_disconnect_received = False
    client.on_publish_received = False
    client.on_subscribe_received = False
    client.on_unsubscribe_received = False
    client.received_payload = False

def set_mqtt5_callbacks_and_parameters(client, test_name, credentials, cert_key_paths):
    #Set username, password, and eventually the certificate and keys (only the clientID must be unique)
    if (credentials != None and not credentials.empty):
        client.username_pw_set(credentials.username, credentials.password)
    if (cert_key_paths != None and cert_key_paths[0]!=None):
        client.tls_set(cert_key_paths[0], cert_key_paths[1], cert_key_paths[2], ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
        client.tls_insecure_set(True) #allow to test scenarios with self-signed certificates

    client.test_name = test_name
    
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    client.on_subscribe = on_subscribe
    client.on_unsubscribe = on_unsubscribe
    client.on_message = on_message
    
    init_parameters(client)

    client.subscription_rc = None
    client.ready_to_disconnect = False
    client.reason_disconnection = None
    client.broker_disconnection = False

def init_mqtt5_client(host, port, keepalive, test_name, cID="", clean=1, conn_properties=None, 
                      will_topic=None, will_payload=None, will_properties=None, connect=True, 
                      credentials=None, cert_key_paths=None):
    '''Initialize a MQTT 5 client and start the connection if specified

       The flag malformed specifies if the client intends to send malformed packets
    '''
    client = mqtt.Client(cID, protocol=mqtt.MQTTv5)
    set_mqtt5_callbacks_and_parameters(client, test_name, credentials, cert_key_paths)
    
    if(will_topic != None):
        client.will_set(will_topic, payload=will_payload, properties=will_properties)
   
    if(connect):
        client.connect(host, port, keepalive, clean_start = clean, properties=conn_properties)
        client.loop_start()
    
    return client

def wait_for_event(client, event_id, timeout=10):
    """Waits an occurence of an event for a client.

    event_id = {
        0 : on_connect_received,
        1 : on_disconnect_received,
        2 : on_publish_received,
        3 : on_subscribe_received,
        4 : on_unsubscribe_received,
        5 : received_payload
    }"""
    timeout_timer = 0
    event = False
    while(timeout_timer < timeout):
        #If the broker disconnects the client return
        if(client.broker_disconnection):
            return False
        if(event_id == Mqtt5Client.CONNECTION):
            event = client.on_connect_received
        if(event_id == Mqtt5Client.DISCONNECTION):
            event = client.on_disconnect_received
        if(event_id == Mqtt5Client.PUBLISH):
            event = client.on_publish_received
        if(event_id == Mqtt5Client.SUBSCRIBE):
            event = client.on_subscribe_received
        if(event_id == Mqtt5Client.UNSUBSCRIBE):
            event = client.on_unsubscribe_received
        if(event_id == Mqtt5Client.MESSAGE):
            event = client.received_payload
        if (event):
            break
        else:
            timeout_timer +=1
            sleep(1)     
    return not (timeout_timer == timeout)

def disconnect_client(client, reason_code=ReasonCodes(PacketTypes.DISCONNECT, "Normal disconnection", 0), properties=None):
    client.ready_to_disconnect = True
    client.disconnect(reason_code, properties=properties)
    client.loop_stop()

def gen_properties(packetType, properties_dict):
    """ Function which permits to generate properties for a MQTT 5 packet. \n
        properties_dict = {"PropertyName" : property_value, ...}
        malformed --> specify if the properties' values are malformed \n
        duplicate --> specify if the properties' have to be sent twice (also malformed has to be set to True) \n
    """
    properties = Properties(packetType)
    for key in properties_dict.keys():
        setattr(properties, key, properties_dict[key])
    return properties

def send_property(host, port, properties_dict, packet_type, credentials=None, cert_key_paths=None):
    """ Function where a client sends a packet packet_type using properties specified in properties_dict.
    It returns the result of the packet sending. \n
    properties_dict = {"PropertyName" : property_value, ...} """
    result = None    
    test = ""
    client = init_mqtt5_client(host, port, 60, test, "client_"+test, connect=(not packet_type == PacketTypes.CONNECT),
                               credentials=credentials, cert_key_paths=cert_key_paths)   
    
    if(packet_type == PacketTypes.CONNECT or wait_for_event(client, Mqtt5Client.CONNECTION)):
        event = ""
        if(packet_type == PacketTypes.CONNECT):
            client.connect(host, port, keepalive=10, bind_address="", clean_start=True,
                            properties=gen_properties(packet_type, properties_dict))
            client.loop_start()
            event = Mqtt5Client.CONNECTION
            wait_for_event(client, Mqtt5Client.CONNECTION)
        elif(packet_type == PacketTypes.PUBLISH):
            client.publish("topic/test", "Ciao", qos=2, properties=gen_properties(packet_type, properties_dict))
            event = Mqtt5Client.PUBLISH
        elif(packet_type == PacketTypes.SUBSCRIBE):
            client.subscribe("topic/test", properties=gen_properties(packet_type, properties_dict))
            event = Mqtt5Client.SUBSCRIBE
        elif(packet_type == PacketTypes.UNSUBSCRIBE):
            client.subscribe("topic/test")
            client.unsubscribe("topic/test", properties=gen_properties(packet_type, properties_dict))
            event = Mqtt5Client.UNSUBSCRIBE
        elif(packet_type == PacketTypes.DISCONNECT):
            client.disconnect(properties=gen_properties(packet_type, properties_dict))
            event = Mqtt5Client.DISCONNECTION
        result = wait_for_event(client, event)
        client.loop_stop(); client.__del__()
    return result



def get_key(val, dict):
    """Given a dictionary and a value returns the first key that matches with the value"""
    for key, value in dict.items():
         if val == value:
             return key
    return "Key does not exist"

def get_properties_by_packet_type(prop):
    """Given a packet type returns all the properties supported by the packet type"""
    propsByType = []
    for p in prop.properties:
        propertyName = get_key(p, prop.names).replace(" ", "")
        propertyType = prop.types[prop.properties[p][0]]
        if(prop.packetType in prop.properties[p][1] and not prop.allowsMultiple(propertyName)):
            propsByType.append((propertyName, propertyType))
    return propsByType