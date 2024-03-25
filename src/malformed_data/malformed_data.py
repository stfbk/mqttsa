import ssl
import paho.mqtt.client as mqtt
import paho.mqtt.properties as Properties
import argparse

# Allow this module to be executed individually
import sys, os
_, current_module = os.path.split(__file__)
_, exec_module    = os.path.split(sys.argv[0])
if (exec_module == current_module):
    from mqtt5_client import *
else:
    from .mqtt5_client import *

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
    @staticmethod
    def list_to_credentials(array):
        if(isinstance(array, list)):
            credentials = Credentials()
            if(len(array) != 0): 
                c = list(array)[0]   
                if(c.username != None and c.password != None):
                    credentials.add_username(c.username)
                    credentials.add_password(c.password)
            return credentials
        elif(isinstance(array, Credentials)):
            return array
        else:
            return Credentials()

# custom class for storing errors returned when trying the malformed data attack
class MyError:
    def __init__(self, err_value, err_message):
        self.err_value = err_value
        self.err_message = err_message
    
    def __str__(self):
        return f"{self.err_value} : {self.err_message}"

# custom class to store values about the results of the malformed data attack
class Malformed:
    def __init__(self, packet, parameter):
        # the packet under testing (CONNECT, PUBLISH...)
        self.packet = packet
        # the parameter of the packet under testing
        self.parameter = parameter
        # array of MyError objects
        self.errors = []
        # array of values for which there was no error
        self.successes = []

    def add_error(self, error):
        self.errors.append(error)

    def add_success(self, success):
        self.successes.append(success)

mal_data = []

"""Performs the malformed data attack

Parameters:
    host (str): IP address of the broker
    topic (bool): topic in which we try to perform the attack
    tls_cert (str): The path to the CA certificate used to connect over TLS

Returns:
    mal_data ([Malformed]): an array of Malformed objects containing information about
                            the data used to perform the test and the result (it provides
                            also information about the errors)
"""
def malformed_data(host, version, port, topic, tls_cert, client_cert, client_key, credentials):
    print("-----Malformed Properties Test-----")
    # try malformed data for CONNECT packet
    test_connect_packet(host, version, port, topic, tls_cert, client_cert, client_key)
    # try malformed data for PUBLISH packet
    test_publish_packet(host, version, port, topic, tls_cert, client_cert, client_key, credentials)
    # try malformed properties in CONNECT and PUBLISH packets
    if(version == '5'):
        #Format credentials
        my_credentials = Credentials.list_to_credentials(credentials)
        malformed_properties(host, port, PacketTypes.CONNECT, topic, my_credentials, [tls_cert, client_cert, client_key])
        malformed_properties(host, port, PacketTypes.PUBLISH, topic, my_credentials, [tls_cert, client_cert, client_key])
    # return the results of the test
    return mal_data

def malformed_data_5(host, port, tls_cert, client_cert, client_key, credentials):
    #Format credentials
    my_credentials = Credentials.list_to_credentials(credentials)
    res1 = double_properties_test(host, port,  my_credentials, [tls_cert, client_cert, client_key])
    res2 = wrong_properties_test(host, port,  my_credentials, [tls_cert, client_cert, client_key])
    res3 = share_topic_test(host, port, my_credentials, [tls_cert, client_cert, client_key])
    return [res1, res2, res3]

# Function that tests parameters of the CONNECT packet
def test_connect_packet(host, version, port, topic, tls_cert, client_cert, client_key):
    global mal_data
    client = mqtt.Client(protocol = mqtt.MQTTv5 if version == '5' else mqtt.MQTTv311)

    # initialize a 'mal' variable as a Malformed() object passing the name of the parameter we are going to test
    # in this way all the results are related to such parameter because are in the same object
    mal = Malformed("CONNECT", "client_id")
    # the malformed_values function will return the set of malformed values associated in this case to strings
    for value in malformed_values(string=True):
        try:
            if version == 5:
                client.reinitialise(client_id=value, userdata=None)
            else:
                client.reinitialise(client_id=value, clean_session=True, userdata=None)
                
            # if the path to the CA certificate it will try to connect over TLS
            if tls_cert != None:
                client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
                               tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True)
            if version == 5:
                client.connect(host, port, keepalive=60, bind_address="", clean_start = True)
            else:
                client.connect(host, port, keepalive=60, bind_address="")
            client.publish(topic, "test")
            # if successful we add the value to the 'mal' object as a value which didn't generate any error
            mal.add_success(value)
        except:
            # if an error occurs, its message will be stored along with the value that caused it in a MyError object
            err = MyError(value, sys.exc_info()[1])
            mal.add_error(err)
    mal_data.append(mal)

    #Try every malformed value for the clean_session value
    mal = Malformed("CONNECT", "clean_session")
    # the malformed_values function will return the set of malformed values associated in this case to booleans
    for value in malformed_values(boolean=True):
        try:
            if version == 5:
                client.reinitialise(userdata=None)
            else:
                client.reinitialise(clean_session=value, userdata=None)
            # if the path to the CA certificate it will try to connect over TLS
            if tls_cert != None:
                client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
                               tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True)
            
            if version == 5:
                client.connect(host, port, keepalive=60, bind_address="", clean_start = value)
            else:
                client.connect(host, port, keepalive=60, bind_address="")
            
            client.publish(topic, "test")
            # if successful we add the value to the 'mal' object as a value which didn't generate any error
            mal.add_success(value)
        except:
            # if an error occurs, its message will be stored along with the value that caused it in a MyError object
            err = MyError(value, sys.exc_info()[1])
            mal.add_error(err)
    mal_data.append(mal)

    #Try every malformed value for the userdata value
    mal = Malformed("CONNECT", "userdata")
    # the malformed_values function will return the set of malformed values associated in this case to strings
    for value in malformed_values(string=True):
        try:
            if version == 5:
                client.reinitialise(userdata=value)
            else:
                client.reinitialise(clean_session=True, userdata=value)
            # if the path to the CA certificate it will try to connect over TLS
            if tls_cert != None:
                client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
                               tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True)
                
            if version == 5:
                client.connect(host, port, keepalive=60, bind_address="", clean_start = True)
            else:
                client.connect(host, port, keepalive=60, bind_address="")
            
            client.publish(topic, "test")
            # if successful we add the value to the 'mal' object as a value which didn't generate any error
            mal.add_success(value)
        except:
            # if an error occurs, its message will be stored along with the value that caused it in a MyError object
            err = MyError(value, sys.exc_info()[1])
            mal.add_error(err)
    mal_data.append(mal)

    #Try every malformed value for the keepalive value
    mal = Malformed("CONNECT", "keepalive")
    # the malformed_values function will return the set of malformed values associated in this case to integers
    for value in malformed_values(integer=True):
        try:
            if version == 5:
                client.reinitialise(userdata=None)
            else:
                client.reinitialise(clean_session=True, userdata=None)
            # if the path to the CA certificate it will try to connect over TLS
            if tls_cert != None:
                client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
                               tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True)
            
            if version == 5:
                client.connect(host, port, keepalive=value, bind_address="", clean_start = True)
            else:    
                client.connect(host, port, keepalive=value, bind_address="")
            
            client.publish(topic, "test")
            # if successful we add the value to the 'mal' object as a value which didn't generate any error
            mal.add_success(value)
        except:
            # if an error occurs, its message will be stored along with the value that caused it in a MyError object
            err = MyError(value, sys.exc_info()[1])
            mal.add_error(err)
    mal_data.append(mal)

# Function that tests parameters of the PUBLISH packet
def test_publish_packet(host, version, port, topic, tls_cert, client_cert, client_key, credentials):
    global mal_data
    client = mqtt.Client(protocol = mqtt.MQTTv5 if version == '5' else mqtt.MQTTv311)
    # if the path to the CA certificate it will try to connect over TLS
    if tls_cert != None:
            client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
                            tls_version=ssl.PROTOCOL_TLS, ciphers=None)
            client.tls_insecure_set(True)

    # if there are credentials in the 'credentials' variable, we try to connect using them
    if (credentials is not None):
        if (len(credentials) !=0):
            c = list(credentials)[0]
            client.username_pw_set(c.username, c.password)

    client.connect(host, port, keepalive=60, bind_address="")

    #Try every malformed value for the topic value
    mal = Malformed("PUBLISH", "topic")
    # the malformed_values function will return the set of malformed values associated in this case to topics
    for value in malformed_values(topic=True):
        try:
            client.publish(value, payload="test")
            # if successful we add the value to the 'mal' object as a value which didn't generate any error
            mal.add_success(value)
        except:
            # if an error occurs, its message will be stored along with the value that caused it in a MyError object
            err = MyError(value, sys.exc_info()[1])
            mal.add_error(err)
    mal_data.append(mal)

    #Try every malformed value for the payload value
    mal = Malformed("PUBLISH", "payload")
    # the malformed_values function will return the set of malformed values associated in this case to strings
    for value in malformed_values(string=True):
        try:
            client.publish(topic, value)
            # if successful we add the value to the 'mal' object as a value which didn't generate any error
            mal.add_success(value)
        except:
            # if an error occurs, its message will be stored along with the value that caused it in a MyError object
            err = MyError(value, sys.exc_info()[1])
            mal.add_error(err)
    mal_data.append(mal)

    #Try every malformed value for the qos value
    mal = Malformed("PUBLISH", "qos")
    # the malformed_values function will return the set of malformed values associated in this case to integers
    for value in malformed_values(integer=True):
        try:
            client.publish(topic, payload="test", qos=value)
            # if successful we add the value to the 'mal' object as a value which didn't generate any error
            mal.add_success(value)
        except:
            # if an error occurs, its message will be stored along with the value that caused it in a MyError object
            err = MyError(value, sys.exc_info()[1])
            mal.add_error(err)
    mal_data.append(mal)

# function that returns an array of values that might trigger an error. The arrays are related to the type of the value
# to test. If, for example, the value to test is an integer, this function should be called in the following way
# malformed_values(integer=True)
def malformed_values(integer=False, boolean=False, string=False, topic=False):
    if integer == True:
        integer_values = [0, 1, 2, 3, -1, -100, 234, 0.12, -0.12, 89342790812734098172349871230948712093749281374972139471902374097123094871029384709127340987123049710293749128374097239017409237409123749071209347091237490321, -1928349182037498127349871239047092387409723104971230947923749012730497210934871293074923174921379047012347092734]
        return integer_values
    elif boolean == True:
        boolean_values = [True, False, 0, 1, 2, -1]
        return boolean_values
    elif string == True:
        string_values = ["test", "$", "$topic", "", "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"]
        return string_values
    elif topic == True:
        topic_values = ["$","$topic","///////", "/../../../../", "#", "/#/#/#"]
        return topic_values
    else:
        return []

def malformed_values_5(type):
    """ function that returns an array of values that might trigger an error. The arrays are related to the type of the value
        to test. If, for example, the value to test is an integer, this function should be called in the following way:
        malformed_values("Integer")"""
    if "Integer" in type:
        integer_values =  [0, 1, -1, -100, 10, 234, 2048, 0.12, -0.12, 2684354557, -2684354557, "Ciao", "Ciao!"]
        return integer_values
    elif "Byte" in type:
        boolean_values = [True, False, 0, 1, 2, -1]
        return boolean_values
    elif "String" in type:
        string_values = ["test", "$", "$topic", "", "0"*100, "$SYS/#", "#", "/#/#/#", "/"*1024]
        return string_values
    elif "Binary" in type:
        binary_values = [b"test", b"$", b"$topic", b"", b"0"*100, b"$SYS/#", b"#", b"/#/#/#", b"/"*1024]
        return binary_values
    elif "ShareTopic" == type:
        topic_values = ["$share/test", "$share///////", "$share/#", "$share/#/topic", "$share/+/..", "$share/"]
        return topic_values
    else:
        return []

def malformed_properties(host, port, packet_type, topic, credentials, cert_key_paths):
    """Function that tests all properties of a given packet type"""
    global mal_data
    #Get all properties of packet_type
    properties = get_properties_by_packet_type(Properties(packet_type))
    published = disconnected = True
    
    #For every property try every malformed value based on property_type
    for property in properties:
        packet_name = ""
        if(packet_type == 1) : packet_name = "CONNECT"
        if(packet_type == 3) : packet_name = "PUBLISH"
        prop_name = property[0]; prop_type = property[1]
        mal = Malformed(packet_name, prop_name)
        print("Testing "+prop_name+"...")
       
        for value in malformed_values_5(prop_type):
            client = init_mqtt5_client(host, port, 60, "malformed_test", "client_"+prop_name+"_"+str(value), 
                                       connect=(not packet_type == PacketTypes.CONNECT),
                                       credentials=credentials, cert_key_paths=cert_key_paths)
            try:                
                if(packet_type == PacketTypes.CONNECT):
                    client.connect(host, port, keepalive=60, clean_start=True,
                                   properties=gen_properties(packet_type, {prop_name:value}, malformed=True))
                    client.loop_start()
                    wait_for_event(client, Mqtt5Client.CONNECTION)
                    client.publish(topic, "test"+prop_name+"_"+str(value), qos=1)
                    published = wait_for_event(client, Mqtt5Client.PUBLISH)
                
                elif(packet_type == PacketTypes.PUBLISH):
                    wait_for_event(client, Mqtt5Client.CONNECTION)
                    client.publish(topic, "test"+prop_name+"_"+str(value), properties=gen_properties(packet_type, {prop_name:value}, malformed=True), qos=2)
                    published = wait_for_event(client, Mqtt5Client.PUBLISH)                  

                #Check if client is able to publish a message without be disconnected by the broker
                if(published and disconnected and not client.broker_disconnection):
                    # if successful we add the value to the 'mal' object as a value which didn't generate any error
                    mal.add_success(value)
                else:
                    # if the broker disconnects the client, its message will be stored along with the value that caused it in a MyError object
                    err = MyError(value, "Broker Disconnection with reason code "+str(client.reason_disconnection))
                    mal.add_error(err)
                client.loop_stop(); client.__del__()
            except KeyboardInterrupt:
                print("Malformed Properties Test skipped")
                return
            except:
                # if an error occurs, its message will be stored along with the value that caused it in a MyError object
                err = MyError(value, sys.exc_info()[1])
                mal.add_error(err)

        mal_data.append(mal)

def share_topic_test(host, port, credentials, cert_key_paths):
    "Function where a client tries to subscribe to a malformed share topic"
    print("-----Malformed Share Topic Test-----")
    results = {}
    #Get all malformed share topics
    for value in malformed_values_5("ShareTopic"):
        client = init_mqtt5_client(host, port, 60, "share_test", "client_share", malformed=True,
                                    credentials=credentials, cert_key_paths=cert_key_paths)
        
        if(wait_for_event(client, Mqtt5Client.CONNECTION)):
            client.subscribe(value, properties=None)
            #If the client is able to subscribe to the topic set test value True, otherwise False
            results[value] = wait_for_event(client, Mqtt5Client.SUBSCRIBE) and client.subscription_rc == 0
        client.loop_stop(); client.__del__()
    print(results)
    print("------------------------------------")
    return results

def double_properties_test(host, port, credentials, cert_key_paths):
    results = {}
    print("-----Double Properties Test-----")
    
    test1_name = 'SessionExpiryInterval'
    res1 = send_property(host, port, {test1_name:5000}, PacketTypes.CONNECT, credentials=credentials, cert_key_paths=cert_key_paths, malformed=True, duplicate=True)
    results[test1_name] = res1
    print(f"Duplicate {test1_name}: {res1}")
    
    test2_name = 'ResponseTopic'
    res2 = send_property(host, port, {test2_name:"$SYS/topic"}, PacketTypes.PUBLISH, credentials=credentials, cert_key_paths=cert_key_paths, malformed=True, duplicate=True)
    results[test2_name] = res2
    print(f"Duplicate {test2_name}: {res2}")
    
    test3_name = 'TopicAliasMaximum'
    res3 = send_property(host, port, {test3_name:"10"}, PacketTypes.CONNECT, credentials=credentials, cert_key_paths=cert_key_paths, malformed=True, duplicate=True)
    results[test3_name] = res3
    print(f"Duplicate {test3_name}: {res3}")
    print("--------------------------------")

    return results

def wrong_properties_test(host, port, credentials, cert_key_paths):
    results = {}
    print("-----Wrong Packet Test-----")
    property = "SessionExpiryInterval"
    test1_name = property + " in SUBSCRIBE"
    res1 = send_property(host, port, {property: 2048}, PacketTypes.SUBSCRIBE, credentials=credentials, cert_key_paths=cert_key_paths, malformed=True)
    results[test1_name] = res1
    print(f"{test1_name}: {res1}")
    
    property = "SubscriptionIdentifier"
    test2_name = property + " in PUBLISH"
    res2 = send_property(host, port, {property: 1}, PacketTypes.PUBLISH, credentials=credentials, cert_key_paths=cert_key_paths, malformed=True)
    results[test2_name] = res2
    print(f"{test2_name}: {res2}")
    
    property = "SessionExpiryInterval"
    test3_name = property +  " in PUBLISH:"
    res3 = send_property(host, port, {property: 2048}, PacketTypes.PUBLISH, credentials=credentials, cert_key_paths=cert_key_paths, malformed=True)
    results[test3_name] = res3
    print(f"{test3_name}: {res3}")
    
    property = "TopicAlias"
    test4_name = property + " in CONNECT"
    res4 = send_property(host, port, {property: 5}, PacketTypes.CONNECT, credentials=credentials, cert_key_paths=cert_key_paths, malformed=True)
    results[test4_name] = res4
    print(f"{test4_name}: {res4}")
    print("---------------------------")
    
    return results

if __name__ == "__main__":
    # parse args
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(metavar='*broker_address*', type=str, dest='broker_address', help='Specify the broker IP address or hostname')
    parser.add_argument('-v', dest='version', type=str, default = '3.1.1', help='Specify the protocol version (3.1.1 by default)')
    parser.add_argument('-p', type=int, dest='port', default=1883, help='broker port (def. 1883)')

    parser.add_argument('-id', dest = 'clientID', type=str, default=None, help='client ID')
    parser.add_argument('-usr', dest = 'username', type=str, default=None, help='client username')
    parser.add_argument('-pwd', dest = 'password', type=str, default=None, help='client password')

    parser.add_argument('-ca', dest = 'ca_cert_path', type=str, default=None, help='CA certificate path')  
    parser.add_argument('-cert', dest = 'client_cert_path', type=str, default=None, help='Client certificate path')
    parser.add_argument('-key', dest = 'client_key_path', type=str, default=None, help='Client key path')

    parser.add_argument('-t', dest = 'topic', type=str, default="Topic1", help='topic for the test')

    args = parser.parse_args()

    credentials = Credentials()
    if(args.clientID != None):
        credentials.add_clientID(args.clientID)        
    if(args.username != None and args.password != None):
        credentials.add_username(args.username)
        credentials.add_password(args.password)

    credentials_list = []
    credentials_list.append(credentials)
   
    malformed_data(args.broker_address, args.version, args.port, args.topic,
                   credentials=credentials_list,
                   tls_cert = args.ca_cert_path, 
                   client_cert = args.client_cert_path, 
                   client_key = args.client_key_path)
    
    print()
    for malformed in mal_data:
        print(malformed.parameter)
        print("SUCCESS = " + str(malformed.successes))
        print("ERRORS")
        for error in malformed.errors:
            print(error)
        print()
    print("-----------------------------------")