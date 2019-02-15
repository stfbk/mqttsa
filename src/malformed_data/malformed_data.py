import ssl
import sys
import pdf_wrapper as pdfw
import paho.mqtt.client as mqtt

# custom class for storing errors returned when trying the malformed data attack
class MyError:
    def __init__(self, err_value, err_message):
        self.err_value = err_value
        self.err_message = err_message

# custom class to store values about the results of the malformed data attack
class Malformed:
    def __init__(self, packet, parameter):
        self.packet = packet
        self.parameter = parameter
        self.errors = []
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
def malformed_data(host, port, topic, tls_cert, client_cert, client_key, credentials):
    # try malformed data for CONNECT packet
    test_connect_packet(host, port, topic, tls_cert, client_cert, client_key)
    # try malformed data for PUBLISH packet
    test_publish_packet(host, port, topic, tls_cert, client_cert, client_key, credentials)
    # return the results of the test
    return mal_data

def test_connect_packet(host, port, topic, tls_cert, client_cert, client_key):
    global mal_data
    client = mqtt.Client()

    # initialize a 'mal' variable as a Malformed() object passing the name of the parameter we are going to test
    # in this way all the results are related to such parameter because are in the same object
    mal = Malformed("CONNECT", "client_id")
    # the malformed_values function will return the set of malformed values associated in this case to strings
    for value in malformed_values(string=True):
        try:
            client.reinitialise(client_id=value, clean_session=True, userdata=None)
            # if the path to the CA certificate it will try to connect over TLS
            if tls_cert != None:
			client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
					tls_version=ssl.PROTOCOL_TLSv1, ciphers=None)
			client.tls_insecure_set(True)
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
            client.reinitialise(clean_session=value, userdata=None)
            # if the path to the CA certificate it will try to connect over TLS
            if tls_cert != None:
			client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
					tls_version=ssl.PROTOCOL_TLSv1, ciphers=None)
			client.tls_insecure_set(True)
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
            client.reinitialise(clean_session=True, userdata=value)
            # if the path to the CA certificate it will try to connect over TLS
            if tls_cert != None:
			client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
					tls_version=ssl.PROTOCOL_TLSv1, ciphers=None)
			client.tls_insecure_set(True)
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
            client.reinitialise(clean_session=True, userdata=None)
            # if the path to the CA certificate it will try to connect over TLS
            if tls_cert != None:
			client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
					tls_version=ssl.PROTOCOL_TLSv1, ciphers=None)
			client.tls_insecure_set(True)
            client.connect(host, port, keepalive=value, bind_address="")
            client.publish(topic, "test")
            # if successful we add the value to the 'mal' object as a value which didn't generate any error
            mal.add_success(value)
        except:
            # if an error occurs, its message will be stored along with the value that caused it in a MyError object
            err = MyError(value, sys.exc_info()[1])
            mal.add_error(err)
    mal_data.append(mal)

def test_publish_packet(host, port, topic, tls_cert, client_cert, client_key, credentials):
    global mal_data
    client = mqtt.Client()
    # if the path to the CA certificate it will try to connect over TLS
    if tls_cert != None:
            client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
                            tls_version=ssl.PROTOCOL_TLSv1, ciphers=None)
            client.tls_insecure_set(True)
            
    if (len(credentials) !=0):
            client.username_pw_set(credentials[0].username, credentials[0].password)
    
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
        string_values = ["test", "", "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"]
        return string_values
    elif topic == True:
        topic_values = ["///////", "/../../../../", "#", "/#/#/#"]
        return topic_values
    else:
        return []
