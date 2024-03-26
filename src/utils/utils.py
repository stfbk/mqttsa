import argparse

# Create parser with parameters options
def create_parser():

    # parse the options for the tool
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(metavar='*broker_address*', type=str, dest='broker_address', help='Specify the broker IP address or hostname')
    
    parser.add_argument('-p', dest='port', type=int, help='Specify the port (defaults to 1883)')
    
    parser.add_argument('-v', dest='version', type=str, default = '5', help='Specify the protocol version (5 by default)')
    
    parser.add_argument('-t', dest='listening_time', type=int, help='Specify the amount of seconds the tool should intercept messages on wildcard topics (defaults to 60)')

    parser.add_argument('-m', dest='text_message', type=str, help='Specify the text message to publish in intercepted topics (defaults to "testtesttest")')

    parser.add_argument('-fc', dest='dos_fooding_conn', type=int, help='Specify the amount of connections for the flooding-based DoS (mandatory for flooding-based DoS)')
    
    parser.add_argument('-fcsize', dest='dos_size', type=int, default = 10, help='Specify the payload size in MB for the flooding-based DoS (defaults to 10)')
    
    parser.add_argument('-sc', dest='dos_slow_conn', type=int, help='Specify the max amount of connections for the slow DoS - 12000 suggested (mandatory for slow DoS)')
    
    parser.add_argument('-mq', dest='max_queue', type=int, help='Specify the number of messages to test the max number of messages queued by the browser - 1000 suggested (mandatory to perform the test)')
    
    parser.add_argument('-mp', dest='max_payload', type=int, help='Specify the payload size to test the max supported payload - 255 suggested (mandatory to perform the test)')
    
    parser.add_argument('-u', dest='username', type=str, help='Specify the username (mandatory for Brute-forcing)')

    parser.add_argument('-w', dest='wordlist_path', type=str, help='Specify the path to the password wordlist')

    parser.add_argument('-i', dest='interface', type=str, help='Specify the interface on which to listen for MQTT packets (mandatory for Sniffing)')

    parser.add_argument('-ca', dest='ca_cert', type=str , help='Specify the CA certificate path (mandatory for connecting with TLS)')

    parser.add_argument('-cert', dest='client_cert', type=str , help='Specify the client certificate path')
    
    parser.add_argument('-key', dest='client_key', type=str , help='Specify the client key path')
        
    parser.add_argument('--md', dest='malformed_data', action='store_true', help='Add flag --md to perform the malformed data test')

    parser.add_argument('--ni', dest='non_intrusive', action='store_true', help='Add flag --ni to perform only non intrusive tests')

    parser.add_argument('-mup', dest = 'max_user_properties', type=int, help='Specify the max number of user properties to include in a message for User Properties Test (100000 suggested - multiples of 10)')
    
    return parser
