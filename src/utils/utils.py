import optparse

# Create parser with parameters options
def create_parser():

    # parse the options for the tool
    parser = optparse.OptionParser('Usage: python mqtt.py *broker_ip* [ARGS]')

    # use '-t' to specify the seconds listening to the channel, default is 60
    parser.add_option('-t', dest='listening_time', type='int', help='Specify the amount of seconds the tool should listen in the channel, default: 60')

    # use '-m' to specify the text message, if not specified: 'testtesttest'
    parser.add_option('-m', dest='text_message', type='string', help='Specify the text message, if not specified: "testtesttest"')

    # use '-d' to specify the connections to send to perform dos, if not specified: no dos
    parser.add_option('-c', dest='dos_connections', type='int', help='Specify the amount of connections to perform the DoS test, if not specified: no DoS')

    # use '-u' to specify the username for the brute force test, if not specified: no brute force attack is performed
    parser.add_option('-u', dest='username', type='string', help='Specify the username, if not specified: no brute force test')

    # use '-w' to specify the path to the wordlist for the brute force test, if not specified: no brute force attack is performed
    parser.add_option('-w', dest='wordlist_path', type='string', help='Specify the path to the wordlist, if not specified: no brute force')

    # use '-x' to specify the threads for the brute force, if not specified: 1
    parser.add_option('-x', dest='threads',type='int',help='Specify the number of threads for the Denial of Service test, if not specified: 10')

    # use '-i' to specify the interface for the sniffing test, if not specified: no sniffing test is performed
    parser.add_option('-i', dest='interface',type='string',help='Specify the interface for the sniffing test, if not specified: no sniffing test')

    # use '-p' to specify the port, if not specified: 1883
    parser.add_option('-p', dest='port',type='int',help='Specify the port, if not specified: 1883')

    # use '--md' to perform the malformed data test 
    parser.add_option('--md', dest='malformed_data', action='store_true',help='Add flag --md to perform the malformed data test')

    # use '--ni' to perform non intrusive tests
    parser.add_option('--ni', dest='non_intrusive', action='store_true',help='Add flag --ni to perform non intrusive tests')

    # use '--tls' to insert the path for a CA certificate to use to connect using tls
    parser.add_option('--tls', dest='tls_cert', type='string' ,help='Specify the path for a CA certificate to use to connect using tls')

    # use '--cert' to insert the path for a client certificate
    parser.add_option('--cert', dest='client_cert', type='string' ,help='Specify the path for a client certificate to use to connect using tls')
    
    # use '--key' to insert the path for a client key
    parser.add_option('--key', dest='client_key', type='string' ,help='Specify the path of the client key associated to its certificate')
    
    return parser
