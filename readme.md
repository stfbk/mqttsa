# MQTTSA

The goal of MQTTSA is to automatically detect misconfigurations in MQTT brokers, to provide a report (in a pdf format) of the potential vulnerabilities, and a list of (high level) measures to deploy for mitigation.  

## Install

**MQTTSA** requires (e.g. via `apt`) the following packets: `python3-pip tshark` -- to allow the execution as non-root user, select yes when prompted. Run `make` to install the additional requirements with `pip3` (from `requirements.txt`). If necessary, add the user to the wireshark group via `sudo adduser $USER wireshark`.

## Usage

Run the tool with the following command specifying the IP address of the broker:  
`python3 mqtt.py {IP_OF_THE_BROKER}`  
The following arguments are available to set specific parameters of the execution or to enable some attacks:  

```
-h, --help          Show this help message and exit  
-t LISTENING_TIME   Specify the amount of seconds the tool should listen in the channel, default: 60  
-m TEXT_MESSAGE     Specify the text message, if not specified: "testtesttest"  
-c DOS_CONNECTIONS  Specify the amount of connections to perform the DoS attack, if not specified: no DoS  
-u USERNAME         Specify the username, if not specified: no brute force attack  
-w WORDLIST_PATH    Specify the path to the wordlist, if not specified: no brute force  
-x THREADS          Specify the number of threads for the brute force attack, if not specified: 10  
-i INTERFACE        Specify the interface for the sniffing attack, if not specified: no sniffing attack  
-p PORT             Specify the port, if not specified: 1883  
--md                Add flag --md to perform the malformed data attack  
--ni                Add flag --ni to perform non intrusive attacks (not sending messages in case some topics are vulnerable)  
--tls               Specify the path for a CA certificate to use when connecting with TLS. If required by the brocker, specify also the path to a client certificate and key with, respectively, the "--cert" and "--key" options
```

When the analysis is complete, a pdf (called `report.pdf`) is created. In these report are listed the results of the attacks performed by MQTTSA and, based on these results, some high level suggestions to improve the security of the MQTT instance.

## Attacks

The attacks implemented are the following:

- Sniffing attack
- Brute Force
- Information Disclosure
- Malformed Data
- Denial of Service

### Sniffing attack

Use the specified interface to intercept MQTTSA packets and look for credentials (*client ids* or *usernames*). In case these are found, the tool will use them to try to connect to the broker.

### Brute force

Use the given username and wordlist to perform a bruteforce attack. A simple wordlist is provided (`/src/words.txt`).

### Information disclosure

The tool will try to intercept messages coming from the MQTT broker and identify the vulnerable topics. In case the *non intrusive* mode is not specified, the tool will also try to write in this topic, to check if attackers will be able to send messages on the vulnerable topics.

### Malformed data

The tool will try to craft malformed packets to try to raise some errors in the broker. **This attack might affect the performance of the broker, so do not perform this attack in critical scenarios**.

### Denial of Service

The tool will send **many** requests to exhaust the broker resources and check if this creates a notable delay. **This attack might affect the performance of the broker, so do not perform this attack in critical scenarios**.
