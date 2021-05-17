# MQTTSA

The goal of MQTTSA is to automatically detect misconfigurations in MQTT brokers, to provide a report (in a pdf format) of the potential vulnerabilities, and a list of (high level) mitigation measures to deploy.  

## Install

**MQTTSA** requires (e.g., via `apt`) the following packets: `python3-pip tshark` -- to allow the execution as non-root user, select yes when prompted. Run `make` to install the additional requirements with `pip3` (from `requirements.txt`). If necessary, add the user to the `wireshark` group via `sudo adduser $USER wireshark`.

## Usage

Run the tool by specifying the broker address (IP/hostname): 
`python3 mqttsa.py [ARGUMENTS] {IP_OF_THE_BROKER}`  
The following arguments allow to enable different attacks and customize the analysis: 

```
-h, --help            show this help message and exit
-p PORT               Specify the port (defaults to 1883)
-t LISTENING_TIME     Specify the amount of seconds the tool should intercept messages on wildcard topics (defaults to 60)
-m TEXT_MESSAGE       Specify the text message to publish in intercepted topics (defaults to "testtesttest")
-fc DOS_FOODING_CONN  Specify the amount of connections for the flooding-based DoS (mandatory for flooding-based DoS)
-fcsize DOS_SIZE      Specify the payload size in MB for the flooding-based DoS (defaults to 10)
-sc DOS_SLOW_CONN     Specify the max amount of connections for the slow DoS - 12000 suggested (mandatory for slow DoS)
-u USERNAME           Specify the username (mandatory for Brute-forcing)
-w WORDLIST_PATH      Specify the path to the password wordlist
-i INTERFACE          Specify the interface on which to listen for MQTT packets (mandatory for Sniffing)
-ca CA_CERT           Specify the CA certificate path (mandatory for connecting with TLS)
-cert CLIENT_CERT     Specify the client certificate path
-key CLIENT_KEY       Specify the client key path
--md                  Add flag --md to perform the malformed data test
--ni                  Add flag --ni to perform only non intrusive tests
```

When the analysis is complete, a pdf (called `report.pdf`) is created. In these report are listed the results of the attacks performed by MQTTSA and, based on these results, some high level suggestions to improve the security of the MQTT instance.

## Attacks

The attacks implemented (that can be run individually from the `/src/` folder) are the following:

- Sniffing attack
- Brute Force
- Information Disclosure
- Malformed Data
- Denial of Service

### Sniffing attack

Use the specified interface to intercept MQTT connect packets for credentials: *client ids*, *usernames* and *passwords*. In case these are found, the tool will use them to perform the other attacks (e.g., connect and intercept messages).

### Brute force

Use the given username and a wordlist to perform a bruteforce attack. An example wordlist is provided in `/src/words.txt`.

### Information disclosure

Once the tool manages to connect to the broker, it listens for and parses each received message according to 10 patterns: domain names, IPs and MACs, email addresses, passwords, phone numbers, credit cards and messages containing typical IoT, status and GPS keywords. In case the *non intrusive* mode is specified, it will not attempt to detect ACLs; otherwise it will try to publish on listened topics and wait for the test messages to be received.

### Malformed data

The tool will try to craft malformed packets to try to raise some exceptions in the broker. **This attack might affect the performance of the broker, so do not perform this attack in critical scenarios**.

### Denial of Service

The tool will first attempt to saturate the number of connection (*slow* DoS approach - Ref. to [1] for additional details); then damage the service quality by publishing with many clients heavy payloads. **This attack might affect the performance of the broker, so do not perform this attack in critical scenarios**.

[[1] Vaccari, Ivan & Aiello, Maurizio & Cambiaso, Enrico. (2020). SlowITe, a Novel Denial of Service Attack Affecting MQTT. Sensors. 20. 2932. 10.3390/s20102932](https://www.researchgate.net/publication/341563324_SlowITe_a_Novel_Denial_of_Service_Attack_Affecting_MQTT). 