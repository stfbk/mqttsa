import struct
import sys
from paho.mqtt.properties import Properties, VariableByteIntegers


# Override topic checks in paho.mqtt.client 
@staticmethod
def _filter_wildcard_len_check(sub):
    return 0



def writeInt16(length):
    # serialize a 16 bit integer to network format
    try:
        return bytearray(struct.pack("!H", length))
    except:
        return writeInt32(length)

def writeInt32(length):
    # serialize a 32 bit integer to network format
    if(isinstance(length, int) and (length > -2147483648 and length < 2147483648)):
        #return bytearray(struct.pack("!L", length))
        return bytearray(struct.pack("!l", length))
    elif(isinstance(length, int)):
        return bytearray(struct.pack("!q", length))
    elif(isinstance(length, float)):
        return bytearray(struct.pack("!f", length))
    else:
        return bytearray(str(length), 'utf-8')

def writeUTF(data):
    # data could be a string, or bytes.  If string, encode into bytes with utf-8
    if sys.version_info[0] < 3:
        data = bytearray(data, 'utf-8')
    else:
        data = data if type(data) == type(b"") else bytes(data, "utf-8")
    return writeInt16(len(data)) + data

def writeBytes(buffer):
    return writeInt16(len(buffer)) + buffer


class CustomProperties(Properties):
    # MQTT v5.0 malformed properties class

    def __init__(self, packetType, duplicate):
        Properties.__init__(self, packetType)
        self.duplicate = duplicate
        

    def allowsMultiple(self, compressedName):
        return self.getIdentFromName(compressedName) in [11, 38]

    def getIdentFromName(self, compressedName):
        # return the identifier corresponding to the property name
        result = -1
        for name in self.names.keys():
            if compressedName == name.replace(' ', ''):
                result = self.names[name]
                break
        return result

    def __setattr__(self, name, value):
        name = name.replace(' ', '')
        privateVars = ["packetType", "types", "names", "properties"]
        if name in privateVars:
            object.__setattr__(self, name, value)
        else:
            if self.allowsMultiple(name):
                if type(value) != type([]):
                    value = [value]
                if hasattr(self, name):
                    value = object.__getattribute__(self, name) + value
            object.__setattr__(self, name, value)

    def writeProperty(self, identifier, type, value):
        buffer = b""
        buffer += VariableByteIntegers.encode(identifier)  # identifier
        if type == self.types.index("Byte"):  # value
            if sys.version_info[0] < 3:
                buffer += chr(value)
            else:
                try:
                    buffer += bytes([value])
                except Exception:
                    buffer += writeInt16(value)
        elif type == self.types.index("Two Byte Integer"):
            buffer += writeInt16(value)
        elif type == self.types.index("Four Byte Integer"):
            buffer += writeInt32(value)
        elif type == self.types.index("Variable Byte Integer"):
            buffer += VariableByteIntegers.encode(value)
        elif type == self.types.index("Binary Data"):
            buffer += writeBytes(value)
        elif type == self.types.index("UTF-8 Encoded String"):
            buffer += writeUTF(value)
        elif type == self.types.index("UTF-8 String Pair"):
            buffer += writeUTF(value[0]) + writeUTF(value[1])
        return buffer

    def pack(self):
        # serialize properties into buffer for sending over network
        buffer = b""
        for name in self.names.keys():
            compressedName = name.replace(' ', '')
            if hasattr(self, compressedName):
                identifier = self.getIdentFromName(compressedName)
                attr_type = self.properties[identifier][0]
                if self.allowsMultiple(compressedName):
                    for prop in getattr(self, compressedName):
                        buffer += self.writeProperty(identifier,
                                                     attr_type, prop)
                else:
                    buffer += self.writeProperty(identifier, attr_type,
                                                 getattr(self, compressedName))
                    if(self.duplicate):
                        buffer += self.writeProperty(identifier, attr_type,
                                                    getattr(self, compressedName))

        return VariableByteIntegers.encode(len(buffer)) + buffer