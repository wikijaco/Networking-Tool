from ipdict import ipdict


class frame:
    
    '''
    frame class to read frame info from file |
        •param fdir: file directory |
        Methods:
            •getEthType
            •getDestMac
            •getSrcMac
            •decodeLLC
            •printMac
            •checkFrameLen
            •printInfoFrame |
    AUTHORS: Bonati, Ugolotti, Gaiani, Francavilla
    '''
    def __init__(self, fdir): #Constructor authors: Bonati, Ugolotti 
        self.fdir = fdir
        self.frame = ""
        self.buffered_frame = []
        self.destMac = []
        self.srcMac = []
        self.srcIp = []
        self.dstIp = []
        self.etherDict ={       #dict from which to pull etherTypes
            0x800 : "IPv4",
            0x806 : "ARP",
            0x8035 : "RARP",
            0x809b : "Ethertalk",
            0x8100 : "VLAN-tagged",
            0x814c : "SNMP",
            0x86dd : "IPv6",
            0x8808 : "MAC Control", 
            0x8809 : "LACP",
            0x8847 : "MPLS",
            0x886 : "PPPoE",
            0x8870 : "Jumbo",
            "f0"   : "Netbeui/Netbios",
            "e0"   : "IPX Novell",
            "06"   : "IPv4",
            "42"   : "STP"
            }
            
        self.__fgetFrame() #constructor, initializes attributes and calls private mehtod __fgetframe()

    """
    Get frame from file
        •return: buffered frame size (type int) 
        •PRIVATE
    AUTHORS: Bonati, Ugolotti 
    """
    def __fgetFrame(self): #opens file, saves it in an attribute, parses file to exclude ascii dump and line indexes(58)
        parse_buffer= []
        framelocal = self.frame
        framelocal = open(self.fdir)
        framelocalRD = framelocal.read()
        framelocal.close()
        self.buffered_frame = framelocalRD.split()
        
        for o in self.buffered_frame:
            if len(o) == 2:
                parse_buffer.append(o)
        self.frame = framelocalRD
        
        self.buffered_frame = parse_buffer # buffered_frame is an array, with one byte per place, parsed.
        return len(self.buffered_frame)
    
    """
    Get ether type
        •return: bytes for ethertype recognition (type int)
        AUTHORS: Francavilla 
    """
    def getEthType(self):
            return int("".join(self.buffered_frame[12:14]),16) 
            #takes from specific byte range, int(-int-, 16) turns into hexadecimal integer

    """
    Get destination mac address
        •return: mac addres bytes (type str)
        AUTHORS: Gaiani
    """
    def getDestMac(self):
        self.destMac = self.buffered_frame[0:6]
        return self.destMac
    
    """
    Get source mac address
        •return: mac address bytes (type str)
        AUTHORS: Gaiani
    """
    def getSrcMac(self):
        self.srcMac = self.buffered_frame[6:12]
        return self.srcMac


    """
    Get IP Addrs from packet bytes
        •return ip addresses, list
                ip address string
        AUTHORS: Ugolotti 
    """
    def getSrcIp(self):
        self.srcIp = self.buffered_frame[26:30]
        return self.srcIp
    
    def getDstIp(self):
        self.dstIp = self.buffered_frame[30:34]
        return self.dstIp

    def printIp(self, ipaddr):
        return str(int(ipaddr[0],16))+"."+str(int(ipaddr[1],16))+"."+str(int(ipaddr[2],16))+"."+str(int(ipaddr[3],16))
    """
    Get mac type
        •param macaddr: mac address
        •return: macaddr + mac info (type str)
        AUTHORS: Bonati
    """    
    def printMac(self,macaddr):
        retStr = "-".join(macaddr)
        try:
            if (int("".join(macaddr), 16) == 0xFFFFFFFFFFFF): #compares evalued MAC address to the broadcast value, bulds string accordingly
                return retStr + " Broadcast"

            elif (int(macaddr[0], 16) % 2 == 0): #checks last bit, looking for singlecast address
                return retStr + " Singlecast"

            elif ((int(macaddr[0], 16) >> 1) % 2 == 1): #shifts macaddress by one bit to the right, to check last-but-one bit, looking for multicast.local
                return retStr + " Multicast.local"
                
            else:
                return retStr + " Multicast.Global" #if all else is false, mac address must be multicast.global
        except ValueError:
            return "Not a valid packet! 2"
    
    """
    Decode LLC 
    AUTHORS: Bonati, Ugolotti
    """
    def decodeLLC(self):
    
        DSAP = self.buffered_frame[14] #takes dsap characteristic byte

        if (self.getEthType() > 0x5dc): #checks if eth2 or 802.3, using Type/len byte
            Etype = self.getEthType() #type len is type
            retStr = ""
            try:
                retStr += "\nFrame.Type = Eth2 \nEtherType = "#builds string
                retStr += "".join(self.buffered_frame[12:14]) #ethertype bytes
                retStr += " "+ str(self.etherDict[Etype])# takes 
                if Etype != 0x806 and Etype != 0x8035 and Etype != 0x8805 and Etype != 0x42: 
                    retStr += "\nDst IP: "+ self.printIp(self.getDstIp())
                    retStr += "\nSrc IP: "+ self.printIp(self.getSrcIp())
               
            except KeyError:
               retStr += "\nFrame.Type = Eth2 " #runs if ethertype is not in dict
               retStr += "\nEtherType = "+ Etype+ " Unknown EthType"
            return retStr
        else: 
            length = self.getEthType() #type/len is len
            retStr = "\nFrame.Type = 802.3 "

            if(int("".join(DSAP),16) == 0xaa): #snap protocol
                retStr +="\nSNAP Protocol"
                OUI = "-".join(self.buffered_frame[17:20]) #pulls OUI field
                retStr += ("\nFrame OUI is:" + OUI) #prints it to string
                return retStr
            else:
                try:
                    retStr += "Packet is of type:"+ self.etherDict["".join(DSAP)]+ "\nWith DSAP:"+ DSAP #not snap, looks for correspondence in dict and also prints dsap
                except KeyError:
                    retStr += "Packet is of type: "+ "UNKNOWN"+ "\nWith DSAP:"+ DSAP #if not in dict

                
                retStr += "Frame is of Len:" + length #adds length 
                return retStr
    
    
    '''
    Check frame length
        •return: frame length (type int)
    AUTHORS: Francavilla
    '''
    def checkFrameLen(self): 
        if (self.getEthType() < 0x5dc):
            return self.getEthType()
        else:
            return int("".join(self.buffered_frame[16:18]),16) + 14

    '''
    Print src & dst mac, frame length and decode LLC
    AUTHORS: Ugolotti 
    '''
    def printInfoFrame(self):
       # try:
            
            retStr = "\n"
            retStr += "Macaddr.dst: " + self.printMac(self.getDestMac())
            retStr += "\nMacaddr.src: " + self.printMac(self.getSrcMac())
            retStr += self.decodeLLC()
            retStr += "Flags: "+self.getFlg()
            retStr += "Fragment Offset: "+self.getOffset()
            retStr += self.getIPvLen()
            retStr += "Protocol: "+ self.getProtocol()
            retStr += "TTL: "+ self.getTTl()
            retStr += "ID" + self.getID()
            retStr += "Ports: " + self.getPorts()
            retStr += "\nTotal Size:  " + str(self.checkFrameLen())
        #except TypeError or IndexError:
        #    return "Not a valid packet!"
            return retStr
    
    
    #wifi, frame body resolution is only valid for beacon frames for now
    '''
    This function is specialized for decoding the frame control field of a wifi frame
    it builds a string with the binary representation of the two bytes, then uses the first byte to determine
    wether the frame is CTS,RTS,ACK or management by using the value of the first byte
        •return: summary string of FC field
    AUTHOR: Bonati
    '''
    def FCwframe(self):  #will be deprecated, better implementation in clone
        TYPEMASK = int(0x0C)
        TYPE_CTRL = int(0X04)

        
        retstr = "Frame control: "
        retstr += str(bin(int("".join(self.buffered_frame[0:2]),16)))  #converts FC field in binary
        retstr += " Type: "
        if (int(self.buffered_frame[0],base = 16) < 0x83):#each subtype can be interpreted (beacon frames can have the first byte of FC spanning from 1000/00/00 - 1000/00/11,0x80-0x83)
             retstr += "Beacon"                           #as a value and thus recognized by comparisons, look at binary implementation of FC 
        elif (TYPEMASK & int(self.buffered_frame[0],base = 16) == TYPE_CTRL):
            retstr += "Control; SUBTYPE "
            if (int(self.buffered_frame[0],base = 16) < 0xB7):
                retstr += "RTS"
            else:
                if (int(self.buffered_frame[0],base = 16) < 0xC7):
                    retstr += "CTS"
                else:
                    retstr += "ACK"
        else:
            retstr += "Management"
        return retstr
    
    def getRTapHLen(self):  #get radiotap header len, this function is important for it is used to calculate offsets for all fields in frame
        return int("".join(reversed(self.buffered_frame[2:4])),16) #little endian, so we reverse it IN PLACE to parse it as big endian, (beta, cant catch exc here)

    def getFCwfield(self): #gets fc field of full frame
        return self.buffered_frame[self.getRTapHLen():2+self.getRTapHLen()]
    
    '''
    Function for checking TDS/FDS bits of FC, similarly to earlier function self.printMac(self,macaddr)
    '''
    def getTdsFds(self):

        if int("".join(self.getFCwfield()),16) & 3 == 0: #both zero
            return "Ad-hoc"
        else:
            if int("".join(self.getFCwfield()),16) % 2 == 0:
                return "Infrastructure, TDS = 1, FDS = 0 UPLINK"
            elif int("".join(self.getFCwfield()),16) % 2 == 1:
                return "Infrastructure, TDS = 0, FDS = 1 DOWNLINK"
        #interlink support coming

    def getwDuration(self):
         return int("".join(self.buffered_frame[2+self.getRTapHLen():4+self.getRTapHLen()]),16)

    '''

    builds a string containing MAC addresses
    '''
    def getwAddresses(self):
        retstr = "Addresses:\n"
        retstr += "\tDestination: "+ "-".join(self.buffered_frame[4+self.getRTapHLen():10+self.getRTapHLen()])
        retstr += "\n\tSource: "+ "-".join(self.buffered_frame[10+self.getRTapHLen():16+self.getRTapHLen()])
        retstr += "\n\tBSSID: "+ "-".join(self.buffered_frame[16+self.getRTapHLen():22+self.getRTapHLen()])
        return retstr

    def getwSeqNum(self):# gets sequence number
        return int("".join(reversed(self.buffered_frame[23+self.getRTapHLen():25+self.getRTapHLen()])),16)
    
    def getWTstamp(self):#gets timestamp
        return int("".join(reversed(self.buffered_frame[24+self.getRTapHLen():32+self.getRTapHLen()])),16)
    
    def getBIeC(self):#gets BeaconInterval and Capability field
        return int("".join(self.buffered_frame[34+self.getRTapHLen():39+self.getRTapHLen()]),16)
    
    '''
    gets and decodes SSID field using offsets calculated from .getRTapHLen() and from the ssid length field of frame
    '''
    def getSSID(self):
        try:
            return bytes.fromhex("".join(self.buffered_frame[38+self.getRTapHLen():38+self.getRTapHLen()+int(self.buffered_frame[37+self.getRTapHLen()],16)])).decode("utf-8")
        except:
            return "Not a valid SSID"
    
    '''
    clone of FCwframe(self), but adapted for use in array offset read mode
    '''
    def getFCInfo(self):
        TYPEMASK = int(0x0C)
        TYPE_CTRL = int(0X04)

        
        retstr = "Frame control: "
        try:
            buf = int("".join(self.getFCwfield()),16)
        except:
            retstr = "NOT a Valid Packet"
        retstr += str(bin(buf)) 
        retstr += " Type: "
        if (int(self.getFCwfield()[0],base = 16) <= 0x83) and (int(self.getFCwfield()[0],base = 16) >= 0x80):
                retstr += "Beacon"
        elif (TYPEMASK & int(self.getFCwfield()[0],base = 16) == TYPE_CTRL):
            retstr += "Control; SUBTYPE "
            if (int(self.getFCwfield()[0],base = 16) <= 0xB7) and (int(self.getFCwfield()[0],base = 16) >= 0xB4):
                retstr += "RTS"
            else:
                if (int(self.getFCwfield()[0],base = 16) <= 0xC7) and (int(self.getFCwfield()[0],base = 16) >= 0xC4):
                    retstr += "CTS"
                else:
                    retstr += "ACK"
        else:
            retstr += "management"
        return retstr

    def decodewframe(self): #decodes a return summary string
        retstr= "RTap len: " + str(self.getRTapHLen())
        retstr +="\n" + self.getFCInfo()
        retstr += "\nCirculation Type: "+ self.getTdsFds()
        retstr += "\nDuration: " + str(self.getwDuration())
        retstr += "\n"+ self.getwAddresses()
        retstr += "\nSequence number: " + str(self.getwSeqNum())
        retstr += "\nTimestamp: "+ str(self.getWTstamp())
        retstr += "\nBeaconInterval/Capability: " + str(self.getBIeC())
        retstr += "\nSSID: " + self.getSSID()

        return retstr


#TODO interlink suppoer, non beacon FB support

##level 3 update

    def getFlg(self):
        byte = self.buffered_frame[21]
        print (byte)
        match byte:
                case "60":
                    return "0x60, reserved bit\n"
                case "40":
                    return "0x40, Don't Fragment\n"
                case "20":
                    return "0x20, More Fragments\n"
                case "00":
                     return "No flag set\n"
                

    def getIPvLen(self):
        byte = int(self.buffered_frame[14])
        len = byte % 10
        ipv = byte // 10
        return "IPv: "+ str(ipv) + ", Header len: "+ str(len*4) +"\n"
    
    def DSF():
        return #TODO

    def getID(self):
        return "".join(self.buffered_frame[18:20]) + "\n"

    def getOffset(self):
        return "".join(self.buffered_frame[20:22])+ "\n"
    
    def getTTl(self):
        return self.buffered_frame[22]+ "\n"
    
    def getProtocol(self):
        return ipdict(int(self.buffered_frame[23])).IPdic() + "\n"
    
    def getPorts(self):
        return "Source Port: "+ str(int("".join(self.buffered_frame[32:34]),16)) + "Destination Port: " + str(int("".join(self.buffered_frame[36:38]),16)) + "\n"



    '''
    DSF
    checksum
    checksum?
    '''

