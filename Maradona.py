try :                   #checks for libs
    from scapy.all import *
    import psutil
except ImportError or ModuleNotFoundError:
    import SystemIncluder #systemIncluder installs libraries if not found


def maradona():             ##Ugolotti 2h, Bonati 3h, (Mostly R&D e Debug) 
    addrs = psutil.net_if_addrs() # containd NIC list 
    packet_container = []

    def custom_action(packet):  #Ugolotti, function passed as prn param to sniff(), indicates where should packet be written. 
        nonlocal packet_container #where sniff() is written
        packet_container = hexdump(packet, dump=True).split("  ")

                             #Bonati, Ugolotti, critical function, to allow code portability 
    try:                     #iterates nic list if default one doesn't work
        sniff(iface=conf.iface,count = 1 ,prn=custom_action)
    except ValueError or Scapy_Exception or errno(19):
        try:
            for a in addrs:
                try:
                    sniff(iface = a,count = 1 ,prn=custom_action) #returns int packet_container (to be parsed)
                    print(a)
                    break
                except ValueError or Scapy_Exception:
                    continue
        except ValueError or Scapy_Exception:
            print("No valid NIC found! \n Aborting...")
            return 1
                
    final_packet = []
    for i in packet_container: #Bonati, parsing of packet_container, excludes line indexes and ascii dump
        try:
            if i != "" and "." not in i and "\n" not in i: #does not append "", if "." or "\n" in list place, 
                final_packet.append(i)
        except IndexError:
            break

    del final_packet[0]
    return " ".join(final_packet)  # builds valid string
    

def morisiSend(self, pkt: str):
    pkt = Packet(bytes(pkt,"UTF-8"))
    #print(pkt)
    #print(conf.iface)
    #print(psutil.net_if_addrs())
    send(pkt,iface= "Ethernet") #funziona
 