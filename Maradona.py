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
    

def morisiSend(self, pkt: str):#famo opzione per cambiare mac ???????????? cerca pure io smadonno per fargli sendare la stringa ok
    #ma raw() assembla il pacchetto a partire da hexdump? non capisco se crea da hex e returna un oggetto o ppure il contrario
#enzomma abbiamo la stringa e la vogliamo mandare via come pacchhetto al massimo usiamo Socket()
    pkt = Packet(bytes(pkt,"UTF-8"))
    #print(pkt)
    #print(conf.iface)
    #print(psutil.net_if_addrs())
    sendp(pkt,iface= "Ethernet") #funziona
 #secondo me ci conviene creare altro file un .pcap? o un altro txt? secondo me meglio creare un .pcap perche lo supporta nativo ma preferisco fare al volo non so scelga lei io provo una cosa off ok

#ok dentro entra come stringa nel sender? in teoria va messa nella textbox in alto, lo passa alla funz come strina e li lo assembla e lo manda ma non so se lo puo mandare come str no ok

