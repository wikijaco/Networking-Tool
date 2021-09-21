import ipaddress
class ip:
    def __init__(self,ipstring):
        
        self.ipstring = str(ipstring)
        return
    
    def bit_not(self, n, numbits=32): #logica di default a 32 bit, serve per fare il not biwise di un intero
      return (1 << numbits) - 1 - n # prende un 1 e lo trasporta a sx di numbits posizioni, ottenendo di fatto un numero composto da numbits+1 bits
      #a questo punto sottrae 1 ottenendo un numero con numbits bits tutti impostati a 1, poi sottrae (al posto di fare un NAND, operazione analoga) il numero n per settare a 0 i bit a 1 che compongono n
       
    def ip_class(self, ip): #implementazione non utilizzata perchè python ne mette a disposizione una sottoforma di libreria, comunque è l' algritmo che avrei usato
        ip = str(ip)
        ip = ip.split(".")
        if ip[0] == "10": #logica per confronto
            return "Private"
        if ip[0] == "172" and int(ip[1]) >= 16 and int(ip[1]) <= 31:
            return "Private"
        if ip[0] == "192" and ip[1] == "168":
            return "Private"
        if ip[0] == "100" and int(ip[1]) >= 64 and int(ip[1]) <= 127:
            return "Private"
        if ip[0] == "192" and ip[1] == "0"and ip[2] == "0":
            return "Private"
        else: 
            return "Public"
    
    def iptobin(self, ip): #semplicemente sfrutta la funzione bin() di python per trasformare in stringhe rappresentanti il binario di ogni ottetto, .zfill mette zeri di fronte ad ogni numero per arrivare a 8 (0b1010 -> 00001010)
        ip = str(ip)
        ip = ip.split(".")
        return " "+bin(int(ip[0]))[2:].zfill(8) + "." +bin(int(ip[1]))[2:].zfill(8) + "." +bin(int(ip[2]))[2:].zfill(8) + "." +bin(int(ip[3]))[2:].zfill(8) + "\n"
    
    def ip_decode_manual(self):
        ip_octs = self.ipstring.split(".")
        buf = ip_octs[-1].split("/")
        ip_octs.pop()
        ip_octs.append(buf[0])
        ip_octs.append(buf[-1].strip("\n")) #queste righe trasformano un IP da stringa in array
        retstr = "Class: "
        int_firstoct = int(ip_octs[0])
        if (int_firstoct & 0b10000000 == 0): #determina la classe utilizzando le maschere, questo controlla che alla posizione 0 ci sia uno 0
            retstr += "A (/8)\n"  
        elif (int_firstoct & 0b11000000 == 0b10000000): #alla posizione 8 un 1 e alla 7 uno 0
            retstr += "B (/16)\n"
        elif (int_firstoct & 0b11100000 == 0b11000000):#110
            retstr += "C (/24)\n"
        elif (int_firstoct & 0b11110000 == 0b11100000):#1110
            retstr += "D (multicast)\n"
        elif (int_firstoct & 0b11110000 == 0b11110000):#1111
            retstr += "E\n"
        retstr += "Network: "
        nw = ipaddress.IPv4Address( #ipaddress.ipv4address trasforma un intero in un indirizzo ip (può essere riportato a intero con int())
            int(ipaddress.IPv4Address(".".join(ip_octs[0:-1]))) #crea un intero a partire dall' indirizzo ip passato come argomento stringa e ...
                & self.bit_not(0) << 32-int(ip_octs[4]))        #...fa un and bitwise tra l' intero sopracitato e la rappresentazione intera della netmask
                                                                #ottenuta shiftando di CIDR posizioni il not a 32bit di 0 
       
        retstr += str(nw) + self.iptobin(nw)

        #retstr += self.ip_class(nw) + " IP Address\n" #implementazione non usata 
        if nw.is_private:
            retstr += "Private IP Address \n"
        else: 
            retstr += "Public IP Address \n"
            
        retstr += "IP Address: "+ ".".join(ip_octs[0:-1]) +self.iptobin(".".join(ip_octs[0:-1])) #rijoina l' IP in una stringa
        retstr += "CIDR nmask: /" + ip_octs[-1]  +"\n"

        nm = str(ipaddress.IPv4Address((self.bit_not(0) << (32-int(ip_octs[-1]))) & 0xFFFFFFFF)) #crea un IP partendo dalla rappresentazione binaria e 0x FFFFFFFF che serve a "tagliare" il risultato a 32 bit
        retstr += "Netmask: " + nm +self.iptobin(nm)
        wcm = str(ipaddress.IPv4Address(self.bit_not(0) >> (int(ip_octs[-1])))) 
        retstr += "Wildcard mask: " + wcm + self.iptobin(wcm)
        retstr += "Host Range: " + str(nw + 1)+ " - " + str(nw + 2 ** (32-int(ip_octs[-1]))-2) + "\n" #per trovare l' ultimo indirizzo, prende l' indirizzo del network e vi aggiunge il numero degli host disponibili massimi -2
        bc = str(nw + 2** (32-int(ip_octs[-1])) - 1)
        retstr += "BC: " + bc + self.iptobin(bc) 
        retstr += "Number of hosts: " + str(2** (32-int(ip_octs[-1])) - 2)
        return retstr