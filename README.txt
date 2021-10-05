Project: "Frame Decoder"
Authors: Bonati J.(PM), Ugolotti E., Gaiani S., Francavilla M.
Group Name: "Gli Idraulici"

Scope:
    Application for decoding an Hex ethernet frame.

Features:
    Sniffing from the host's local network
    GUI
    IP extraction

Usage:
    Run the program with Main.py or dist/Main.exe, pick frame source from dropdown menu (open)
    Every module and dependency should be installed automatically by SystemIncluder.py, 
    TO ENABLE THE PACKET SNIFFING FEATURE WINPCAP MUST BE INSTALLED.

    Written in Python 3.9

Project Modularity:
    THis Project is developed across 3 main files:
        Frame.py: (Bonati, Ugolotti, Gaiani, Francavilla; 3.30 - 4hh)
            Class that deodes an ehernet frame from a file (FRAMEFILE) and with the method .printInfoFrame returns:
                -IP Addresses
                -MAC Addresses
                -Type/Length
                -OUI
                -Size
                -Ethertype
            Decoding happens through file reading and following string parsing which removes ASCII dump and line indexes, splitting the packet on hex bytes.
            Using this method it's easy to check for correspondence  for characteristic byte fields, and with bit masking(%2) and bit shifting (>> 1) its possible check MAC Addrs' bits to determine the multicast class.
        Maradona.py (Bonati, Ugolotti; 5hh):
            Function to pull packets from host's LAN, using the sniff(iface, count, pnr) function
           imported from scapy.py external library, the iface parameter, indicating the network interface to pull packets from,
            is assigned a default name, in case said interface was unavailable, the method .net_if_addrs() from the psutil external library
            returns a list of available interfaces, which is iterated until a valid NIC is found.
            Now the sniff() function returns a non parsed frame, which is turned into a valid string and then written to frame.txt, which is later read by Frame.py.
            The external libs are mported by SystemIncluder.py, which installs everything needed for the correct functioning of the program.
        GuiBackup.py (Gaiani, Francavilla; 6hh):
            This segment uses the TkInter(Built-In) lib to draw a simple GUI that allows the user to pick between one of the four operating modes of this program:
            The modes are::
                1) Decode from Frame.txt -> first_botton(self)
                2) Decode from Network (will overwrite frame.txt) -> second_botton(self)
                3) Decode from Text (will overwrite frame.txt) -> third_botton(self)
				4) Decode from External File 
				+ Help button to open this file
            InitGUI() function draws and displays the textboxes and buttons.
            writePacketInFile(self) function is fundamental for using frame.txt: writes contents of textbox in frame.txt.
        Main.py (Gaiani, Francavilla; 1h)
            Main file, used to invoke GUI
        EmergencyMain.py (Gaiani, Francavilla; 2min)
            To be used in case of problems with GUI, simply prints decoded contents of frame.txt to shell.
                Each button calls one of four functions, and each function is responsible for linking the other two modules together and for clearing textboxes, writing and reading files. 

DEBUGGING TIME NOT INCLUDED IN TIMESTAMPS


COMPITI DELLE VACANZE 2021
tutte le modifiche successive alla versione già consegnata in 4a sono state apportate esclusivamente da me, senza piu ricorso al team precedente.
Ho aggiunto varie funzionalità che al momento sono ancora in fase di sviluppo (ip lookup, dns/rdns) percheè ho intenzione di continuoare a coltivare qyesto programmino e portarlo all' esame di stato
con tante features in piu.

ad ogni modo, le modifiche apportate (oltre che quelle del menu) sono nel file Ip.py, e per attivare la funzione di decode prevista come compito basta digitare un IP con CIDR
nella textbox in alto , poi dal menu in alto cliccare su "Networking" e poi selezionare "IP decode"
si stampa sulla tb in basso l' output richiesto