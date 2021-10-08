from scapy.modules.six import b
from Ip import ip
from tkinter import *
from tkinter.filedialog import askopenfile
from Frame import frame
import Maradona
import os
LINE = "\n-----------------------------------------------------------------------------\n"
THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))
FRAMEFILE = os.path.join(THIS_FOLDER, 'frame.txt')
LOGFILE = os.path.join(THIS_FOLDER, 'log.txt')
HELP = os.path.join(THIS_FOLDER, 'README.txt')
ENABLE_CMM = False
ENABLE_IPV4 = False

class GUI(Frame):
    def __init__(self, master = None):
        Frame.__init__(self, master)
        self.master = master
        self.initGUI()

    def initGUI(self):
          #textbox for pulling frame from text
        self.frame_input = Entry(width = 60)
        self.packetTextbox = Text(height = 12)
        self.packetTextbox.grid(row=0, column = 1, padx = 10)
        self.resultTextbox = Text(height = 12)
        self.resultTextbox.grid(row=1, column = 1, padx = 10) 


        menubar = Menu(self.master)
        self.master.config(menu = menubar)

        #Help Menu
        helpMenu = Menu(menubar, tearoff = 0)
        helpMenu.add_command(label="About", command = self.displayCredits)

        #Open menu
        openMenu = Menu(menubar, tearoff = 0)
        openMenu.add_command(label="...From frame.txt (will be overwritten)", command=self.file_decode)
        openMenu.add_command(label="...From Network", command=self.network_sniff)
        openMenu.add_command(label="...From Text", command=self.text_decode)
        openMenu.add_command(label="...From External File", command=self.ext_file)
        openMenu.add_command(label="Toggle Continuous Moitoring Mode", command = self.CMM)
        openMenu.add_command(label="Clear TB", command = self.clear)
        

        #80211 menu
        wifiMenu = Menu(menubar, tearoff = 0)
        wifiMenu.add_command(label="Inspect FC", command = self.wframelayout)
        wifiMenu.add_command(label="Inspect Whole Frame from Text", command = self.wframeinfo)
        
        #Tools menu
        toolsMenu = Menu(menubar, tearoff = 0)
        toolsMenu.add_command(label="Lookup MAC", command=self.file_decode)
        toolsMenu.add_command(label="Lookup IP", command=self.network_sniff)
        toolsMenu.add_command(label="Lookup DNS", command=self.text_decode)
        toolsMenu.add_command(label="Lookup RDNS", command=self.ext_file)
        toolsMenu.add_command(label="NOT WORKING Toggle Continuous Monitoring Mode", command = self.nof)
        toolsMenu.add_command(label="Clear TB", command = self.clear)
        toolsMenu.add_command(label = "Send PKT", command= self.morisi)
        #Net menu
        netMenu = Menu(menubar, tearoff = 0)
        netMenu.add_command(label="IP Decode", command=self.ipdecode)
        netMenu.add_command(label="Clear TB", command = self.clear)
        
        #Adding the menus to the Bar
        menubar.add_cascade(label="802.3...", menu = openMenu)
        menubar.add_cascade(label="802.11...", menu = wifiMenu)
        menubar.add_cascade(label="Tools..", menu = toolsMenu)
        menubar.add_cascade(label="Networking...", menu = netMenu)
        menubar.add_cascade(label="Help..", menu = helpMenu)
        

      
    def wframelayout(self):
        self.writePacketInFile()
        self.resultTextbox.delete("1.0", END)
        try:
           self.resultTextbox.insert("1.0",frame(FRAMEFILE).FCwframe())
        except TclError or ValueError:
            self.clear()
            self.packetTextbox.insert("1.0", "Write a WIFI packet here!")

       

    def wframeinfo(self):
        #only writes text from tbox in file.
        self.writePacketInFile()
        self.resultTextbox.delete("1.0", END)
        try:
           self.resultTextbox.insert("1.0",frame(FRAMEFILE).decodewframe())
        except TclError or ValueError :
            self.clear()
            self.packetTextbox.insert("1.0", "Write a WIFI packet here!")


        
    def nof(self):
        return 0
    def clear(self):
        self.packetTextbox.delete("1.0",END)
        self.resultTextbox.delete("1.0", END)

    def displayCredits(self): #opens readme file
        ENABLE_CMM = False
        os.system("start " + HELP)

    def writePacketInFile(self):       
        #checks for content on textbox 
        if self.packetTextbox.get("1.0", END):                        
            takenFrame = self.packetTextbox.get("1.0", END) 
            #deletes previous frame in file and writes a new one
            with open(FRAMEFILE,"w") as frameFile: 
                frameFile.write(takenFrame)
            if ENABLE_CMM:
                with open(LOGFILE,"w") as logFile: 
                    logFile.write(takenFrame)
                    logFile.write(frame(FRAMEFILE).printInfoFrame())
                    logFile.write(LINE)
        else:
            self.packetTextbox.delete("1.0",END)
            self.packetTextbox.insert("1.0","Write a packet here!")


    def file_decode(self):   
        ENABLE_CMM = False 
        #opens file
        try:
            f = open(FRAMEFILE,"r").read()
        except FileNotFoundError:
            f = open(FRAMEFILE,"w").read()
        self.clear()
        self.packetTextbox.insert("1.0",f)     #writes new frame
        self.resultTextbox.insert("1.0", frame(FRAMEFILE).printInfoFrame()) #prints decoded frame on tBox
    
    def network_sniff(self):
        ENABLE_CMM = False
        #stampa il pacchetto sniffato dallo sniffatore di pacchetti
        self.clear()
        try:
            self.packetTextbox.insert("1.0", Maradona.maradona()) #same as file_decode(), but writes result of sniffer() on tBox
        except RuntimeError:
            self.clear()
            self.packetTextbox.insert("1.0","WINPCAP/NPCAP IS NOT INSTALLED \n you must install one to have network sniffing")
        self.writePacketInFile() #writes tBox on file
        self.resultTextbox.insert("1.0", frame(FRAMEFILE).printInfoFrame())

    def text_decode(self):
        ENABLE_CMM = False
        #only writes text from tbox in file.
        self.writePacketInFile()
        self.resultTextbox.delete("1.0", END)
        try:
            self.resultTextbox.insert("1.0", frame(FRAMEFILE).printInfoFrame())
        except TclError or ValueError:
            self.packetTextbox.insert("1.0", "Write an 802.3 packet here!")

    def ext_file(self):
        ENABLE_CMM = False
        try:
            extFile = askopenfile(mode ='r', filetypes =[('Text Files', '*.txt')])
            extFileContent = extFile.read()
            self.clear()
            self.packetTextbox.insert("1.0",extFileContent)
            self.resultTextbox.insert("1.0", frame(extFile.name).printInfoFrame())
        except AttributeError:
            self.clear()
            self.packetTextbox.insert("1.0","No File Selected!")
    
    def CMM(self):
        ENABLE_CMM = True
        while(ENABLE_CMM):
            self.packetTextbox.delete("1.0", END)
            self.packetTextbox.insert("1.0", Maradona.maradona()) #same as file_decode(), but writes result of sniffer() on tBox
            self.writePacketInFile() #writes tBox on file
            self.resultTextbox.delete("1.0", END)
            self.resultTextbox.insert("1.0", frame(FRAMEFILE).printInfoFrame())

    def ipdecode(self):
        self.resultTextbox.delete("1.0", END)
        rt = self.packetTextbox.get("1.0", END)
        res = ip(rt).ip_decode_manual()
        self.resultTextbox.insert("1.0",res)
    
    def morisi(self): 
        try:
            Maradona.morisiSend(self,self.packetTextbox.get("1.0",END))
        except ValueError:
            self.packetTextbox.insert("1.0","Write a frame here!")
        self.resultTextbox.delete("1.0", END)
        self.writePacketInFile()
        self.resultTextbox.insert("1.0", frame(FRAMEFILE).printInfoFrame())


       
            

        
