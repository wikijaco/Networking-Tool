try :                   #checks for libs
    import dnspython as dns
    import dns.resolver
    import socket
except ImportError or ModuleNotFoundError:
    import ToolsIncluder 
class Tools:

    def __init__(self,string):
        self.string = str(string)
        return

    def findArecordDNS(self):
       return dns.resolver.query(self.string,"A")

    def nslookupWrapper():
        return #userà il comando integrato in cmd nslookup come dns

    def reverseDNS(self):
        return socket.gethostbyaddr(self.string)[0]


