import os
import platform
import sys

try:
    if platform.system() == 'Darwin': #nessuno pensa mai ai mac user 
        os.system('cmd /c "pip install dnspython"')
       

    elif platform.system() == "Linux":
        os.system("pip3 install dnspython")
        

    else: #win
        os.system('cmd /c "pip install dnspython"')
        
    print("finished setting up required libraries, please restart program")
    from scapy.all import *
    import psutil
except ImportError as e:
    print(f"Unable to collect: {e}")