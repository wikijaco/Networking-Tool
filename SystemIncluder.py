#opera del buon bonati + ugo povero mac user si aggiusta da solo , 20 min totale
import os
import platform
import sys

try:
    if platform.system() == 'Darwin': #nessuno pensa mai ai mac user 
        os.system('cmd /c "pip install libpcap"')
        os.system('cmd /c "pip install --pre scapy[complete]"')
        os.system('cmd /c "pip install wheel"')
        os.system('cmd /c "pip install psutil"')

    elif platform.system() == "Linux":
        os.system("pip3 install libpcap")
        os.system("pip install --pre scapy[complete]")
        os.system("pip install wheel")
        os.system("pip install psutil")

    else: #win
        os.system('cmd /c "pip install scapy"')
        os.system('cmd /c "pip install wheel"')
        os.system('cmd /c "pip install psutil"')

    print("finished setting up required libraries, restarting program...")
    from scapy.all import *
    import psutil
except ImportError as e:
    print(f"Unable to collect: {e}")

