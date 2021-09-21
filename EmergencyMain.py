from Frame import frame
from Maradona import maradona as sniffer

USE_SNIFFER = True
if USE_SNIFFER:
    with open("frame.txt","w") as f:
        f.write(sniffer())
print(frame("frame.txt").printInfoFrame())

