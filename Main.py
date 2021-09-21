from GuiBackup import GUI
from tkinter import *

window = Tk() #instance of Tk, used later to draw the GUI
GUI(window) #used to configure the GUI, eg positioning tBoxes, writing text

window.geometry("665x395") #size of window
window.title("Frame Decoder -Gli Idraulici-") 
window.configure(background = "whitesmoke")
window.grid_columnconfigure(0, weight = 0)

window.mainloop() 


