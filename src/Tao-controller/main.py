import sys
import os
import tkinter as tk

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

os.environ['TAO_BASE_DIR'] = BASE_DIR

ICON_PATH = os.path.join(BASE_DIR, "ico", "ico.ico")

from ui.main_window import RC

if __name__ == "__main__":
    root = tk.Tk()
    
    if os.path.exists(ICON_PATH):
        root.wm_iconbitmap(ICON_PATH)
        
    app = RC(root)
    root.mainloop()