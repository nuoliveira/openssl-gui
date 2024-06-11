from tkinter import Tk
from tkinter.ttk import Frame, Notebook

class App():
    def __init__(self):
        self.root = Tk()
        self.root.geometry("800x600")
        self.root.title("OpenSSL GUI")
        self.notebook = Notebook(self.root)
        self.notebook.add(FileIntegrityTab(), text="Tab 1")
        self.notebook.add(FileIntegrityTab(), text="Tab 2")
        self.notebook.add(FileIntegrityTab(), text="Tab 3")
        self.notebook.add(FileIntegrityTab(), text="Tab 4")
        self.notebook.pack(expand=True)

    def run(self):
        self.root.mainloop()

class FileIntegrityTab(Frame):
    def __init__(self):
        super().__init__()
