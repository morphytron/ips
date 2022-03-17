import socket, errno, sys, tkinter as t, threading
from tkinter import scrolledtext

class info_logger(t.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.lock = threading.Lock()
        self.master.title("IdealPrevention Monitoring Station")
        #self.master.attributes('-alpha', .7)
        self.createWidgets()
        self.pack()
        x = threading.Thread(target=servlet, args=[self], daemon=True)
        x.start()
        self.mainloop()
    def createWidgets(self):
        #lists/frames
        self.event_frame = t.LabelFrame(self, text="Events")
        self.events = t.Listbox(self.event_frame, width=150, bg="dark grey", fg="green")
        self.event_scroll = t.Scrollbar(self.event_frame)
        self.event_scroll_x = t.Scrollbar(self.event_frame, orient='horizontal')
        self.events.config(xscrollcommand=self.event_scroll_x.set, yscrollcommand=self.event_scroll.set)
        self.event_scroll.config(command=self.events.yview)
        self.event_scroll_x.config(command=self.events.xview)
        self.event_frame.grid(column=1, row=1, columnspan=2, sticky=t.W + t.N + t.S + t.E)
        self.event_scroll.pack(side=t.RIGHT, fill=t.Y)
        self.event_scroll_x.pack(side=t.BOTTOM, fill=t.X)
        self.events.pack(fill=t.BOTH)
        #vars
        self.alerts = t.BooleanVar(self, True)
        self.alerts_textvar = t.StringVar(self, "Alerts Enabled")
        #buttons, labels
        self.ex = t.Button(self, text="Quit", command=self.leaveApp)
        self.ex.grid(column=1, row=3, sticky=t.W + t.N + t.S + t.E)
        self.check_alerts = t.Checkbutton(self, variable=self.alerts, textvariable=self.alerts_textvar, command=self.toggle, fg="green", bg="black")
        self.check_alerts.grid(column=2, row=3, sticky=t.W + t.N + t.S + t.E)
    def leaveApp(self):
        self.quit()
    def toggle(self):
        if self.alerts.get():
            self.check_alerts.config(fg="green")
            self.alerts_textvar.set("Alerts Enabled")
        else:
            self.check_alerts.config(fg="red")
            self.alerts_textvar.set("Alerts Disabled")
    def parseInputString(self, string):
        #put logic to make it look cleaner...
        self.lock.acquire()
        self.events.insert(0, string)
        self.lock.release()
class servlet(info_logger):
    args = sys.argv[1:]
    msg = "Connection established.".encode(encoding='utf-8')
    def __init__(self, gui):
        self.gui = gui
        print("Starting IPS Servlet...")
        try:
            self.server_address = (self.args[0], int(self.args[1]))
        except:
            print("Make sure the first argument is the ip address in quotes, and the second argument is the port number!")
            return
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Created socket...")
        serv.bind(self.server_address)
        print("Bound the server address successfully.")
        serv.listen(25)  # twenty-five connections maximum
        print("Listening for up to twenty-five connections...")
        #run server
        while True:
            clientsocket, client_address = serv.accept()
            print("Accepted connection.")
            string = ""
            try:
                clientsocket.send(self.msg)
                data = clientsocket.recv(500)
                string = "Received: " + str(data.decode(encoding='utf-8')) + " from " + str(client_address)
                print(string)
                self.gui.parseInputString(string)
                clientsocket.close()
            except socket.error as e:
                if e.errno != errno.ECONNRESET:
                    print("Some error occurred with server/client TCP/IP connection...")
                print("Could not receive any information from client because of error#" + str(e.errno))
            finally:
                with open("log3.lg", "a+", encoding="utf-8") as f:
                    f.write(string)
a = info_logger()