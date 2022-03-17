'''
#Author: Daniel Alexander Apatiga
#Contact info = daniel-apatiga@uiowa.edu
#For questions, please email me and put in the subject, "your IPS script."  Thank you.
#needed regardless
#from subprocess import check_output
#for personal use only
'''
import sys, os, subprocess as sp, threading, socket as sock, re, datetime, ArgumentMatcher as a, tkinter as t, plyer as ply
from tkinter import filedialog, scrolledtext
#from SysTray import SysTrayIcon as tray
from subprocess import CompletedProcess

class Gui(t.Frame):
    lock=threading.Lock()
    #widgets for main window
    def __init__(self, master=None):
        super().__init__(master)
        #frame properties
        self.master.title("Intrusion Prevention System")
        self.master.config(relief=t.RIDGE)
        self.config(bg="blue", highlightcolor="red", highlightbackground="purple")
        #self.master.attributes('-alpha', .65)
        #initiate variables
        self.output = t.StringVar("")
        self.createWidgets()
        self.pack()
        self.main()
        #self.sys_tray = tray(icon="favicon.ico", hover_text="Ideal Prevention System",
        #                     menu_options=(('Start/Restart', None, self.quit), ('Stop', None, self.stop_ips)))
        self.mainloop()
    #def addException(self):
    #    pass
    def processAnalysis(self):
        pass
    def failureAnalysis(self):
        pass
    def timeAnalysis(self):
        pass
    def increStringVar(self, stringvar):
        regex = re.compile("[0-9].")
        z = stringvar.get()
        matc = regex.match(z)
        stringvar.set(str(int(z[matc.start():matc.end()]) + 1))
    def repopulateWinExceptions(self):
        crit_exceptions = ["System", "smss.exe", "csrss.exe", "dwm.exe", "sihost.exe", "lsass.exe", "smartscreen.exe", "RuntimeBroker.exe", "dasHost.exe", "dllhost.exe", "svchost.exe", "SearchUI.exe"]
        self.lock.acquire()
        for crit_ex in crit_exceptions:
            b = False
            z = self.exception_l.get(0, last=self.exception_l.size())
            for ex in z:
                if ex == crit_ex:
                    b=True
                    break
            if b:
                continue
            else: #It's not in the list
                self.insertToProgToExempt(crit_ex)
                self.instance.accepted_apps.append(crit_ex)
        self.lock.release()
    def createWidgets(self):
        #menu & menu items
        self.attack_analytics = t.Menubutton(self,anchor=t.N, text="Analytics", relief=t.RAISED)
        self.configuration = t.Menubutton(self, anchor=t.N, text="Exceptions", relief=t.RAISED)
        self.analy = t.Menu(self.attack_analytics, tearoff= 0)
        self.conf = t.Menu(self.configuration, tearoff=0)
        self.exception_sub_menu = t.Menu(self.conf, tearoff=0)
        self.attack_analytics.config(menu=self.analy)
        self.configuration.config(menu=self.conf)
        #menu configs
        self.analy.add_command(label="Process Analysis", command=self.processAnalysis)
        self.analy.add_command(label="Failure/Success Analysis", command=self.failureAnalysis)
        self.analy.add_command(label="Time Analysis", command=self.timeAnalysis)
        self.conf.add_cascade(label="Repopulate", menu=self.exception_sub_menu)
        self.exception_sub_menu.add_command(label="Add for Windows 10", command=self.repopulateWinExceptions)
        #layout
        self.attack_analytics.grid(row=0, column=1, sticky=t.N + t.E + t.S + t.W)
        self.configuration.grid(row=0, column=2, sticky=t.N + t.E + t.S + t.W)
        # frames around widgets
        self.app_status_frame = t.LabelFrame(self, text="Status")
        self.processes_s_frame = t.LabelFrame(self, text="Processes stopped")
        self.processes_not_s_frame = t.LabelFrame(self, text="Stopping failures")
        self.exemption_frame = t.LabelFrame(self, text="Program exceptions")
        self.console_frame = t.LabelFrame(self, text="Console output")
        self.start_stop = t.LabelFrame(self, text="Main")
        self.list_control = t.LabelFrame(self, text="Modify...")
        #variables
        self.app_status = t.StringVar(self,"Started")
        self.total_removals = t.StringVar(self, "0")
        self.total_failures_to_remove = t.StringVar(self, "0")
        self.total_duplicate_removals = t.StringVar(self, "0")
        #status labels
        self.app_status_label = t.Label(self.app_status_frame, textvariable=self.app_status, foreground="green", background="black")
        self.total_removals_label = t.Label(self.app_status_frame, textvariable=self.total_removals, foreground="green", background="black")
        self.total_failures_to_remove_label = t.Label(self.app_status_frame, textvariable=self.total_failures_to_remove, foreground="red", background="black")
        self.total_duplicate_removals_label = t.Label(self.app_status_frame, textvariable=self.total_duplicate_removals, foreground="light green", bg="black")
        # listboxes
        self.console = scrolledtext.ScrolledText(self.console_frame)
        self.psl_scroll = t.Scrollbar(self)
        self.pnsl_scroll = t.Scrollbar(self)
        self.exemptions_scroll = t.Scrollbar(self)
        self.exception_l = t.Listbox(self.exemption_frame, selectbackground="dark blue", selectforeground="green", yscrollcommand=self.exemptions_scroll.set)
        self.processes_stopped_l = t.Listbox(self.processes_s_frame, selectbackground="azure2",selectforeground="azure", yscrollcommand=self.psl_scroll.set)
        self.processes_not_stopped_l = t.Listbox(self.processes_not_s_frame, selectbackground="azure2", selectforeground="azure", yscrollcommand=self.pnsl_scroll.set)
        self.psl_scroll.config(command=self.processes_stopped_l.yview)
        self.pnsl_scroll.config(command=self.processes_not_stopped_l.yview)
        self.exemptions_scroll.config(command=self.exception_l.yview)
        #assign positions
        self.app_status_frame.grid(column=4,row=3, rowspan=4, sticky=t.N + t.E + t.S)
        self.app_status_label.grid(column=1,row=1, sticky=t.N + t.E + t.S + t.W)
        self.total_removals_label.grid(column=1, row=2, sticky=t.N + t.E + t.S + t.W)
        self.total_duplicate_removals_label.grid(column=1, row=3, sticky=t.N + t.E + t.S + t.W)
        self.total_failures_to_remove_label.grid(column =1 , row =4, sticky=t.N + t.E + t.S + t.W)
        self.processes_s_frame.grid(column=1, row=1)
        self.processes_stopped_l.pack(fill=t.BOTH)
        self.processes_not_s_frame.grid(column=2, row=1)
        self.psl_scroll.grid(column=1, row=1, sticky=t.N + t.E + t.S)
        self.pnsl_scroll.grid(column=2, row=1, sticky=t.N + t.E + t.S)
        self.exemptions_scroll.grid(column=3, row=1, sticky=t.N + t.E + t.S)
        self.processes_not_stopped_l.pack(fill=t.BOTH)
        self.exemption_frame.grid(column=3, row=1)
        self.exception_l.pack(fill=t.BOTH)
        self.console_frame.grid(column=1,row=2,columnspan=3,rowspan=2)
        self.console.grid(column=1,row=2,columnspan=3,rowspan=2, sticky=t.N + t.E + t.S + t.W)
        self.start_stop.grid(column=4, row=2, columnspan=1, sticky=t.N + t.E + t.S + t.W)
        self.list_control.grid(column=4, row=1, columnspan=1, sticky=t.N + t.E + t.S + t.W)
        #button widgets
        #app control
        self.leave = t.Button(self.start_stop, command=self.quitApp, text="Quit")
        self.add_application_to_exception_list = t.Button(self.start_stop, text="Add Program Exception", command=self.addException)
        self.startb = t.Button(self.start_stop, text="Start/Restart", command=self.start)
        self.stop = t.Button(self.start_stop, text="Stop", command=self.stop_ips)
        #assign to start-stop
        self.startb.grid(column=1, row=1, columnspan=1, sticky= t.N + t.S + t.W + t.E)
        self.add_application_to_exception_list.grid(column=1, row=3, columnspan=1, sticky= t.N + t.S + t.W + t.E)
        self.leave.grid(column=1, row=4, columnspan=1, sticky= t.N + t.S + t.W + t.E)
        self.stop.grid(column=1, row=2, columnspan=1, sticky= t.N + t.S + t.W + t.E)
        #list_control
        self.exception_remove = t.Button(self.list_control, command=self.removeFromExemptBox, text="Remove exception...")
        self.exception_add = t.Button(self.list_control, command=self.addToExemptBox, text="Add exception by name")
        #assign to list_control
        self.exception_add.grid(column=1, row=1, columnspan=1, sticky= t.N + t.S + t.W + t.E)
        self.exception_remove.grid(column=1, row=2, columnspan=1, sticky= t.N + t.S + t.W + t.E)
    def removeFromExemptBox(self):
        cursor_location = self.exception_l.curselection()[0]
        temp = self.exception_l.get(cursor_location)
        self.exception_l.delete(cursor_location)
        print("Removed: " + str(temp))
        return
    def addToExemptBox(self):
        window = t.Toplevel(self)
        def close_dialogue():
            window.destroy()
        label1 = t.Label(window, text="Program name: ")
        input1 = t.Entry(window)
        def add_to_exceptions():
            self.lock.acquire()
            self.exception_l.insert(0, input1.get())
            self.instance.accepted_apps.append(input1.get())
            self.lock.release()
            window.destroy()
        input1.insert(10, "Edge.exe")
        cancel = t.Button(window, text="Cancel", command = close_dialogue)
        add = t.Button(window, text="Add to exceptions", command = add_to_exceptions)
        #add to grid
        label1.pack()
        input1.pack()
        add.pack()
        cancel.pack()
        window.grid()
        return
    def quitApp(self):
        print("Saved exempted-app list to IPS.conf.")
        with open("./IPS.conf", "w") as f:
            for x in self.instance.accepted_apps:
                if (x == "System"):
                    continue
                f.write(x)
                f.write(",")
            f.flush()
        self.stop_ips()
        self.quit()
    def addException(self):
        exception_box = filedialog.askopenfilenames(initialdir = "/", title="Add file binaries that run in the background to the exemption list", filetypes=(("Binary files","*.exe"),("all files","*.*")))
        f_names = []
        for x in exception_box:
            temp = str(x).split("/").pop()
            f_names.append(temp)
            self.lock.acquire()
            self.insertToProgToExempt(temp)
            self.instance.accepted_apps.append(temp)
            self.lock.release()
        print(f_names)
    def getIndexOfProcessInList(self, listbox, duple):
        alist = listbox.get(t.FIRST, t.END)
        val = -1
        for x in alist:
            val += 1
            regex = re.compile(duple[0])
            b = x.match(regex)
            if b != None:
                return val
        return -1
    def getCountInString(self, string, start_delimiter, end_delimiter):
        beginning = re.compile(" \\<^[0-9].?")
        ending = re.compile("\\>")
        start = beginning.match(string)
        end = ending.match(string)
        if end != None and start != None:
            x1 = start.start()
            x2 = end.start()
            print("string[x1:x2] value created: " + string[x1:x2])
            return int(string[x1:x2])
        else:
            raise Exception("No match found in string")
    def incrementCountInString(self, string):
        beginning = re.compile(" \\<^[0-9].?")
        ending = re.compile("\\>")
        start = beginning.match(string)
        end = ending.match(string)
        if end != None and start != None:
            x1 = start.start()
            x2 = end.start()
            print("string[x1:x2] value created: " + string[x1:x2])
            count = int(string[x1:x2])
            count += 1
            f = string[:start] + str(count) + string[end:]
            print("result string: " + f)
            return f
        else:
            raise Exception("No match found in string")
    def insertToListBoxDuple(self, duple, listbox):
        self.lock.acquire()
        val = self.getIndexOfProcessInList(listbox, duple)
        if val == -1:
            listbox.insert(index=t.END, chars=duple[0] + " " + duple[1] + " <1>")
        else:
            listbox.insert(index=t.END, chars=self.incrementCountInString(listbox.get(val)))
        self.lock.release()
    def insertToConsole(self, text):
        self.lock.acquire()
        self.console.insert(chars=text, index=t.END)
        self.lock.release()
    def insertToProgToExempt(self, prog):
        self.exception_l.insert(0, prog)
    def getExemptionList(self):
        return self.exception_l.get(0)
    def start(self):
        self.app_status_label.config(background="black", foreground="purple")
        self.app_status.set("Stopping")
        self.instance.stopKillProcessesLoop()
        self.instance.stopNetstatLoops()
        self.instance.stopTsklistLoops()
        self.app_status.set("Started")
        self.app_status_label.config(background="black", foreground="green")
        self.main()
    def main(self):
        self.instance = ips(self)
        self.instance.thread_list = []
        self.instance.thread_event_list = []
        self.instance.ParseConfig()
        self.instance.SelectCommandsByOS()
        sessions_search_loop = threading.Thread(target=self.instance.SessionsLoop)
        self.instance.thread_list.append(sessions_search_loop)
        tasklist_loop = threading.Thread(target=self.instance.TasklistLoop)
        self.instance.thread_list.append(tasklist_loop)
        sessions_search_loop.start()
        tasklist_loop.start()
        kill_processes_loop = threading.Thread(target=self.instance.KillProcessLoop)
        self.instance.thread_list.append(kill_processes_loop)
        kill_processes_loop.start()
    def stop_ips(self):
        self.app_status.set("Stopping")
        self.app_status_label.config(background="black", foreground="orange")
        self.instance.stopKillProcessesLoop()
        self.instance.stopNetstatLoops()
        self.instance.stopTsklistLoops()
        self.app_status.set("Stopped")
        self.app_status_label.config(background="black", foreground="red")
class ips(Gui):
    'The class that determines which processes to stop that are unauthoraized for a given platform given a set of acceptable parameters.'
    # client variables.
    ip = ""
    total_kill_threads = 0
    config_parsed = False
    mode = 0  # modes are 0) load allowed applications from file for standalone IPS. 1) use argument parameters for allowing certain files.
    thread_list = []  # threads in order: Sessions loop method, tasklist loop method, kill processes loop, gui loop, update variables loop
    thread_event_list = [] #same order as above, but for requesting a stop.
    maxThreads = 4
    port = -1
    server_address = ()
    # Toggling variables
    usingLog1 = True
    # Lists
    pid_set = []  # set of unique PID's for force kill of the process.
    applications_to_kill = []
    kill_processes_started = []
    print_out_txt = ""
    # Variables for configuration depending on what Operating system you are using.
    possible_CLI_commands = [["netstat", "-b"], ["sudo", "lsof", '-i'], ["sudo", "lsof", '-i']]
    platform_specific_sessions_args = []
    # modify this to your desire.
    accepted_apps = ['System']
    programs_not_stopped = []
    # Regexes for parsing config.
    comma = re.compile(",")
    # Regexes for parsing netstat -b output.
    left_bracket = re.compile("\[")
    right_bracket = re.compile("]")
    # Regexes for parsing tasklist.
    newline = re.compile("\n")
    pid = re.compile("PID:          ")

    def matchArgs(self, args=[]):
        hasIP = False
        hasPort = False
        count = 0
        for arg in args:
            if arg[0] == "-ip":
                self.ip = arg[1]
                hasIP = True
            elif arg[0] == "-port":
                hasPort = True
                self.port = int(arg[1])
            elif arg[0] == "-Tc":
                self.maxThreads = int(arg[1])
            elif arg[0] == "-allow":
                l = arg[1].split(",")
                for x in range(0, len(l)):
                    self.accepted_apps.append(l[x])
            elif arg[0] == "-m":
                if arg[1] == "file":
                    self.mode = 0
                elif arg[1] == "cli":
                    self.mode = 1
            count += 1
            if count >= len(args):
                break
        l = [hasIP, hasPort]
        if all(l):
            self.server_address = (self.ip, self.port)
            self.gui.insertToConsole("Connects via TCP/IP to: <ip: " + self.server_address[0] + ", port: " + str(self.server_address[1]) + ">")

    def __init__(self, gui):
        self.gui = gui
        arguments = a.ArgumentMatcher()
        ips_argD = {
            "-m": "Mode of the app: use \"file\" for loading allowed apps from IPS.conf, or use \"cli\" for just sending a comma-delimited list of app names.",
            "-Tc": "Max threads.",
            "-ip": "IPv4 address to IPS Logger.",
            "-port": "Dedicated port number for IPS Logger.",
            "-allow": "List of applications allowed to use the application layer"}
        arguments.setCharKeys(ips_argD)
        arguments.sortArgumentParameters()
        l = arguments.getSortedArguments()
        self.matchArgs(l)
        print(l)
    def SelectCommandsByOS(self):
        if sys.platform == 'win32':
            self.platform_specific_sessions_args = self.possible_CLI_commands[0]
        elif sys.platform == 'linux' or sys.platform == 'linux2':
            self.platform_specific_sessions_args = self.possible_CLI_commands[1]
        elif sys.platform == 'darwin':
            self.platform_specific_sessions_args = self.possible_CLI_commands[1]

    def ParseConfig(self):
        if self.config_parsed:
            return
        else:
            self.config_parsed = True
        if self.mode == 0:
            string = ""
            with open(sys.path[0] + '\\IPS.conf', 'r', encoding='utf-8') as f:
                for line in f.readlines():
                    string += line
            while True:
                z = self.comma.search(string)
                if type(z) != type(None):
                    b = z.span()
                    self.accepted_apps.append(string[:b[1] - 1])
                    string = string[b[1]:]
                else:
                    break
            self.gui.insertToConsole("Applications that can send packets on the LAN and WAN are: " + str(
                self.accepted_apps) + "\n")
            print("Applications that can send packets on the LAN and WAN are: " + str(
                self.accepted_apps))
            for i in range(len(self.accepted_apps)):
                self.gui.insertToProgToExempt(self.accepted_apps[i])
        if not self.server_address == ():
            self.gui.insertToConsole("Application will attempt to connect the IPS server with an IPv4 address of " + str(
                self.server_address[0]) + ":" + str(self.server_address[1]) + "\n")
            print("Application will attempt to connect the IPS server with an IPv4 address of " + str(
                self.server_address[0]) + ":" + str(self.server_address[1]))

    def SessionsLoop(self):
        self.gui.insertToConsole("Starting local-computer sessions-layer watch service.\n")
        #print("Starting local-computer sessions-layer watch service.")
        self.thread_event_list.append(threading.Event())
        while True:
            if self.thread_event_list[0].is_set():
                break
            self.lock.acquire()
            x = self.maxThreads + self.total_kill_threads
            self.lock.release()
            if threading.active_count() <= x:
                t = threading.Thread(target=self.SaveOutputFromNetstat,
                                     args=(self.platform_specific_sessions_args,))
                self.gui.insertToConsole("Starting new sessions-search thread [" + t.getName() + "]\n")
                print("Starting new sessions-search thread [" + t.getName() + "]")
                t.start()

    def TasklistLoop(self):
        self.gui.insertToConsole("Starting background task watch service.\n")
        #print("Starting background task watch service.")
        self.thread_event_list.append(threading.Event())
        while True:
            if self.thread_event_list[1].is_set():
                break
            startupinfo = sp.STARTUPINFO()
            t = sp.Popen(["tasklist", "/fo", "LIST"], startupinfo = startupinfo, stdout=sp.PIPE, shell=True)
            out = t.communicate()[0]
            self.ParseTasklistOut(out)

    def ParseNetstatOut(self, string):
        lock = threading.Lock()
        while True:
            z = self.left_bracket.search(string)
            if type(z) != type(None):
                b = z.span()
                string = string[b[1]:]
            else:
                break
            z = self.right_bracket.search(string)
            if type(z) != type(None):
                print("Gets to if statement before MatchApplication.")
                b = z.span()
                temp = string[:b[1] - 1]
                if self.MatchApplication(temp) == False and not self.AlreadyAdded(self.applications_to_kill, temp):
                    print("Gets to if statement block with applications_to_kill.")
                    self.applications_to_kill.append(temp)
                string = string[b[1]:]
            lock.acquire()
            self.gui.insertToConsole("Processes with sessions: " + str(self.applications_to_kill) + "\n")
            print("Processes with sessions: " + str(self.applications_to_kill))
            lock.release()
    def stopNetstatLoops(self):
        self.thread_event_list[0].set()
    def stopTsklistLoops(self):
        self.thread_event_list[1].set()
    def stopKillProcessesLoop(self):
        self.thread_event_list[2].set()
    def combineTwoListsWithSpace(self, list1, list2):
        new_list = []
        count = 0
        for text in list1:
            new_list.append(text + " " + list2[count])
            count += 1
        return new_list

    def ParseTasklistOut(self, string):
        'This method uses the output from the tasklist subprocess and creates a unique set of PID\'s to stop'
        string = string.decode(encoding="utf-8", errors="ignore")
        # print("Get's to parsetasklistout method.")
        for str in self.applications_to_kill:
            pattern = re.compile(str)
            matches = re.finditer(pattern, string)
            temp = string
            for match in matches:
                temp = string[match.end():]
                mo = re.search(self.pid, temp)
                temp = temp[mo.end():]
                mo = re.search(self.newline, temp)
                temp = temp[0: mo.end() - 1]
                bool = self.ShouldAddPID(temp)
                if bool:
                    self.lock.acquire()
                    self.pid_set.append(temp)
                    self.lock.release()
                    del temp, mo, bool
                    # sys.exit()

    def ShouldAddPID(self, string):
        'if a PID value has already been added to the list, it will not add another of the same PID value'
        for pid in self.pid_set:
            if pid == string:
                return False
        return True

    def MatchApplication(self, string):
        'matches applications that may run on the operating system with those applications that netstat has identified as using the network.'
        for app in self.accepted_apps:
            if app == string:
                return True
        return False

    def AlreadyAdded(self, list, string):
        'works with tasklist and netstat results'
        for item in list:
            if item == string:
                return True
        return False
    def killProcess(self, pid, name):
        s = sp.Popen(args=["taskkill", "/pid", pid, "/f"], shell=True,
                     stdout=sp.PIPE)
        out = s.communicate()[0]
        print("Output: " + str(out))
        now = datetime.datetime.now()
        if s.returncode == 0:
            #CompletedProcess(args=["taskkill", "/pid", pid, "/f"], returncode=0).check_returncode()
            self.SendDataToServer(pid, name)
            self.lock.acquire()
            self.gui.insertToConsole("Stopped <pid: " + pid + ", name: " + name + "> and its children processes.\n")
            #print("Stopped <pid: " + pid + ", name: " + name + "> and its children processes.")
            self.gui.increStringVar(self.gui.total_removals)
            self.gui.insertToListBoxDuple((name,"[" + str(now.month) + "/" + str(now.day) + "/" + str(now.year) + " " + str(now.hour) + ":" + str(now.minute) + "]"))
            self.kill_processes_started.remove(pid)
            self.lock.release()
            ply.facades.notification.Notification(
                title= name + 'stopped',
                message = name + ' stopped, with p.i.d. ' + pid + '.',
                app_name='Ideal Prevention System',
                app_icon= 'favicon.ico',
                timeout= '3',
                ticker= 'Process stopped...'
            )
            del pid
        else:
            #print("Could not stop <pid: " + pid + ", name: " + name + ".>")
            self.lock.acquire()
            self.gui.increStringVar(self.gui.total_failures_to_remove)
            self.gui.insertToConsole("Could not stop <pid: " + pid + ", name: " + name + ".>\n")
            self.gui.insertToListBoxDuple((name, "[" + str(now.month) + "/" + str(now.day) + "/" + str(now.year) + " " + str(now.hour) + ":" + str(now.minute) + "]"))
            self.kill_processes_started.remove(pid)
            self.lock.release()
            ply.facades.notification.Notification(
                title=name + 'could not be stopped',
                message=name + ' was not stopped, with p.i.d. ' + pid + '.',
                app_name='Ideal Prevention System',
                app_icon='favicon.ico',
                timeout='3',
                ticker='Process stopped...'
            )
            del pid
    def KillProcessLoop(self):
        self.gui.insertToConsole("Starting LAN/WAN intrusion prevention system.\n")
        #print("Starting LAN/WAN intrusion prevention system.")
        self.thread_event_list.append(threading.Event())
        while True:
            while len(self.pid_set) > 0:
                if self.thread_event_list[2].is_set():
                    break
                self.lock.acquire()
                pid = self.pid_set.pop()
                self.lock.release()
                name = ""
                try:
                    s = sp.Popen(["tasklist", "/fi", "pid eq " + pid], shell=True,
                                 stdout=sp.PIPE)  # tasklist /fi "pid eq 4444"
                    name = s.communicate()[0]
                    name = name.decode(encoding="utf-8", errors="ignore")
                    print("Stopped " + name)
                except:
                    self.gui.insertToConsole("Error getting name associated with pid using tasklist /fi \"pid eq 234234\" format\n")
                    print("Error getting name associated with pid using tasklist /fi \"pid eq 234234\" format")
                b = False
                for p in self.kill_processes_started:
                    if p == name:
                        b = True
                        break
                if not b:
                    self.kill_processes_started.append(pid)
                    t = threading.Thread(target=self.killProcess, args=(pid, name))
                    t.start()
    def SendDataToServer(self, pid, name):
        sockme = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        now = datetime.datetime.now()
        string = "HOST: " + sock.gethostname() + "P_Name: " + name + ", PID: " + str(pid) + ", TIME: " + str(now.month) + "/" + str(now.day) + "/" + str(now.year) + " " + str(now.hour) + ":" + str(now.minute)
        try:
            print("Connecting to this server: " + str(self.server_address))
            sockme.connect(self.server_address)
            sockme.sendall(string.encode())
            response = sockme.recv().decode()
            self.gui.insertToConsole("Response: " + response + "\n")
        except:
            self.gui.insertToConsole("Could not send data to server because server is unreachable.\n")
            print("Could not send data to server because server is unreachable.")

    def ToggleLogFile(self):
        if self.usingLog1:
            self.usingLog1 = False
        else:
            self.usingLog1 = True

    def SaveOutputFromNetstat(self, args):
        # print("Saving output from Netstat.")
        # print(str(args))
        startupinfo = sp.STARTUPINFO()
        s = sp.Popen(args, startupinfo=startupinfo, stdout=sp.PIPE, shell=True)
        out = s.communicate()[0]
        # out = sp.check_output(args)
        string = out.decode(encoding='utf-8', errors='ignore')
        log1 = os.path.getsize(sys.path[0] + '\\log.lg')
        log2 = os.path.getsize(sys.path[0] + '\\log2.lg')
        if log1 > 1000000 and log2 > 1000000:  # if the size of this file is greater than 1MB.
            self.ToggleLogFile()
            # empty contents of log.lg file...
            if self.usingLog1:
                file = '\\log.lg'
            else:
                file = '\\log2.lg'
            with open(sys.path[0] + file,
                      'w'):  # empties the other log file that the IPS will now use to log data.  This way it rotates.
                pass
        elif log1 > 1000000 and log2 < 1000000:
            self.usingLog1 = False
            file = '\\log2.lg'
        elif log1 < 1000000 and log2 > 1000000:
            self.usingLog1 = True
            file = '\\log.lg'
        else:
            if self.usingLog1:
                file = '\\log.lg'
            else:
                file = '\\log2.lg'
        with open(sys.path[0] + file, 'a+', encoding='utf-8') as f:
            now = datetime.datetime.now()
            f.write(
                "\n**** Date was " + str(now.month) + "/" + str(now.day) + "/" + str(
                    now.year) + " & time was " + str(
                    now.hour) + ":" + str(now.minute) + "." + str(now.second) + " ****\n")
            string = out.decode(encoding='utf-8', errors='ignore')
            string.replace('\\n', '\n')
            string.replace('\\r', '\n')
            string.replace('\'b', '')
            f.write(string)
        self.ParseNetstatOut(string)
        del string

gui = Gui()