import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import BOTTOM, DISABLED, HORIZONTAL, LEFT, NORMAL, RIGHT, TOP, VERTICAL, Y, YES, PanedWindow
from capture import list_interface
from capture import get_choose_if_name
from capture import start_capture
from capture import pause_capture
from capture import stop_capture
from capture import analyse_packet
from capture import save_file_accordance_file_path
from capture import is_Stop
from capture import set_state_stop
from capture import read_file_accordance_file_path
from capture import set_filter
from capture import get_thread

def filter(filter):
    set_filter(filter)





def save_file():
    if not is_Stop():
        messagebox.showwarning(
            message = "Save file require you stop capture packet",
            title = "Save warn"
        )
    else:
        file_path = filedialog.asksaveasfilename(
            defaultextension = ".pcap",
            filetypes = [("pcap file", "*.pcap")],
            title = "choose save file"
        )
        if not file_path: return
        save_file_accordance_file_path(file_path)

def read_file(list_tree, analyse_tree, text_area):
    file_path = filedialog.askopenfilename(
        filetypes = [("pcap file", "*.pcap")],
        title = "open pcap file"
    )
    if not file_path: return
    list_tree.delete(*list_tree.get_children())
    analyse_tree.delete(*analyse_tree.get_children())
    text_area['state'] = NORMAL
    text_area.delete(1.0, 'end')
    text_area['state'] = DISABLED

    read_file_accordance_file_path(file_path, list_tree)


def closeCallBack(win):
    set_state_stop()
    # ensure thread can be close
    get_thread().join()
    if determine_close():
        win.destroy()

def determine_close():
    return messagebox.askyesno(
        message = "Are you sure to exit this program?",
        icon = "question",
        title = "Are you sure?"
    )


class graphics:
    def __init__(self):
        window = tk.Tk()
        window.geometry('2000x1200+200+200')
        window.title('Capture')
        window.option_add(
            '*tearOff',
            False
        )
        self.if_list = list_interface()
        window.resizable(False, False)
        window.protocol("WM_DELETE_WINDOW", lambda : closeCallBack(window))

        menubar = tk.Menu(window)
        window['menu'] = menubar

        menu_file = tk.Menu(menubar)
        menu_config = tk.Menu(menubar)

        #menu_file
        menu_file.add_command(
            label = 'open file(pcap)',
            command = lambda : read_file(tree_packet_list, tree_packet_analyse, text_packet_hexdump)
        )
        menu_file.add_command(
            label = 'save file',
            command = save_file
        )

        #menu_config
        menu_config.add_command(
            label = 'choose interface',
            command = self.choose_device,
        )

        menubar.add_cascade(
            label = 'file',
            menu = menu_file
        )

        menubar.add_cascade(
            label = 'config',
            menu = menu_config
        )

        # filter and quick begin pause and stop
        frm_filter = tk.Frame(
            master = window,
            height = 50, 
            relief = 'raised',
            borderwidth = 1
        )
        frm_filter.pack(
            fill = 'x',
        )
        ety_filter = tk.Entry(
            master = frm_filter,
            width = 40
        )
        ety_filter.place(
            x = 5,
            y = 10
        )
        btn_filter_filter = tk.Button(
            master = frm_filter, 
            text = 'flter',
            command = lambda : filter(ety_filter.get())
        )
        btn_filter_filter.place(
            x = 340,
            y = 6
        )
        btn_begin = tk.Button(
            master = frm_filter,
            text = 'begin',
            command = lambda : start_capture(tree_packet_list, btn_begin, btn_pause, btn_stop, text_packet_hexdump, tree_packet_analyse)
        )
        btn_begin.place(
            x = 400, 
            y = 6
        )
        btn_pause = tk.Button(
            master = frm_filter,
            text = 'pause',
            command = lambda : pause_capture(btn_pause)
        )
        btn_pause.place(
            x = 470, 
            y = 6
        )
        btn_stop = tk.Button(
            master = frm_filter,
            text = 'stop',
            command = lambda : stop_capture(btn_begin, btn_pause, btn_stop)
        )
        btn_stop.place(
            x = 540,
            y = 6
        )

        btn_begin['state'] = NORMAL
        btn_pause['state'] = DISABLED
        btn_stop['state'] = DISABLED

        panel_packet_area = PanedWindow(
            window,
            orient = 'vertical'
        )
        # container a packet_list , analyse packet and hexdump
        #packet_list
        tree_packet_list_frame = tk.Frame()
        tree_packet_list_frame_for_Y_Scollbar = tk.Frame(tree_packet_list_frame)

        tree_packet_list = ttk.Treeview(
            tree_packet_list_frame,
            selectmode = 'browse',
            height = 20
        )
        tree_packet_list['columns'] = ('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        tree_packet_list_each_column_width = [10, 100, 200, 200, 50, 300, 600]
        tree_packet_list['show'] = 'headings'
        tree_packet_list.bind("<<TreeviewSelect>>", lambda event: analyse_packet(event, tree_packet_list, tree_packet_analyse, text_packet_hexdump))
        for column_name, column_width in zip(tree_packet_list['columns'], tree_packet_list_each_column_width):
            tree_packet_list.column(
                column_name, 
                width = column_width
            )
            tree_packet_list.heading(
                column_name, 
                text = column_name
            )

        tree_packet_list.pack(
            fill = 'both',
            side = LEFT,
            expand = YES
        )


        tree_packet_list_Yscrollbar = tk.Scrollbar(tree_packet_list_frame_for_Y_Scollbar, orient = VERTICAL, command = tree_packet_list.yview)
        tree_packet_list.config(yscrollcommand = tree_packet_list_Yscrollbar.set)
        tree_packet_list_Yscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
        tree_packet_list_frame_for_Y_Scollbar.pack(fill='both', expand=YES)

        tree_packet_list_frame.pack(side = TOP, fill = 'both', expand=YES)

        panel_packet_area.add(tree_packet_list_frame)


        # analyse area
        tree_packet_analyse_frame = tk.Frame()
        tree_packet_analyse_frame_for_Y_Scollbar = tk.Frame(tree_packet_analyse_frame)

        tree_packet_analyse = ttk.Treeview(
            tree_packet_analyse_frame, 
            show = 'tree',
            selectmode = 'browse',
            height = 20
        )
        tree_packet_analyse.pack(
            fill = 'both',
            side = LEFT,
            expand = YES
        )

        tree_packet_analyse_Yscrollbar = tk.Scrollbar(tree_packet_analyse_frame_for_Y_Scollbar, orient = VERTICAL, command = tree_packet_analyse.yview)
        tree_packet_analyse.config(yscrollcommand = tree_packet_analyse_Yscrollbar.set)
        tree_packet_analyse_Yscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
        tree_packet_analyse_frame_for_Y_Scollbar.pack(fill='both', expand=YES)

        tree_packet_analyse_frame.pack(side = TOP, fill = 'both', expand=YES)

        panel_packet_area.add(tree_packet_analyse_frame)

        #hexdump area
        text_packet_hexdump_frame = tk.Frame()
        text_packet_hexdump_frame_for_Y_Scollbar = tk.Frame(text_packet_hexdump_frame)

        text_packet_hexdump = tk.Text(
            text_packet_hexdump_frame, 
            state = 'disabled'
        )

        text_packet_hexdump.pack(side = 'left', fill = 'both', expand = True)


        text_packet_hexdump_Yscollbar = tk.Scrollbar(text_packet_hexdump_frame_for_Y_Scollbar, orient = VERTICAL, command = text_packet_hexdump.yview)
        text_packet_hexdump.config(yscrollcommand = text_packet_hexdump_Yscollbar.set)
        text_packet_hexdump_Yscollbar.pack(side = RIGHT, fill = Y, expand = YES)
        text_packet_hexdump_frame_for_Y_Scollbar.pack(side = 'top', fill = 'both', expand = YES)

        text_packet_hexdump_frame.pack(side = TOP, fill = 'both', expand = YES)

        panel_packet_area.pack(
            fill = 'both',
        )
        panel_packet_area.add(text_packet_hexdump_frame)

        window.mainloop()

    def choose_device(self):
        choose_device_window = tk.Tk()
        choose_device_window.geometry('500x280')
        choose_device_window.title('choose device')

        choose_device_tree = ttk.Treeview(
            choose_device_window,
            show = 'tree'
        )
        choose_device_tree.pack(
            fill = 'both',
            padx = 5, 
            pady = 5
        )


        choose_device_button = tk.Button(
            choose_device_window, 
            text = "It's decided to be you!",
            command = lambda : get_choose_if_name(choose_device_window, choose_device_tree)

        )
        choose_device_button.pack(
            pady = 10
        )

        for item in self.if_list:
            choose_device_tree.insert('', 'end', text = item)


        choose_device_window.mainloop()


