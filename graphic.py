import tkinter as tk
import tkinter.ttk as ttk
from tkinter import PanedWindow

class graphics:
    window = ''
    def __init__(self):
        window = tk.Tk()
        window.geometry('2000x1200+200+200')
        window.title('Capture')
        window.option_add(
            '*tearOff',
            False
        )

        menubar = tk.Menu(window)
        window['menu'] = menubar

        menu_operate = tk.Menu(menubar)
        menu_file = tk.Menu(menubar)
        menu_config = tk.Menu(menubar)

        #menu_operate
        menu_operate.add_command(
            label = 'begin',
        )
        menu_operate.add_command(
            label = 'pause',
        )
        menu_operate.add_command(
            label = 'stop',
        )

        #menu_file
        menu_file.add_command(
            label = 'open file(pcap)'
        )
        menu_file.add_command(
            label = 'save file'
        )

        #menu_config
        menu_config.add_command(
            label = 'choose device',
            command = self.choose_device,
        )

        menubar.add_cascade(
            label = 'operate',
            menu = menu_operate
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
            fill = 'x'
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
            text = 'flter'
        )
        btn_filter_filter.place(
            x = 340,
            y = 6
        )
        btn_begin = tk.Button(
            master = frm_filter,
            text = 'begin'
        )
        btn_begin.place(
            x = 400, 
            y = 6
        )
        btn_pause = tk.Button(
            master = frm_filter,
            text = 'pause'
        )
        btn_pause.place(
            x = 470, 
            y = 6
        )
        btn_stop = tk.Button(
            master = frm_filter,
            text = 'stop'
        )
        btn_stop.place(
            x = 540,
            y = 6
        )

        # container a packet_list , analyse packet and hexdump
        panel_packet_area = PanedWindow(
            window,
            orient = 'vertical'
        )

        tree_packet_list = ttk.Treeview(
            panel_packet_area,
            selectmode = 'browse',
            height = 20
        )
        tree_packet_list['columns'] = ('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        tree_packet_list_each_column_width = [10, 100, 200, 200, 50, 300, 600]
        tree_packet_list['show'] = 'headings'
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
            fill = 'both'
        )

        panel_packet_area.add(tree_packet_list)

        tree_packet_analyse = ttk.Treeview(
            panel_packet_area, 
            show = 'tree',
            selectmode = 'browse',
            height = 20
        )
        tree_packet_analyse.pack(fill = 'both')
        tree_packet_analyse.pack(fill = 'both')

        panel_packet_area.add(tree_packet_analyse)

        tree_packet_hexdump = tk.Text(
            panel_packet_area, 
            height = 18, 
            state = 'disabled'
        )
        panel_packet_area.add(tree_packet_hexdump)

        panel_packet_area.pack(
            fill = 'both'
        )
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
            text = "It's decided to be you!"
        )
        choose_device_button.pack(
            pady = 10
        )

        choose_device_window.mainloop()


def run():
    _ = graphics()

run()


