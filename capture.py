import tkinter
import scapy.all as scapy
import threading
from tkinter import DISABLED, NORMAL, constants
from time import sleep

state = {
    'interface_name' : 'wlp0s20f3',
    'first_time' : 0.0,
    'packet_number' : 0,
    'is_Stop':False,
    'is_Pause':False,
    'capture_packet_array':[],
    'filter':""
}

def TODO(txt):
    print(txt)
    assert(0)

def list_interface():
    return scapy.get_if_list()

def get_choose_if_name(win, tv):
    iid = tv.focus()
    if(not(iid)): return
    state['interface_name'] = tv.item(iid)['text']
    win.destroy()

def packet_handle(pkt, tree):
    if state['is_Pause'] or state['is_Stop']: return

    state['capture_packet_array'].append(pkt)

    total_layer = pkt.layers()
    total_layer_numer = len(total_layer)

    # count number of packet
    state['packet_number'] += 1

    # get each packet sent/receive times
    if state['first_time'] == 0:
        state['first_time'] = pkt.time
    packet_time = round(pkt.time - state['first_time'], 6)

    # get each packet Source and Destination
    ip_layer_index = 0
    for index in range(total_layer_numer):
        if "IP" in str(total_layer[index]):
            ip_layer_index = index
    # print(pkt.summary())
    packet_srouce = pkt[ip_layer_index].src
    packet_destination = pkt[ip_layer_index].dst

    # get top level protocol name
    laster_protocol_index = total_layer_numer - 1;
    if "Raw" in pkt:
        laster_protocol_index -= 1
    packet_protocol = pkt[laster_protocol_index].name

    # get each packet length
    packet_length = len(pkt)

    # get each packet Info
    packet_info = pkt.summary()

    # print("-" * 100)
    tree.insert('', 'end', state['packet_number'], value = (state['packet_number'], packet_time, packet_srouce, packet_destination, packet_protocol, packet_length, packet_info))
    tree.update_idletasks()



def is_Stop(_):
    return state['is_Stop']

def capture(tree):
    scapy.sniff(
        iface = state['interface_name'],
        prn = lambda pkt: packet_handle(pkt, tree),
        stop_filter = is_Stop,
        filter = state['filter']
    )

def start_capture(tree_list, btn_begin, btn_pause, btn_stop, hex_area, tree_analyse):
    if not state['is_Pause']:
        state['is_Stop'] = False
        state['packet_number'] = 0
        state['capture_packet_array'].clear()
        state['first_time'] = 0
        tree_list.delete(*tree_list.get_children())
        tree_analyse.delete(*tree_analyse.get_children())
        hex_area['state'] = NORMAL
        hex_area.delete(1.0, 'end')
        hex_area['state'] = DISABLED


    t = threading.Thread(target=lambda: capture(tree_list), name = 'capture packet')
    t.start()

    btn_begin['state'] = DISABLED
    btn_pause['state'] = NORMAL
    btn_stop['state'] = NORMAL

def pause_capture(btn):
    if btn['text'] == 'pause':
        btn['text'] = 'reset'
        state['is_Pause'] = True
    elif btn['text'] == 'reset':
        btn['text'] = 'pause'
        state['is_Pause'] = False

def stop_capture(btn_begin, btn_pause, btn_stop):
    state['is_Stop'] = True
    state['is_Pause'] = False
    btn_pause['text'] = 'pause'
    btn_begin['state'] = NORMAL
    btn_pause['state'] = DISABLED
    btn_stop['state'] = DISABLED

def analyse_packet(event, list_tree, analyse_tree, hex_area):
    if(not list_tree.focus()): return
    pkt = state['capture_packet_array'][int(list_tree.focus()) - 1]

    # clear analyse area
    analyse_tree.delete(*analyse_tree.get_children())

    show_result = pkt.show(dump = True)
    result_to_lines = show_result.split('\n')
    parent_iid = ''
    for line in result_to_lines:
        if line.startswith('#'):
            line = line.strip('# ')
            parent_iid = analyse_tree.insert('', 'end', text = line)
        else:
            analyse_tree.insert(parent_iid, 'end', text = line)

    hex_area['state'] = NORMAL
    hex_area.delete(1.0, 'end')
    hex_area.insert('end', scapy.hexdump(pkt, dump = True))
    hex_area['state'] = DISABLED


def set_state_stop(value):
    state['is_Stop'] = value

def save_file_accordance_file_path(file_path):
    scapy.wrpcap(file_path, state['capture_packet_array'])

def read_file_accordance_file_path(file_path, tree):
    state['capture_packet_array'].clear()
    state['is_Pause'] = False
    state['is_Stop'] = False
    state['first_time'] = 0
    state['packet_number'] = 0

    scapy.sniff(
        prn = lambda pkt: packet_handle(pkt, tree),
        stop_filter = is_Stop,
        offline = file_path,
        filter = state['filter']
    )

    state['is_Stop'] = True

def set_filter(filter):
    state['filter'] = filter
