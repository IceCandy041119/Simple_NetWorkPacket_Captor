import scapy.all as scapy
import threading
from tkinter import DISABLED, NORMAL, constants

state = {
    'interface_name' : 'wlp0s20f3',
    'first_time' : 0.0,
    'packet_number' : 0,
    'capture_packet_array':[],
    'filter': "",
    'capture_thread' : None
}

is_stop = threading.Event()
is_pause = threading.Event()
 

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
    if is_pause.is_set() or is_stop.is_set(): return

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



def capture(tree):
    scapy.sniff(
        iface = state['interface_name'],
        prn = lambda pkt: packet_handle(pkt, tree),
        stop_filter = lambda _: is_stop.is_set(),
        filter = state['filter']
    )

def start_capture(tree_list, btn_begin, btn_pause, btn_stop, hex_area, tree_analyse):
    if not is_pause.is_set():
        is_stop.clear()
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
    state['capture_thread'] = t

    btn_begin['state'] = DISABLED
    btn_pause['state'] = NORMAL
    btn_stop['state'] = NORMAL

def pause_capture(btn):
    if btn['text'] == 'pause':
        btn['text'] = 'reset'
        is_pause.set()
    elif btn['text'] == 'reset':
        btn['text'] = 'pause'
        is_pause.clear()

def stop_capture(btn_begin, btn_pause, btn_stop):
    is_stop.set()
    is_pause.clear()
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


def set_state_stop():
    is_stop.set()

def save_file_accordance_file_path(file_path):
    scapy.wrpcap(file_path, state['capture_packet_array'])

def read_file_accordance_file_path(file_path, tree):
    state['capture_packet_array'].clear()
    is_pause.clear()
    is_stop.clear()
    state['first_time'] = 0
    state['packet_number'] = 0

    scapy.sniff(
        prn = lambda pkt: packet_handle(pkt, tree),
        stop_filter = lambda _: is_stop.is_set(),
        offline = file_path,
        filter = state['filter']
    )

    is_stop.set()

def set_filter(filter):
    state['filter'] = filter

def is_Stop():
    return is_stop.is_set()

def get_thread():
    return state['capture_thread']
