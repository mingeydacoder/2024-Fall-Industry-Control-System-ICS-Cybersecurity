from scapy.all import rdpcap, IP, TCP, wrpcap
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def extract_reference_number(pkt):
    try:
        pdu = bytes(pkt[TCP].payload)
        function_code = pdu[7]  
        reference_number = int.from_bytes(pdu[8:10], "big")
        #length = len(pkt)
        return function_code, reference_number
    except:
        return None, None
    
def get_register_0_value(next_pkt):
    try:
        pdu = bytes(next_pkt[TCP].payload)
        register_0_value = int.from_bytes(pdu[9:11], "big")
        return register_0_value
    except:
        return None

def filter_modbus_requests(file_path, ip_list, modbus_port=502):
    packets = rdpcap(file_path) 
    filtered_packets = [] 

    for i, pkt in enumerate(packets):
        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            if (src_ip in ip_list and dst_ip in ip_list) and (dst_port or src_port == modbus_port):
                function_code, rem = extract_reference_number(pkt)
                if function_code is not None:
                    filtered_packets.append(pkt)
    if filtered_packets:
        wrpcap(output_pcap, filtered_packets)
        print(f"已將符合條件的封包儲存至: {output_pcap}")

def second_filter_modbus_requests(file_path):
    packets = rdpcap(file_path) 
    value = []
    for i, pkt in enumerate(packets):
        function_code, ref_num = extract_reference_number(pkt)
        # 檢查 Reference Number 是否為 0
        register_0_value = None
        if ref_num == 0 and i + 1 < len(packets):
            register_0_value = get_register_0_value(packets[i + 1])
            value.append(register_0_value)
            #print(value)
    return value

if __name__ == "__main__":
    pcap_file = "normal_1hr.pcap"  
    output_pcap = "filtered_output.pcap"
    ip_list = ["192.168.1.19", "192.168.1.23"]
    
    filtered_results = filter_modbus_requests(pcap_file, ip_list)
    
    # 二次分析
    final_results = second_filter_modbus_requests(output_pcap)
    print(final_results)
    
    fig, ax = plt.subplots(figsize=(24, 4))
    time = np.linspace(0,3602,3603)
    x, y = time, final_results
    ax.set_ylim([0,20000])
    ax.plot(x,y)
    
