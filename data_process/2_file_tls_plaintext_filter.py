import os
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
import time
import psutil
import gc
from scapy.all import rdpcap, wrpcap, Raw, PcapWriter
from tempfile import NamedTemporaryFile
import numpy as np
from scapy.layers.inet import IP, TCP, UDP


root_a = ""  # root dir, for saving processed tls_filter pcap
root_standard = "“   
# This code removes the TLS Recod Layer Header and all Handshake Message, and subsequent processing can be accomplished directly by extracting the packet loads

MAX_MEMORY_PERCENT = 80  
MIN_WORKERS = 2  
MAX_WORKERS = 10  
MAX_SEQ_NUM = 4294967295  

def adjust_tcp_seq(seq, adjustment):
    new_seq = seq + adjustment
    return new_seq % (MAX_SEQ_NUM + 1)  


failed_files = []
no_tls_record_content_files = [] 
successful_dirs = 0  

print("File_tls_plaintext_filter:")

def count_files_in_subdirectories(root_path):

    subdirectory_counts = {}
    for root, dirs, files in os.walk(root_path):
        if os.path.dirname(root) == root_path:  
            subdirectory_name = os.path.basename(root)
            subdirectory_counts[subdirectory_name] = len(files)
    return subdirectory_counts

def print_counts(input_root, output_root):
    input_counts = count_files_in_subdirectories(input_root)
    output_counts = count_files_in_subdirectories(output_root)

    for subdirectory, count in input_counts.items():
        print(f"  {subdirectory}: {count} files")

    for subdirectory, count in output_counts.items():
        print(f"  {subdirectory}: {count} files")




def filter_non_tls_packets(input_file, output_file):

    command = f'tshark -r "{input_file}" -Y "!(tls.record.content_type == 20 || tls.record.content_type == 21 || tls.record.content_type == 22 || tls.record.content_type == 23)" -w "{output_file}"'
    subprocess.run(command, shell=True, check=True)

def filter_tls_packets(input_file, output_file):

    command = f'tshark -r "{input_file}" -Y "(tls.record.content_type == 20 || tls.record.content_type == 21 || tls.record.content_type == 22 || tls.record.content_type == 23)" -w "{output_file}"'
    subprocess.run(command, shell=True, check=True)




def quick_scan_tls_headers(payload):

    header_patterns = [b'\x14', b'\x15', b'\x16', b'\x17']  
    possible_offsets = []
    offset = 0
    while offset + 5 <= len(payload):
        if payload[offset:offset+1] in header_patterns and payload[offset+1:offset+3] in [b'\x03\x01', b'\x03\x02', b'\x03\x03', b'\x03\x04']:
            possible_offsets.append(offset)
            offset += 5  
        else:
            offset += 1
    return possible_offsets


def numpy_scan_tls_headers(payload):

    payload_np = np.frombuffer(payload, dtype=np.uint8)
    
    content_types = np.array([0x14, 0x15, 0x16, 0x17], dtype=np.uint8)

    versions = [(0x03, 0x01), (0x03, 0x02), (0x03, 0x03), (0x03, 0x04)]

    possible_offsets = np.isin(payload_np, content_types).nonzero()[0]


    valid_offsets = []
    for offset in possible_offsets:
        if offset + 5 <= len(payload_np):
            version = tuple(payload_np[offset+1:offset+3])
            if version in versions:
                valid_offsets.append(offset)
    
    return valid_offsets


def parse_tls_layers(payload, offsets):
    cleaned_payload = bytearray(payload)
    delete_ranges = []
    total_deleted_length = 0  
    tcp_seq_offset_adjustment = 0  
    
    for offset in offsets:
        content_type = cleaned_payload[offset]
        if content_type in [0x14, 0x15, 0x16]:  
            next_offset = offset + 5
            while next_offset < len(cleaned_payload):
                next_content_type = cleaned_payload[next_offset]
                next_version = cleaned_payload[next_offset+1:next_offset+3] if next_offset + 2 <= len(cleaned_payload) else None
                if next_content_type == 0x17 and next_version in [b'\x03\x01', b'\x03\x02', b'\x03\x03', b'\x03\x04']:
                    break
                next_offset += 1

            delete_ranges.append((offset, next_offset))  
            length_deleted = next_offset - offset
            total_deleted_length += length_deleted
            
            if offset == 0:  
                tcp_seq_offset_adjustment = length_deleted

        elif content_type == 0x17:  
            delete_ranges.append((offset, offset+5))  
            total_deleted_length += 5  

            if offset == 0:  
                tcp_seq_offset_adjustment = 5

    merged_ranges = []
    for start, end in sorted(delete_ranges):
        if merged_ranges and merged_ranges[-1][1] >= start: 
            merged_ranges[-1] = (merged_ranges[-1][0], max(merged_ranges[-1][1], end))
        else:
            merged_ranges.append((start, end))
    
    for start, end in reversed(merged_ranges):  
        del cleaned_payload[start:end]

    return bytes(cleaned_payload), tcp_seq_offset_adjustment


def optimized_tls_processing(payload):
    offsets = numpy_scan_tls_headers(payload)
    
    return parse_tls_layers(payload, offsets)



def process_tls_containing_pcap(input_file, output_file):

    packets = rdpcap(input_file)
    with PcapWriter(output_file, append=True, sync=True) as pcap_writer:
        for pkt in packets:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)

                offsets = numpy_scan_tls_headers(payload)

                cleaned_payload, tcp_seq_offset_adjustment = parse_tls_layers(payload, offsets)

                pkt[Raw].load = cleaned_payload

            pcap_writer.write(pkt)



def process_notls_pcap(input_file, output_file):

    packets = rdpcap(input_file)  
    with PcapWriter(output_file, append=True, sync=True) as pcap_writer:
        for pkt in packets:
            if pkt.haslayer(Raw):  
                payload = bytes(pkt[Raw].load)
                original_payload_length = len(pkt[Raw].load)

                if len(payload) >= 5 and payload[0] == 0x17 and payload[1] == 0x03 and payload[2] in [0x01, 0x02, 0x03, 0x04]:

                    payload = payload[5:]
                    pkt[Raw].load = payload
                    modified_payload = payload 

            pcap_writer.write(pkt)



def adjust_final_pcap(file_path, output_file):

    packets = rdpcap(file_path) 
    with PcapWriter(output_file, append=True, sync=True) as pcap_writer:
        last_seq = {}  
        last_ack = {} 

        for pkt in packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                key = (ip_src, ip_dst, sport, dport)  

                payload_length = len(pkt[Raw].load)  


                if key in last_seq:
                    pkt[TCP].seq = adjust_tcp_seq(last_seq[key], 0)  
                    last_seq[key] = adjust_tcp_seq(last_seq[key], payload_length)
                else:
                    last_seq[key] = adjust_tcp_seq(pkt[TCP].seq, payload_length)

                reverse_key = (ip_dst, ip_src, dport, sport)  
                if reverse_key in last_seq:
                    pkt[TCP].ack = adjust_tcp_seq(last_seq[reverse_key], 0)
                    
                del pkt[IP].chksum
                del pkt[IP].len
                del pkt[TCP].chksum

            pcap_writer.write(pkt)



def convert_to_standard_pcap(subdir, root_a, root_standard):

    try:
        subdir_path = os.path.join(root_a, subdir)
        dest_dir_standard = os.path.join(root_standard, subdir)
        os.makedirs(dest_dir_standard, exist_ok=True)

        for file in os.listdir(subdir_path):
            if file.endswith(".pcap") or file.endswith(".pcapng"):
                pcap_file_path = os.path.join(subdir_path, file)
                filtered_output_pcap = os.path.join(dest_dir_standard, f"filtered_{file}")
                processed_notls_pcap = os.path.join(dest_dir_standard, f"processed_notls_{file}")
            
                tls_containing_output_pcap = os.path.join(dest_dir_standard, f"tls_{file}")
                processed_tls_containing_pcap = os.path.join(dest_dir_standard, f"processed_tls_{file}")

                final_processed_pcap = os.path.join(dest_dir_standard, f"final_processed_tls_{file}")
                final_output_pcap = os.path.join(dest_dir_standard, file)

                filter_non_tls_packets(pcap_file_path, filtered_output_pcap)

                process_notls_pcap(filtered_output_pcap, processed_notls_pcap)

                filter_tls_packets(pcap_file_path, tls_containing_output_pcap)

                process_tls_containing_pcap(tls_containing_output_pcap, processed_tls_containing_pcap)

                merge_command = f"mergecap -w {final_processed_pcap} {processed_notls_pcap} {processed_tls_containing_pcap}"
                subprocess.run(merge_command, shell=True, check=True)

                adjust_final_pcap(final_processed_pcap, final_output_pcap)

                os.remove(filtered_output_pcap)
                os.remove(processed_notls_pcap)
                os.remove(tls_containing_output_pcap)
                os.remove(processed_tls_containing_pcap)
                os.remove(final_processed_pcap)

        return True
    
    except Exception as e:
        print(f"Error in processing subdir {subdir}: {e}")
        return False

def monitor_system_usage():
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.percent
    cpu_usage = psutil.cpu_percent(interval=1)
    print(f"CPU usage: {cpu_usage}% | Memory usage: {memory_usage}%")
    return memory_usage > MAX_MEMORY_PERCENT

def main():
    global successful_dirs
    subdirs = sorted(os.listdir(root_a))
    num_workers = MAX_WORKERS
    total_tasks = len(subdirs)

    start_time = time.time()
    while subdirs:
        if monitor_system_usage():
            num_workers = max(MIN_WORKERS, num_workers - 1)
        else:
            num_workers = min(MAX_WORKERS, num_workers + 1)

        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(convert_to_standard_pcap, subdir, root_a, root_standard) for subdir in subdirs]
            subdirs = []  
            completed_tasks = 0
            for future in as_completed(futures):
                try:
                    if future.result():
                        completed_tasks += 1
                        successful_dirs += 1
                    print(f"Completed {completed_tasks}/{total_tasks}.")
                except Exception as e:
                    print(f"Task failed: {e}")

        gc.collect()

    print("All tasks completed.")
    total_elapsed_time = time.time() - start_time
    print(f"All tasks completed in {total_elapsed_time:.2f} seconds.")
    print(f"Successfully created {successful_dirs} directories.")

    print_counts(root_a, root_standard)

if __name__ == "__main__":
    main()