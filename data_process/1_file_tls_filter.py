
import os
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
import time
import psutil
import gc


root_a = ""  # root dir
root_standard = “"  # save dir


MAX_MEMORY_PERCENT = 80  
MIN_WORKERS = 1  
MAX_WORKERS = 1 


failed_files = []
no_tls_record_content_files = []  
successful_dirs = 0  


def count_files_in_subdirectories(root_path):
    subdirectory_counts = {}
    for root, dirs, files in os.walk(root_path):
        if os.path.dirname(root) == root_path:  # 只统计二级目录
            subdirectory_name = os.path.basename(root)
            subdirectory_counts[subdirectory_name] = len(files)
    return subdirectory_counts

def print_counts(input_root, output_root):
    input_counts = count_files_in_subdirectories(input_root)
    output_counts = count_files_in_subdirectories(output_root)

    print(input_root)
    for subdirectory, count in input_counts.items():
        print(f"  {subdirectory}: {count} files")

    print(output_root)
    for subdirectory, count in output_counts.items():
        print(f"  {subdirectory}: {count} files")



def extract_related_frames(pcap_file_path):
    """
    Extract all frame numbers associated with TLS Application Data packets from the pcap file, including both complete TLS Application Data packets and fragmented packets.
    """
    result = subprocess.run(
        # f'tshark -r "{pcap_file_path}" -Y "tls.record.content_type == 23" -T fields -e frame.number -e tcp.segment',
        f'tshark -r "{pcap_file_path}" -Y "tls.record.content_type == 23" -T fields -e frame.number -e tcp.segment -e tls.record.content_type',
        # f'tshark -r "{pcap_file_path}" -Y "tls.record.content_type == 23" -o "tcp.desegment_tcp_streams:TRUE" -T fields -e frame.number -e tcp.segment -e tls.record.content_type',
        shell=True, capture_output=True, text=True
    )


    frames_to_keep = set()
    for line in result.stdout.splitlines(): 
        parts = line.split()
        if len(parts) > 1:
            frame_number = parts[0]
            if len(parts) > 2 and parts[1] != "": 
                frames_to_keep.add(frame_number)  
                segments = parts[1].split(",")  
                frames_to_keep.update(segments)
            else: 
                frames_to_keep.add(frame_number)

    return frames_to_keep  





def save_frames_in_batches(pcap_file_path, standard_pcap_path, frames_to_keep, batch_size=100):

    temp_files = []
    frames_list = list(frames_to_keep)

    small_batch_size = 50  
    large_batch_size = batch_size 

    for i in range(0, len(frames_list), small_batch_size):
        batch_frames = frames_list[i:i + small_batch_size]
        frame_numbers = " ".join(batch_frames)
        temp_file = f"{standard_pcap_path}_batch_{i}.pcap"

        command = f'editcap -r "{pcap_file_path}" "{temp_file}" {frame_numbers}'
        try:
            subprocess.run(command, shell=True, check=True)
            temp_files.append(temp_file)
        except subprocess.CalledProcessError as e:
            # temp_files.append(temp_file)
            print(f"Error processing small batch {i}: {e} editcap")
            continue

    merged_files = []
    for i in range(0, len(temp_files), large_batch_size):
        partial_merge_file = f"{standard_pcap_path}_merged_batch_{i}.pcap"
        merge_command = f'mergecap -w "{partial_merge_file}" ' + " ".join(temp_files[i:i + large_batch_size])
        try:
            subprocess.run(merge_command, shell=True, check=True)
            merged_files.append(partial_merge_file)
        except subprocess.CalledProcessError as e:
            print(f"Error merging large batch {i}: {e} mergecap")
            continue

    final_merge_command = f'mergecap -w "{standard_pcap_path}" ' + " ".join(merged_files)
    try:
        subprocess.run(final_merge_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error merging final files: {e}")

    for temp_file in temp_files + merged_files:
        if os.path.exists(temp_file):
            os.remove(temp_file)




def convert_to_standard_pcap(subdir, root_a, root_standard):
    # global non_empty_files_by_subdir  # 声明使用全局变量
    print(subdir)
    subdir_path = os.path.join(root_a, subdir)
    dest_dir_standard = os.path.join(root_standard, subdir)
    os.makedirs(dest_dir_standard, exist_ok=True)

    for file in os.listdir(subdir_path):
        if file.endswith(".pcap") or file.endswith(".pcapng"):
            pcap_file_path = os.path.join(subdir_path, file)
            
            # print(pcap_file_path)

            if file.endswith(".pcapng"):
                file = file.replace(".pcapng", ".pcap")
            standard_pcap_path = os.path.join(dest_dir_standard, file)

            # 提取所有相关的帧号
            frames_to_keep = extract_related_frames(pcap_file_path)  
            if not frames_to_keep: 
                no_tls_record_content_files.append(pcap_file_path)
                # print(f"No TLS Application Data found in {pcap_file_path}. Skipping.")
                continue

            try:
                save_frames_in_batches(pcap_file_path, standard_pcap_path, frames_to_keep)  
                print(f"Converted {pcap_file_path} to standard PCAP format at {standard_pcap_path}")
            except subprocess.CalledProcessError as e: 
                if os.path.exists(standard_pcap_path):
                    os.remove(standard_pcap_path)
                print(f"Error converting {pcap_file_path}: {e}")
                failed_files.append(pcap_file_path)  

    return True

def estimate_remaining_time(start_time, completed_tasks, total_tasks):
    elapsed_time = time.time() - start_time
    avg_time_per_task = elapsed_time / completed_tasks if completed_tasks > 0 else 0
    remaining_tasks = total_tasks - completed_tasks
    estimated_remaining_time = avg_time_per_task * remaining_tasks
    return estimated_remaining_time

def monitor_system_usage():
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.percent
    cpu_usage = psutil.cpu_percent(interval=1)
    print(f"CPU usage: {cpu_usage}% | Memory usage: {memory_usage}%")

    if memory_usage > MAX_MEMORY_PERCENT:
        print("Memory usage exceeds the limit. Consider reducing the number of workers.")
        return True
    return False

def main():
    global successful_dirs  
    subdirs = sorted(os.listdir(root_a))  
    num_workers = MAX_WORKERS
    total_tasks = len(subdirs)

    print(f"Total tasks: {total_tasks}")
    print(f"Number of workers: {num_workers}")
    print("-" * 150)
    start_time = time.time()

    while subdirs:
        print(subdirs)

        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            batch_size = min(num_workers, len(subdirs))
            current_batch = subdirs[:batch_size]
            futures = [executor.submit(convert_to_standard_pcap, subdir, root_a, root_standard) for subdir in current_batch]
            subdirs = subdirs[batch_size:]  

            completed_tasks = 0
            for future in as_completed(futures):
                try:
                    if future.result():
                        completed_tasks += 1
                        successful_dirs += 1

                    remaining_time = estimate_remaining_time(start_time, completed_tasks, total_tasks)
                    print(f"Completed {completed_tasks}/{total_tasks} tasks. Estimated remaining time: {remaining_time:.2f} seconds.")
                except Exception as e:
                    print(f"Task failed: {e}")

        gc.collect()  

    total_elapsed_time = time.time() - start_time
    print(f"All tasks completed in {total_elapsed_time:.2f} seconds.")
    print(f"Successfully created {successful_dirs} directories.")


    if no_tls_record_content_files:
        print(f"No_tls_record_content_files ({len(no_tls_record_content_files)}):")
        # for failed_file in no_content_type_files:
            # print(failed_file)
        with open("./no_tls_record_content_files.txt", 'w') as f:
            f.write(f"No_tls_record_content_files ({len(no_tls_record_content_files)}):\n")
            for failed_file in no_tls_record_content_files:
                f.write(f"{failed_file}\n")

    if failed_files:
        print(f"Failed files ({len(failed_files)}):")
        with open("./no_tls_record_content_files.txt", 'w') as f:
            f.write(f"Failed files ({len(failed_files)}):\n")
            for failed_file in failed_files:
                f.write(f"{failed_file}\n")
        # for failed_file in failed_files:
            # print(failed_file)
    
    print_counts(root_a, root_standard)


if __name__ == "__main__":
    main()