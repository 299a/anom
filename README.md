# anom
0. The dataset dirctory structure:
root/
├── train/               
│   ├── class_1/         
│   │   ├── sample_1.pcap
│   │   ├── sample_2.pcap
│   │   └── ...
│   ├── class_2/         
│   │   ├── sample_1.pcap
│   │   ├── sample_2.pcap
│   │   └── ...
│   └── ...

The EnDatSet extracted in Section 5:
1. The raw pcap dataset need to preprocessed to the 'flow' by five tuple Saving the extracted flow pcap file in 'root' path, the dataset directory should be same as above.
2. Run 1_file_tls_filter.py
This file extracting and saving only tls.application_record packets and associated tcp segments, but including TLS record layer header
3. Run 2_file_tls_plaintext_filter.py
This file process the extracted TLS Application Data related packets, including the TCP segmented main frame and all dependent frames, directly process .pcap file. 
Root path in this file is the save path in 1_file_tls_filter.py

What we do:
- Remove the IP and TCP headers from each packet, leaving only the encrypted load content. 
- Also removes all TLS record layer header bytes.
- Very detailed processing, TCP/TP header retention.
- Save as the standard .pcap file.
