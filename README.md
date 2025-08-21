## **Building a Low-Cost Unidirectional File Transfer System With A Custom Data Diode and Special TFTP Implementation**

## **Project Overview**

This project implements a **unidirectional file transfer system** designed for physically air-gapped networks, specifically those secured by a custom data diode. It reimagines the TFTP (Trivial File Transfer Protocol) to operate in a **"fire-and-forget"** mode, where the client sends data packets without expecting any acknowledgments (ACKs) or responses from the server. This fundamental design choice ensures that the system can function across a one-way network link where a return path is physically impossible.

The core philosophy of this system is that **"silence is a source of great strength."** The absence of a return channel, which is a significant limitation for most protocols, becomes a security feature here.

![alt text](https://github.com/douglasmun/DataDiode-TFTP/edit/main/IMG_2909.jpg?raw=true)


![alt text](https://github.com/douglasmun/DataDiode-TFTP/edit/main/IMG_2910.jpg?raw=true)


## **Core Design Principles**

* **Physical Security via Data Diode:** The system's security is enforced at the **physical layer (Layer 1\)**, not by software or policy. A custom data diode, built with a laser on the sender side and a light detector on the receiver side, creates a physically irreversible, one-way channel. This ensures that no data can ever travel back from the receiver to the sender, effectively preventing threats like ransomware from moving from a less-trusted network (e.g., an IT network) to a more-trusted one (e.g., an OT/SCADA network).  
* **Manual ARP Setup:** Due to the unidirectional nature of the network, the standard Address Resolution Protocol (ARP) cannot function, as it relies on a two-way exchange to discover the physical address of the receiver. This is a key design limitation that requires a **static ARP entry** to be manually configured on the client machine to correctly route packets to the receiver.  
* **No Acknowledgements (ACKs):** The most significant departure from standard TFTP is the complete elimination of ACKs. The client does not wait for confirmation that a packet was received, and the server never sends one.  
* **Timing Replaces Reliability:** To prevent the sender from overwhelming the receiver, the client introduces a small, fixed delay between sending each data packet. This timing-based approach replaces the flow control provided by ACKs in a traditional protocol.  
* **Hash-Based Integrity:** Since the system cannot use checksums or re-transmissions to ensure data integrity, it relies on a **SHA-256 hash** of the file. The client calculates this hash and embeds it into the filename of the initial request. The server then calculates the hash of the received file and compares it to the one in the filename to verify its integrity.  
* **"Write Now, Ask Never" Philosophy:** On the server side, data is written directly to disk as it is received. This prevents buffer overflows and ensures that as much data as possible is saved, even in a non-guaranteed delivery environment.

## **System Components**

### **1\. The Client (oneway\_tftp\_client.py)**

This script acts as the sender. It is a highly modified TFTP client that:

* Constructs a Write Request (WRQ) packet containing the filename and a SHA-256 hash.  
* Sends all data blocks to a single, fixed server port (69) without expecting any reply.  
* Includes a configurable delay between packets to prevent network congestion.  
* Can send files up to approximately 32 MB, a limitation inherited from the 16-bit block number in the TFTP protocol.

### **2\. The Server (oneway\_tftp\_server.py)**

This script acts as the receiver. It is a stateless "deaf" listener that:

* Listens exclusively on port 69 for all incoming WRQ and DATA packets.  
* Immediately writes incoming data to a temporary file on the disk.  
* Discards duplicate or out-of-order blocks without requesting re-transmission.  
* Finalizes the file transfer after a configurable delay, during which it verifies the file's integrity using the SHA-256 hash from the filename. If the hash does not match, the file is deleted.  
* Sanitizes filenames to prevent malicious path traversal attacks.

## **User Guide**

### **1\. Prerequisites**

* **Python 3.x:** Both the client and server scripts require Python 3\.  
* **YAML Library:** The server requires the PyYAML library for configuration. You can install it using pip install pyyaml.  
* **A One-Way Network Link:** For production use, this system requires a physical data diode or a similar hardware-enforced unidirectional link.

### **2\. Setup**

**Server Side:**

1. Create a configuration file named oneway\_tftp\_server\_config.yaml to define settings like the receive directory and delays. A basic example is shown below:  
   YAML

| `receive_dir: ./received_files  # Directory to save received files` |
| :---- |

2. Run the server script from a terminal. It will start listening for incoming files.  
   Bash

| `python3 oneway_tftp_server.py --config oneway_tftp_server_config.yaml` |
| :---- |

**Client Side:**

* The client script does not require a separate configuration file. You can adjust its behavior using command-line arguments.

### **3\. Usage**

To send a file from the client to the server, run the client script from a separate terminal.

**Basic Usage:**

1. The simplest command sends the file to the default server address (127.0.0.1) and port (69). python3 oneway\_tftp\_client.py \<path\_to\_your\_file\>  
   Bash

| `python3 oneway_tftp_client.py file.pdf` |
| :---- |


**Advanced Usage:**

2. You can specify the server IP address and a custom remote filename.   
   python3 oneway\_tftp\_client.py \--server \<server\_ip\> \--remote-name \<custom\_name\> \<path\_to\_your\_file\>  
   Bash

| `python3 oneway_tftp_client.py --server 192.168.1.100 --remote-name important_report.pdf my_local_report.pdf` |
| :---- |

Upon successful completion, the server will print a message indicating that the file was received and verified, and you will find the file in the received\_files directory (or the one you configured).
