#!/usr/bin/env python3
"""
One-Way TFTP Client for Data Diode
Sends files without waiting for server acknowledgments
"""

import socket
import struct
import time
import os
import sys

class OneWayTFTPClient:
    def __init__(self, server_host='127.0.0.1', server_port=69):
        self.server_host = server_host
        self.server_port = server_port
        self.block_size = 512
        self.delay_ms = 5  # 5ms delay between blocks
        
        # TFTP opcodes
        self.OPCODE_RRQ = 1    # Read request
        self.OPCODE_WRQ = 2    # Write request 
        self.OPCODE_DATA = 3   # Data packet
        self.OPCODE_ACK = 4    # Acknowledgment
        self.OPCODE_ERROR = 5  # Error packet
    
    def create_wrq_packet(self, filename, mode='octet'):
        """Create a Write Request (WRQ) packet"""
        packet = struct.pack('!H', self.OPCODE_WRQ)
        packet += filename.encode('ascii') + b'\x00'
        packet += mode.encode('ascii') + b'\x00'
        return packet
    
    def create_data_packet(self, block_number, data):
        """Create a DATA packet"""
        packet = struct.pack('!HH', self.OPCODE_DATA, block_number)
        packet += data
        return packet
    
    def send_file(self, local_filepath, remote_filename=None):
        """Send a file using one-way TFTP without waiting for ACKs"""
        
        if not os.path.exists(local_filepath):
            print(f"Error: File '{local_filepath}' not found")
            return False
        
        if remote_filename is None:
            remote_filename = os.path.basename(local_filepath)
        
        file_size = os.path.getsize(local_filepath)
        total_blocks = (file_size + self.block_size - 1) // self.block_size
        
        print(f"Sending file: {local_filepath}")
        print(f"Remote filename: {remote_filename}")
        print(f"File size: {file_size} bytes")
        print(f"Total blocks: {total_blocks}")
        print(f"Target server: {self.server_host}:{self.server_port}")
        print(f"Block delay: {self.delay_ms}ms")
        print("-" * 50)
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)  # Short timeout since we're not waiting for responses
            
            # Send WRQ (Write Request)
            wrq_packet = self.create_wrq_packet(remote_filename)
            print(f"Sending WRQ for '{remote_filename}'...")
            sock.sendto(wrq_packet, (self.server_host, self.server_port))
            
            # Small delay after WRQ
            time.sleep(0.01)
            
            # Open file and send data blocks
            with open(local_filepath, 'rb') as f:
                block_number = 1
                bytes_sent = 0
                
                while True:
                    # Read block of data
                    data = f.read(self.block_size)
                    if not data:
                        break
                    
                    # Create and send DATA packet
                    data_packet = self.create_data_packet(block_number, data)
                    sock.sendto(data_packet, (self.server_host, self.server_port))
                    
                    bytes_sent += len(data)
                    progress = (bytes_sent / file_size) * 100
                    
                    print(f"Block {block_number:4d}/{total_blocks}: {len(data):3d} bytes "
                          f"({progress:5.1f}%) - Total sent: {bytes_sent} bytes")
                    
                    # If this block is smaller than block_size, it's the last block
                    if len(data) < self.block_size:
                        print("Last block sent (partial block)")
                        break
                    
                    block_number += 1
                    
                    # Pause between blocks
                    time.sleep(self.delay_ms / 1000.0)
            
            sock.close()
            print("-" * 50)
            print(f"Transfer complete: {bytes_sent} bytes sent in {block_number} blocks")
            return True
            
        except Exception as e:
            print(f"Error during transfer: {e}")
            return False
    
    def send_multiple_files(self, file_list, delay_between_files=1.0):
        """Send multiple files with delay between each file"""
        print(f"Sending {len(file_list)} files...")
        
        for i, filepath in enumerate(file_list, 1):
            print(f"\n=== File {i}/{len(file_list)} ===")
            success = self.send_file(filepath)
            
            if not success:
                print(f"Failed to send {filepath}")
                continue
            
            # Delay between files (except after the last file)
            if i < len(file_list):
                print(f"Waiting {delay_between_files}s before next file...")
                time.sleep(delay_between_files)
        
        print("\nAll files processed.")


def main():
    """Main function with command line interface"""
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <file_to_send> [remote_filename] [server_ip] [server_port]")
        print(f"  {sys.argv[0]} --multiple file1 file2 file3... [server_ip] [server_port]")
        print("\nExamples:")
        print(f"  {sys.argv[0]} document.txt")
        print(f"  {sys.argv[0]} data.bin backup_data.bin 192.168.1.100 69")
        print(f"  {sys.argv[0]} --multiple file1.txt file2.txt file3.txt")
        return
    
    # Default values
    server_ip = '127.0.0.1'
    server_port = 69
    
    client = OneWayTFTPClient()
    
    if sys.argv[1] == '--multiple':
        # Multiple files mode
        if len(sys.argv) < 3:
            print("Error: No files specified for multiple file mode")
            return
        
        files = []
        i = 2
        # Collect files until we hit an IP address or end of args
        while i < len(sys.argv):
            arg = sys.argv[i]
            # Check if this looks like an IP address
            if '.' in arg and len(arg.split('.')) == 4:
                server_ip = arg
                if i + 1 < len(sys.argv):
                    server_port = int(sys.argv[i + 1])
                break
            else:
                files.append(arg)
            i += 1
        
        client.server_host = server_ip
        client.server_port = server_port
        client.send_multiple_files(files)
    
    else:
        # Single file mode
        local_file = sys.argv[1]
        remote_file = None
        
        # Parse arguments
        if len(sys.argv) >= 3:
            # Could be remote filename or server IP
            if '.' in sys.argv[2] and len(sys.argv[2].split('.')) == 4:
                # It's an IP address
                server_ip = sys.argv[2]
                if len(sys.argv) >= 4:
                    server_port = int(sys.argv[3])
            else:
                # It's a remote filename
                remote_file = sys.argv[2]
                if len(sys.argv) >= 4:
                    server_ip = sys.argv[3]
                    if len(sys.argv) >= 5:
                        server_port = int(sys.argv[4])
        
        client.server_host = server_ip
        client.server_port = server_port
        client.send_file(local_file, remote_file)


if __name__ == '__main__':
    main()
