#!/usr/bin/env python3
"""
One-Way TFTP Client

This client is designed for a **unidirectional data transfer system**,
specifically for use with a custom data diode. Unlike standard TFTP,
it operates in a "fire-and-forget" mode, sending all packets to a fixed
port (69) without expecting or waiting for any acknowledgments (ACKs)
or responses from the server. This design choice is fundamental to its
purpose: to function across a network link where a return path is
[cite_start]physically impossible, such as with a fiber optic data diode[cite: 36, 37].

The client's primary assumptions are:
1. The server is always listening on the designated port (69).
2. [cite_start]The network path is one-way, so no ACKs will ever be received[cite: 99].
3. The sender's ARP cache has a static entry for the receiver, bypassing the
   [cite_start]need for an ARP request which would fail on a one-way link[cite: 58, 60].

The main design limitations include:
1. **No Reliability**: Since there are no ACKs, the client cannot confirm
   if a packet was received. [cite_start]Packet loss is not detected or handled[cite: 147].
2. **No Congestion Control**: The client sends packets at a fixed rate
   (with a millisecond delay) instead of adjusting based on network
   [cite_start]conditions, which could lead to buffer overflows at the receiver[cite: 149].
3. **No Error Correction**: The client assumes data integrity and cannot
   [cite_start]re-transmit lost or corrupted blocks[cite: 147].

Usage examples:
# Terminal 1: Start fixed server
python3 oneway_tftp_server.py --config oneway_tftp_server_config.yaml

# Terminal 2: Send 20MB file
python3 oneway_tftp_client.py large_file.pdf

"""
import socket
import struct
import time
import os
import sys
import hashlib
import logging
from datetime import datetime
from pathlib import Path


class OneWayTFTPClient:
    def __init__(self, server_host='127.0.0.1', server_port=69):
        # Initializes the client with server address and port.
        # This port (69) is fixed and hardcoded, as it's the standard TFTP port.
        # The design assumes the server will handle all WRQ and DATA packets
        # on this single port, which is a departure from standard TFTP
        # behavior that uses ephemeral ports for data transfer.
        self.server_host = server_host
        self.server_port = server_port
        self.block_size = 512  # Standard TFTP block size.
        [cite_start]self.delay_ms = 1  # 1ms delay between data packets to prevent receiver buffer overflow[cite: 123].
        self.wrq_delay = 50  # Delay after sending the WRQ packet before starting data transfer.
        self.use_integrity = True  # Flag to enable SHA-256 hash calculation for filename.
        self.OPCODE_WRQ = 2
        self.OPCODE_DATA = 3
        self.stats = {'files_sent': 0, 'bytes_sent': 0, 'blocks_sent': 0, 'errors': 0}
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=logging.INFO, format=log_format, handlers=[logging.StreamHandler()])
        self.logger = logging.getLogger(__name__)

    def calculate_file_hash(self, filepath):
        # Calculates the SHA-256 hash of the file.
        # This is a key design feature for integrity verification, as the one-way link
        # prevents the use of traditional checksums or error correction protocols.
        # The hash is sent as part of the filename in the WRQ packet.
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def generate_remote_filename(self, original_name, file_hash):
        # Creates a new filename that includes the SHA-256 hash.
        # This embeds integrity information into the file name itself, allowing
        # the receiver to verify the file's integrity upon completion without a return channel.
        stem = Path(original_name).stem
        suffix = Path(original_name).suffix
        return f"{stem}__SHA256_{file_hash}{suffix}"[:255]

    def create_wrq_packet(self, filename):
        # Creates a TFTP Write Request (WRQ) packet.
        # The WRQ packet's filename includes the SHA-256 hash.
        # A limitation is the 255-byte filename length limit.
        try:
            if len(filename) > 255:
                filename = filename[:255]
            packet = struct.pack('!H', self.OPCODE_WRQ)
            packet += filename.encode('ascii', errors='replace') + b'\x00'
            packet += b'octet\x00'
            return packet
        except Exception as e:
            self.logger.error(f"Error creating WRQ: {e}")
            return None

    def create_data_packet(self, block_number, data):
        # Creates a TFTP Data (DATA) packet.
        # The block number wraps around at 65536, which is a standard TFTP
        # behavior to accommodate file sizes up to 32MB (65535 blocks * 512 bytes).
        # This implementation re-uses the standard block number format, but
        # the lack of ACKs means the client doesn't verify correct reception
        # or re-transmit blocks.
        try:
            wrapped = block_number % 65536
            if wrapped == 0: wrapped = 1
            packet = struct.pack('!HH', self.OPCODE_DATA, wrapped)
            packet += data
            return packet
        except Exception as e:
            self.logger.error(f"Error creating DATA: {e}")
            return None

    def send_packet(self, sock, packet, addr):
        # Sends a single UDP packet to the specified address.
        # This function is designed to be "unidirectional," meaning it only
        # sends data and does not attempt to receive anything. This is a
        # critical implementation detail for a data diode system.
        try:
            sock.sendto(packet, addr)
            return True
        except Exception as e:
            self.logger.error(f"Send failed: {e}")
            self.stats['errors'] += 1
            return False

    def send_file(self, local_filepath, remote_filename=None):
        # Main function to send the file.
        local_path = Path(local_filepath)
        if not local_path.exists():
            self.logger.error(f"File not found: {local_filepath}")
            return False

        file_size = local_path.stat().st_size
        is_perfect_multiple = file_size > 0 and (file_size % self.block_size == 0)
        total_blocks = (file_size + self.block_size - 1) // self.block_size
        # The effective block count accounts for the zero-byte last packet
        # required by standard TFTP for files that are a perfect multiple of the block size.
        effective_blocks = total_blocks + (1 if is_perfect_multiple else 0)

        if effective_blocks > 65535:
            # File size limitation: The 16-bit block number limits the max file size to ~32MB.
            # This is a fundamental limitation inherited from the TFTP protocol.
            self.logger.error("File too large, max-size is 32MB, breaks it to smaller files")
            return False

        # Generate remote filename with hash for integrity verification.
        file_hash = self.calculate_file_hash(local_path) if self.use_integrity else None
        final_name = self.generate_remote_filename(remote_filename or local_path.name, file_hash)

        print(f"Sending: {local_filepath} → {final_name} ({file_size:,}B)")
        print(f"SHA-256: {file_hash}")

        # Set up a UDP socket for sending.
        # The socket's send buffer size is increased (64KB) to improve
        # performance by allowing the OS to buffer more outgoing packets.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64*1024)
        server_addr = (self.server_host, self.server_port)

        # Send the WRQ packet and wait before sending data.
        # The WRQ delay is a manual timing control to give the server
        # [cite_start]time to set up the transfer before the data stream begins[cite: 107].
        wrq = self.create_wrq_packet(final_name)
        if not wrq or not self.send_packet(sock, wrq, server_addr):
            sock.close()
            return False
        time.sleep(self.wrq_delay / 1000.0)

        # Begin file transfer loop.
        start = time.time()
        with open(local_path, 'rb') as f:
            block_num = 1
            bytes_sent = 0
            while True:
                data = f.read(self.block_size)
                # This check handles the last block of a file that is not
                # a perfect multiple of the block size.
                if not data and not is_perfect_multiple:
                    break
                packet = self.create_data_packet(block_num, data)
                if packet:
                    self.send_packet(sock, packet, server_addr)
                    bytes_sent += len(data)
                    self.stats['blocks_sent'] += 1
                if len(data) < self.block_size:
                    # Handles the last block which is smaller than the block size.
                    break
                block_num += 1
                # [cite_start]Introduces a small delay between packets[cite: 116]. This is a
                # critical part of the one-way design, as it replaces the
                # [cite_start]"acknowledgment" mechanism of standard TFTP[cite: 153].
                # It prevents the sender from overwhelming the receiver's buffer
                # [cite_start]and allows the receiver time to write the data to disk[cite: 124].
                time.sleep(self.delay_ms / 1000.0)
            if is_perfect_multiple:
                # If the file size is a perfect multiple of the block size, a final
                # zero-byte packet is sent to signal the end of the transfer,
                # as required by the TFTP protocol.
                final_pkt = self.create_data_packet(block_num, b'')
                self.send_packet(sock, final_pkt, server_addr)
                self.stats['blocks_sent'] += 1

        sock.close()
        elapsed = time.time() - start
        rate = bytes_sent / elapsed if elapsed > 0 else 0
        print(f"Sent {bytes_sent:,}B in {elapsed:.2f}s → {rate:,.0f} B/s")
        return True


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='File to send')
    parser.add_argument('--server', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=69)
    parser.add_argument('--remote-name')
    args = parser.parse_args()
    client = OneWayTFTPClient(args.server, args.port)
    success = client.send_file(args.file, args.remote_name)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
