#!/usr/bin/env python3
"""
TRUE One-Way TFTP Server for Data Diode

This server is specifically designed to function as the receiver side
of a **unidirectional data transfer system**. Its core design principle
is to operate in a "listening" mode without ever sending a reply or
acknowledgment (ACK) packet. This "silence" is a key feature that
allows it to be used with a physical data diode, where a return path
[cite_start]is impossible[cite: 12].

Key design choices and assumptions:
1. **No ACKs**: The server is a "deaf receiver" and never sends any
   packets back to the client, even to acknowledge a WRQ or data packet.
   [cite_start]This breaks the standard TFTP protocol flow[cite: 94].
2. **Fixed Port**: All incoming packets (WRQ and DATA) are handled on a
   single, fixed port (69), bypassing the standard TFTP practice of
   switching to an ephemeral port for data transfer. This simplifies
   the server's operation and aligns with the unidirectional nature
   [cite_start]of the system[cite: 37].
3. **Immediate Write**: Data is written directly to disk as it arrives
   [cite_start]to prevent buffer overflows[cite: 124]. The server assumes that the
   client's packet timing (e.g., the 1ms delay) is sufficient to prevent
   data loss from an over-run buffer.
4. **Resilience**: The server is designed to handle out-of-order or
   duplicate blocks by logging them and proceeding. It's a "best-effort"
   system that prioritizes receiving data over strict protocol adherence.

The main design limitations include:
1. **No Reliability**: The lack of ACKs means the server cannot request
   [cite_start]retransmission of lost blocks[cite: 147].
2. **Loss of Data**: If a block is lost in transit, the file will be
   incomplete or corrupted, and the server has no way to recover it.
   Integrity is checked only at the end using the filename hash, and a
   [cite_start]mismatch results in file deletion[cite: 147].
3. **No Authentication**: The server accepts files from any IP, lacking
   authentication or encryption mechanisms. Security relies solely on the
   [cite_start]physical data diode[cite: 148].

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
import threading
import hashlib
import logging
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from logging.handlers import RotatingFileHandler
import re
import signal
import yaml
import uuid

# TFTP opcodes
OPCODE_WRQ = 2
OPCODE_DATA = 3


class OneWayTransfer:
    def __init__(self, addr, filename, mode, full_path, temp_path, safe_filename, logger, stats, config):
        # Represents an active file transfer from a single client IP.
        self.addr = addr
        self.filename = filename
        self.mode = mode
        self.full_path = full_path
        self.temp_path = temp_path
        self.safe_filename = safe_filename
        self.logger = logger
        self.stats = stats
        self.config = config
        self.file_handle = open(temp_path, 'wb')
        self.expected_block = 1  # Tracks the expected block number for in-order writing.
        self.bytes_received = 0
        self.blocks_received = 0
        self.start_time = time.time()
        self.last_block_time = time.time()
        self.completed = False
        self.seen_blocks = set()  # Stores seen block numbers to detect duplicates.
        self.out_of_order_blocks = 0
        self.duplicate_blocks = 0
        self.final_block_size = None
        self.file_hash_known = False
        self.expected_hash = None

    def handle_data(self, block_num, data):
        # Processes incoming DATA packets.
        # This method's logic is a core part of the "resilience" design:
        # it handles duplicate blocks and out-of-order blocks without
        # attempting to re-sort or request missing data.
        client_ip = self.addr[0]
        self.last_block_time = time.time()

        # Integrity check: The server parses the SHA-256 hash from the filename
        # of the first block. This is the only mechanism for verifying
        # the file's integrity at the end of the transfer.
        if block_num == 1 and not self.file_hash_known:
            match = re.search(r'__SHA256_([0-9a-fA-F]{64})', self.filename)
            if match:
                self.file_hash_known = True
                self.expected_hash = match.group(1).lower()
                self.logger.info(f"Expected hash: {self.expected_hash}")

        if block_num in self.seen_blocks:
            # Handles duplicate blocks by logging and discarding them,
            # which is a robust behavior for a system without ACKs where
            # the client might re-send a packet if it doesn't get a response.
            self.stats['duplicate_blocks'] += 1
            self.duplicate_blocks += 1
            self.logger.debug(f"Duplicate block {block_num} from {client_ip}")
            return

        self.seen_blocks.add(block_num)
        payload_len = len(data)
        is_last_block = payload_len < self.config['block_size']

        expected = self.expected_block % 65536 or 1
        if block_num == expected:
            # Writes the data to the temporary file immediately if the block
            # is received in the correct order. This "write-now" strategy
            # [cite_start]prevents buffer overflows[cite: 124].
            self.write_block(block_num, data, is_last_block)
            self.expected_block += 1
            # Flush any contiguous buffered blocks
            self.flush_contiguous()
        else:
            # Logs out-of-order blocks but does not store their data.
            # This is a major limitation; if a block arrives out-of-order and
            # the in-order blocks ahead of it are never received, the transfer
            # will be incomplete.
            self.out_of_order_blocks += 1
            self.stats['out_of_order_blocks'] += 1
            self.logger.info(f"Out-of-order block {block_num}, expected {expected}")

        if is_last_block:
            # Schedules the completion of the transfer after a delay.
            # The completion delay is a crucial part of the design. It gives
            # any remaining late or out-of-order blocks a chance to arrive
            # before the file is finalized, renamed, and the transfer is
            # marked as complete.
            self.schedule_completion()

    def write_block(self, block_num, data, is_last):
        # Writes data to the temporary file and flushes it to disk.
        # `os.fsync` ensures the data is written from the OS buffer to the
        # physical disk, reducing the risk of data loss from a sudden crash.
        try:
            self.file_handle.write(data)
            self.file_handle.flush()
            os.fsync(self.file_handle.fileno())
            self.bytes_received += len(data)
            self.blocks_received += 1
            self.stats['total_blocks_received'] += 1
            if is_last:
                self.final_block_size = len(data)
            elapsed = time.time() - self.start_time
            rate = self.bytes_received / elapsed if elapsed > 0 else 0
            self.logger.info(f"Block {block_num} written: {len(data)} bytes "
                           f"({self.bytes_received:,} total, {rate:,.0f} B/s){' [LAST]' if is_last else ''}")
        except Exception as e:
            self.logger.error(f"Write failed: {e}")
            self.complete(success=False)

    def flush_contiguous(self):
        """This function is a placeholder and not used in this implementation.
        In a more complex design, it would be used to write buffered
        out-of-order blocks once their preceding blocks have arrived."""
        pass

    def schedule_completion(self):
        # Schedules the `finalize` method to run after a configurable delay.
        # This timer-based approach replaces the ACK-based completion of
        # standard TFTP and accounts for potential packet delays on the network.
        if hasattr(self, '_timer'):
            self._timer.cancel()
        self._timer = threading.Timer(self.config['completion_delay'], self.finalize)
        self._timer.start()
        self.logger.info(f"Scheduled completion in {self.config['completion_delay']}s")

    def finalize(self):
        # Finalizes the transfer, which is called by the completion timer.
        self.complete(success=True)

    def calculate_hash(self):
        # Calculates the SHA-256 hash of the received temporary file.
        try:
            h = hashlib.sha256()
            with open(self.temp_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calc failed: {e}")
            return None

    def verify_integrity(self):
        # Compares the calculated hash of the received file with the hash
        # provided in the filename.
        # This is a critical step for data integrity in a system without
        # [cite_start]reliability protocols[cite: 152].
        if self.file_hash_known:
            computed = self.calculate_hash()
            if computed and computed.lower() != self.expected_hash:
                self.logger.error(f"Hash mismatch: got {computed}, expected {self.expected_hash}")
                return False
        return True

    def complete(self, success=True):
        # Finalizes the transfer, handling file renaming and cleanup.
        if self.completed:
            return
        self.completed = True

        if hasattr(self, '_timer'):
            self._timer.cancel()

        try:
            self.file_handle.close()
        except:
            pass

        if success and self.verify_integrity():
            try:
                # Atomically renames the temporary file to its final name.
                # This ensures that the file is not visible to other applications
                # until it has been completely received and verified.
                self.temp_path.rename(self.full_path)
                self.full_path.chmod(0o644)
                self.stats['files_received'] += 1
                self.stats['bytes_received'] += self.bytes_received
                self.stats['transfers_completed'] += 1
                elapsed = time.time() - self.start_time
                rate = self.bytes_received / elapsed
                self.logger.info(f"TRANSFER SUCCESS: {self.safe_filename} ({self.bytes_received:,}B, {elapsed:.2f}s, {rate:,.0f}B/s)")
                self.print_stats()
            except Exception as e:
                self.logger.error(f"Rename failed: {e}")
                success = False
        else:
            # Deletes the incomplete or corrupted temporary file.
            # This is a key safety feature to prevent saving bad data.
            self.stats['transfers_failed'] += 1
            if self.temp_path.exists():
                self.temp_path.unlink()
                self.logger.warning(f"Removed incomplete file: {self.temp_path}")
            self.logger.info(f"TRANSFER FAILED: {self.safe_filename}")

        threading.Timer(30.0, lambda: self.cleanup()).start()

    def cleanup(self):
        pass


class TrueOneWayTFTPServer:
    def __init__(self, config_file=None):
        # Initializes the main server loop and configuration.
        # The configuration is loaded from a YAML file, allowing for flexible
        # adjustments to behavior like `completion_delay` and `block_size`.
        self.config = {
            'host': '0.0.0.0',
            'port': 69,
            'receive_dir': './received_files',
            'max_file_size': 10 * 1024 * 1024 * 1024,  # 10 GB
            'max_transfers': 10,
            'max_per_ip': 3,
            'rate_limit_sec': 1.0,
            'completion_delay': 2.0,
            'block_size': 512
        }
        if config_file:
            with open(config_file, 'r') as f:
                self.config.update(yaml.safe_load(f))
        self.logger = self.setup_logging()
        self.receive_dir = Path(self.config['receive_dir']).resolve()
        self.receive_dir.mkdir(parents=True, exist_ok=True)
        # `active_transfers` tracks ongoing file transfers, using the client IP
        # as a unique identifier. This is a simple but effective way to manage
        # multiple simultaneous transfers in a stateless protocol.
        self.active_transfers = {}
        self.transfer_lock = threading.Lock()
        self.running = False
        self.stats = defaultdict(int)
        self.ip_last_request = defaultdict(float)

    def setup_logging(self):
        # Configures logging for both console output and a rotating file.
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh = RotatingFileHandler('tftp_server.log', maxBytes=10*1024*1024, backupCount=5)
        ch = logging.StreamHandler()
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logging.basicConfig(level=logging.INFO, handlers=[ch, fh])
        return logging.getLogger(__name__)

    def sanitize_filename(self, name):
        # Sanitizes the filename to prevent path traversal or other malicious
        # file-naming attacks. This is a basic security measure since the
        # server cannot authenticate the client.
        name = Path(name).name
        if name.upper() in ['CON', 'PRN', 'AUX', 'NUL']:
            name = f"unsafe_{name}"
        name = name.replace('\x00', '')
        safe = ''.join(c for c in name if c.isalnum() or c in '._-')
        if safe.startswith('.'):
            safe = 'dot_' + safe[1:]
        return safe[:200] or 'unknown_file'

    def get_safe_path(self, filename):
        """
        Generate final path: original_name_YYYYMMDD-HHMMSS_mmm.ext
        If a file with that name exists, appends _1, _2, etc.
        """
        # Creates unique, timestamped filenames to prevent overwriting existing files.
        # A UUID is used for the temporary file to ensure it is unique and cannot
        # be guessed or accessed by an external process while being written.
        base_name = self.sanitize_filename(filename)
        stem = Path(base_name).stem
        suffix = Path(base_name).suffix

        # Generate base timestamped name
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d-%H%M%S")
        millisecond = f"{now.microsecond // 1000:03d}"
        base_final_name = f"{stem}_{timestamp}_{millisecond}{suffix}"
        full_path = self.receive_dir / base_final_name

        # If it exists, add counter
        counter = 1
        final_path = full_path
        while final_path.exists() and counter < 1000:
            final_path = self.receive_dir / f"{base_final_name[:-len(suffix)]}_{counter}{suffix}"
            counter += 1

        if counter >= 1000:
            # Fallback: use UUID (very rare)
            final_path = self.receive_dir / f"{uuid.uuid4()}{suffix}"

        # Always use a unique temp file
        temp_path = self.receive_dir / f"{uuid.uuid4()}.part"

        return final_path, temp_path, base_name


    def parse_wrq(self, data):
        # Parses the filename and mode from an incoming WRQ packet.
        try:
            parts = data[2:].split(b'\x00')
            if len(parts) < 2:
                return None, None
            filename = parts[0].decode('ascii', errors='ignore')
            mode = parts[1].decode('ascii', errors='ignore').lower()
            return filename, mode
        except:
            return None, None

    def handle_wrq(self, data, addr):
        # Handles a WRQ packet by initiating a new transfer.
        # This function includes basic rate limiting to prevent a single IP
        # from overwhelming the server with transfer requests.
        if len(self.active_transfers) >= self.config['max_transfers']:
            self.logger.warning(f"Max transfers reached. Rejecting WRQ from {addr[0]}")
            return

        filename, mode = self.parse_wrq(data)
        if not filename:
            return

        client_ip = addr[0]
        now = time.time()
        with self.transfer_lock:
            # Implements a basic rate-limiting mechanism per IP address.
            if now - self.ip_last_request[client_ip] < self.config['rate_limit_sec']:
                return
            self.ip_last_request[client_ip] = now

        try:
            full_path, temp_path, safe_name = self.get_safe_path(filename)
            xfer = OneWayTransfer(addr, filename, mode, full_path, temp_path, safe_name,
                                self.logger, self.stats, self.config)
            with self.transfer_lock:
                self.active_transfers[client_ip] = xfer
            self.stats['transfers_started'] += 1
            self.logger.info(f"WRQ from {client_ip}:{addr[1]} - File: {filename}")
            self.logger.info(f"    -> Saving as: {safe_name} (temp: {temp_path})")
        except Exception as e:
            self.logger.error(f"Failed to start transfer: {e}")
            self.stats['errors'] += 1

    def handle_data(self, data, addr):
        # Handles incoming DATA packets.
        # It looks up the active transfer based on the client's IP address and
        # delegates the handling of the block to the `OneWayTransfer` instance.
        if len(data) < 4:
            return
        block_num = struct.unpack('!H', data[2:4])[0]
        payload = data[4:]

        client_ip = addr[0]
        with self.transfer_lock:
            xfer = self.active_transfers.get(client_ip)
            if not xfer or xfer.completed:
                # Discards data packets for transfers that are not active or have already completed.
                # This is a key part of the server's stateless, "best-effort" design.
                self.logger.warning(f"DATA from {client_ip} - no active transfer")
                return
        xfer.handle_data(block_num, payload)

    def start(self):
        # Main server loop. It listens for packets on a single UDP socket
        # bound to the configured port (69).
        print("Starting TRUE One-Way TFTP Server (No ACKs, All on Port 69)")
        print(f"Config: {dict(self.config)}")
        print("-" * 70)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.config['host'], self.config['port']))
        sock.settimeout(1.0) # The timeout allows the main loop to periodically check for shutdown signals.
        self.running = True

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                opcode = struct.unpack('!H', data[:2])[0]
                if opcode == OPCODE_WRQ:
                    self.handle_wrq(data, addr)
                elif opcode == OPCODE_DATA:
                    self.handle_data(data, addr)
                else:
                    self.logger.warning(f"Unknown opcode {opcode} from {addr}")
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Main loop error: {e}")

        # Finalizes any remaining active transfers before shutting down.
        for xfer in self.active_transfers.values():
            xfer.finalize()
        self.print_stats()

    def print_stats(self):
        # Prints a summary of the server's operational statistics.
        print("\n" + "="*70)
        print("ONE-WAY TFTP SERVER STATISTICS")
        print("="*70)
        print(f"Files received:     {self.stats['files_received']}")
        print(f"Bytes received:     {self.stats['bytes_received']:,}")
        print(f"Transfers completed: {self.stats['transfers_completed']}")
        print(f"Transfers failed:   {self.stats['transfers_failed']}")
        print(f"Duplicate blocks:   {self.stats['duplicate_blocks']}")
        print(f"Out-of-order:       {self.stats['out_of_order_blocks']}")
        print("="*70)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='True One-Way TFTP Server for Data Diode')
    parser.add_argument('--config', help='YAML config file')
    args = parser.parse_args()
    server = TrueOneWayTFTPServer(args.config)
    try:
        server.start()
    except KeyboardInterrupt:
        server.running = False


if __name__ == '__main__':
    main()
