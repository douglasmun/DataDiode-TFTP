#!/usr/bin/env python3
"""
One-Way TFTP Server for Data Diode
Receives files without sending acknowledgments
"""

import socket
import struct
import time
import os
import sys
import threading
from datetime import datetime

class OneWayTFTPServer:
    def __init__(self, host='0.0.0.0', port=69, receive_dir='./received_files'):
        self.host = host
        self.port = port
        self.receive_dir = receive_dir
        self.block_size = 512
        self.running = False
        
        # TFTP opcodes
        self.OPCODE_RRQ = 1    # Read request
        self.OPCODE_WRQ = 2    # Write request 
        self.OPCODE_DATA = 3   # Data packet
        self.OPCODE_ACK = 4    # Acknowledgment
        self.OPCODE_ERROR = 5  # Error packet
        
        # Active transfers - track ongoing file transfers
        self.active_transfers = {}
        self.transfer_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'files_received': 0,
            'bytes_received': 0,
            'transfers_started': 0,
            'transfers_completed': 0,
            'errors': 0
        }
        
        # Create receive directory if it doesn't exist
        if not os.path.exists(self.receive_dir):
            os.makedirs(self.receive_dir)
            print(f"Created receive directory: {self.receive_dir}")
    
    def parse_wrq_packet(self, data):
        """Parse a Write Request packet"""
        try:
            # Skip opcode (first 2 bytes)
            payload = data[2:]
            
            # Find filename (null-terminated)
            filename_end = payload.find(b'\x00')
            if filename_end == -1:
                return None, None
            
            filename = payload[:filename_end].decode('ascii')
            
            # Find mode (null-terminated)
            mode_start = filename_end + 1
            mode_end = payload.find(b'\x00', mode_start)
            if mode_end == -1:
                return filename, 'octet'  # Default mode
            
            mode = payload[mode_start:mode_end].decode('ascii')
            return filename, mode
            
        except Exception as e:
            print(f"Error parsing WRQ packet: {e}")
            return None, None
    
    def parse_data_packet(self, data):
        """Parse a DATA packet"""
        try:
            if len(data) < 4:
                return None, None
            
            # Unpack opcode and block number
            opcode, block_num = struct.unpack('!HH', data[:4])
            if opcode != self.OPCODE_DATA:
                return None, None
            
            # Extract data payload
            payload = data[4:]
            return block_num, payload
            
        except Exception as e:
            print(f"Error parsing DATA packet: {e}")
            return None, None
    
    def get_safe_filename(self, filename):
        """Generate a safe filename, avoiding overwrites"""
        # Remove any path components for security
        filename = os.path.basename(filename)
        
        # Replace unsafe characters
        unsafe_chars = '<>:"/\\|?*'
        for char in unsafe_chars:
            filename = filename.replace(char, '_')
        
        full_path = os.path.join(self.receive_dir, filename)
        
        # If file exists, add timestamp suffix
        if os.path.exists(full_path):
            name, ext = os.path.splitext(filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{name}_{timestamp}{ext}"
            full_path = os.path.join(self.receive_dir, filename)
        
        return full_path, filename
    
    def handle_wrq(self, addr, filename, mode):
        """Handle Write Request - start a new file transfer"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] WRQ from {addr[0]}:{addr[1]} - File: {filename} (mode: {mode})")
        
        try:
            # Generate safe filename
            full_path, safe_filename = self.get_safe_filename(filename)
            
            # Create transfer session
            transfer_id = f"{addr[0]}:{addr[1]}:{filename}"
            
            with self.transfer_lock:
                self.active_transfers[transfer_id] = {
                    'filename': filename,
                    'safe_filename': safe_filename,
                    'full_path': full_path,
                    'file_handle': open(full_path, 'wb'),
                    'expected_block': 1,
                    'bytes_received': 0,
                    'blocks_received': 0,
                    'start_time': time.time(),
                    'last_block_time': time.time(),
                    'addr': addr,
                    'completed': False
                }
                self.stats['transfers_started'] += 1
            
            print(f"    -> Saving as: {safe_filename}")
            return transfer_id
            
        except Exception as e:
            print(f"Error handling WRQ: {e}")
            self.stats['errors'] += 1
            return None
    
    def handle_data(self, addr, block_num, data):
        """Handle DATA packet"""
        transfer_id = None
        
        # Find the transfer session for this address
        with self.transfer_lock:
            for tid, transfer in self.active_transfers.items():
                if transfer['addr'] == addr and not transfer['completed']:
                    transfer_id = tid
                    break
        
        if not transfer_id:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] DATA from {addr[0]}:{addr[1]} - No active transfer found (block {block_num})")
            return
        
        try:
            with self.transfer_lock:
                transfer = self.active_transfers[transfer_id]
                
                # Update last activity time
                transfer['last_block_time'] = time.time()
                
                # Write data to file (we accept blocks out of order for robustness)
                transfer['file_handle'].write(data)
                # CRITICAL: Flush data to disk immediately for one-way diode
                transfer['file_handle'].flush()
                os.fsync(transfer['file_handle'].fileno())
                
                transfer['bytes_received'] += len(data)
                transfer['blocks_received'] += 1
                
                # Check if this is the last block (less than 512 bytes)
                is_last_block = len(data) < self.block_size
                
                # Print progress
                elapsed = time.time() - transfer['start_time']
                rate = transfer['bytes_received'] / elapsed if elapsed > 0 else 0
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Block {block_num:4d}: {len(data):3d} bytes "
                      f"({transfer['bytes_received']:,} total, {rate:,.0f} B/s) "
                      f"{'[LAST]' if is_last_block else ''}")
                
                # If last block, complete the transfer
                if is_last_block:
                    self.complete_transfer(transfer_id)
        
        except Exception as e:
            print(f"Error handling DATA packet: {e}")
            self.stats['errors'] += 1
    
    def complete_transfer(self, transfer_id):
        """Complete a file transfer"""
        try:
            with self.transfer_lock:
                if transfer_id not in self.active_transfers:
                    return
                
                transfer = self.active_transfers[transfer_id]
                
                # Close file
                transfer['file_handle'].close()
                transfer['completed'] = True
                
                # Update statistics
                self.stats['files_received'] += 1
                self.stats['bytes_received'] += transfer['bytes_received']
                self.stats['transfers_completed'] += 1
                
                # Calculate transfer stats
                elapsed = time.time() - transfer['start_time']
                rate = transfer['bytes_received'] / elapsed if elapsed > 0 else 0
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] TRANSFER COMPLETE:")
                print(f"    File: {transfer['safe_filename']}")
                print(f"    Size: {transfer['bytes_received']:,} bytes")
                print(f"    Blocks: {transfer['blocks_received']}")
                print(f"    Time: {elapsed:.2f}s")
                print(f"    Rate: {rate:,.0f} B/s")
                print(f"    Saved to: {transfer['full_path']}")
                print("-" * 60)
                
                # Clean up transfer after a delay (keep for duplicate detection)
                threading.Timer(30.0, self.cleanup_transfer, args=[transfer_id]).start()
        
        except Exception as e:
            print(f"Error completing transfer: {e}")
            self.stats['errors'] += 1
    
    def cleanup_transfer(self, transfer_id):
        """Clean up completed transfer after delay"""
        with self.transfer_lock:
            if transfer_id in self.active_transfers:
                transfer = self.active_transfers[transfer_id]
                if transfer['completed'] and transfer['file_handle'].closed:
                    del self.active_transfers[transfer_id]
    
    def cleanup_stale_transfers(self):
        """Clean up transfers that haven't received data recently"""
        current_time = time.time()
        stale_timeout = 3.0  # 3 seconds timeout for one-way diode
        
        with self.transfer_lock:
            stale_transfers = []
            for transfer_id, transfer in self.active_transfers.items():
                if not transfer['completed']:
                    time_since_last = current_time - transfer['last_block_time']
                    if time_since_last > stale_timeout:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] TIMEOUT: No data for {time_since_last:.1f}s - Completing transfer: {transfer['filename']}")
                        # Complete the transfer due to timeout
                        self.complete_transfer(transfer_id)
                        stale_transfers.append(transfer_id)
            
            # Note: completed transfers are cleaned up by complete_transfer method
        
        if stale_transfers:
            print(f"Completed {len(stale_transfers)} transfers due to timeout")
    
    def print_stats(self):
        """Print server statistics"""
        print("\n" + "="*60)
        print("TFTP SERVER STATISTICS")
        print("="*60)
        print(f"Files received:       {self.stats['files_received']}")
        print(f"Bytes received:       {self.stats['bytes_received']:,}")
        print(f"Transfers started:    {self.stats['transfers_started']}")
        print(f"Transfers completed:  {self.stats['transfers_completed']}")
        print(f"Errors:               {self.stats['errors']}")
        print(f"Active transfers:     {len([t for t in self.active_transfers.values() if not t['completed']])}")
        print(f"Receive directory:    {self.receive_dir}")
        print("="*60)
    
    def start(self):
        """Start the TFTP server"""
        print(f"Starting One-Way TFTP Server...")
        print(f"Listening on: {self.host}:{self.port}")
        print(f"Receive directory: {self.receive_dir}")
        print(f"Block size: {self.block_size} bytes")
        print("Note: This server does NOT send acknowledgments (one-way mode)")
        print("-" * 60)
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.settimeout(1.0)  # 1 second timeout for cleanup checks
            
            self.running = True
            last_cleanup = time.time()
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(4096)
                    
                    if len(data) < 2:
                        continue
                    
                    # Parse opcode
                    opcode = struct.unpack('!H', data[:2])[0]
                    
                    if opcode == self.OPCODE_WRQ:
                        # Write Request
                        filename, mode = self.parse_wrq_packet(data)
                        if filename:
                            self.handle_wrq(addr, filename, mode)
                    
                    elif opcode == self.OPCODE_DATA:
                        # Data packet
                        block_num, payload = self.parse_data_packet(data)
                        if block_num is not None:
                            self.handle_data(addr, block_num, payload)
                    
                    else:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Unknown opcode {opcode} from {addr[0]}:{addr[1]}")
                
                except socket.timeout:
                    # Periodic cleanup check - check every 500ms for faster timeout detection
                    current_time = time.time()
                    if current_time - last_cleanup > 0.5:  # Every 500ms for 3-second timeout
                        self.cleanup_stale_transfers()
                        last_cleanup = current_time
                    continue
                
                except Exception as e:
                    print(f"Error processing packet: {e}")
                    self.stats['errors'] += 1
        
        except KeyboardInterrupt:
            print("\nShutdown requested...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.running = False
            sock.close()
            
            # Close any remaining file handles
            with self.transfer_lock:
                for transfer in self.active_transfers.values():
                    try:
                        if not transfer['file_handle'].closed:
                            transfer['file_handle'].close()
                    except:
                        pass
            
            self.print_stats()
            print("Server stopped.")


def main():
    """Main function with command line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='One-Way TFTP Server for Data Diode')
    parser.add_argument('--host', default='0.0.0.0', help='Server host/IP (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=69, help='Server port (default: 69)')
    parser.add_argument('--dir', default='./received_files', help='Receive directory (default: ./received_files)')
    
    args = parser.parse_args()
    
    server = OneWayTFTPServer(host=args.host, port=args.port, receive_dir=args.dir)
    
    try:
        server.start()
    except PermissionError:
        print(f"Error: Permission denied to bind to port {args.port}")
        print("Try running with sudo or use a port > 1024")
        sys.exit(1)


if __name__ == '__main__':
    main()
