from datetime import datetime, timezone
import logging
import argparse
import re
import logging
import win32security
import subprocess
import win32com.client
import socket
import traceback
import json
import psutil
from pdml_parser import PDMLParser
from capture import PacketCapture
from save_logs import SaveLogs
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename='smb_monitor.log')

@dataclass
class PacketInfo:
    cmd: str
    buffer_code: str
    nt_status: str
    is_response: bool
    is_request: bool
    share_type: str
    sec_info_infolevel: str
    file_disposition_info: str
    file_rename_info: str
    file_info_infolevel: str
    session_id: str
    ntlmssp_verf: str
    acct: str
    domain: str
    msg_id: str
    tree_path: str
    tree_id: str
    filename: str
    delete_on_close: str
    create_disposition: str
    file_id: str
    file_attribute_directory: str
    create_action: str
    last_write_time: str
    owner: str
    timestamp: str
    formatted_time: str
    client_ip: str
    client_port: str
    server_ip: str
    server_port: str

class SMB2Monitor:
    def __init__(self, config_file):
        self.load_config(config_file)
        self.ipv4_address, self.ipv6_address = self.get_interface_ip_addresses(self.interface)  # Get IP addresses
        self.ip_addresses = (self.ipv4_address, self.ipv6_address)
        self.capture_filter = self.generate_capture_filter(*self.ip_addresses)
        self.sendlogs = SaveLogs(url=self.url, token=self.token, save_to_file=self.save_to_file, num_files=self.num_files, logs_dir=self.logs_dir)
        self.log_data = self.sendlogs.add_log_data
        self.smb2_sessions = {}  
        self.tree_connect_info = {}  
        self.tree_request_info = {}
        self.create_request_info = {}
        self.create_response_info = {}
        self.create_delete_info = {}
        self.rename_info = {}
        self.file_modifications = {}
        self.set_security_info = {}
        self.file_accessed_info = {}
        self.security_request_info = {}
        self.get_security_response_info = {}
        self.share_info_dict = {}
        self.close_request_info = {}
        self.computer_name = self.get_computer_name()
        self.packet = PacketInfo

    def get_values(self, packet):
        try:
            self.packet.cmd = packet.smb2.get_field('smb2.cmd').get_attribute("show", "Unknown")
            self.packet.buffer_code = packet.smb2.get_field('smb2.buffer_code').get_attribute("show", "Unknown")
            self.packet.nt_status = packet.smb2.get_field('smb2.nt_status').get_attribute("show", "Unknown")
            self.packet.is_response = True if packet.smb2.get_field('smb2.flags.response').get_attribute("show", "Unknown") == 'True' else False
            self.packet.is_request = True if packet.smb2.get_field('smb2.flags.response').get_attribute("show", "Unknown") == 'False' else False
            self.packet.share_type = packet.smb2.get_field('smb2.share_type').get_attribute("show", "Unknown")
            self.packet.sec_info_infolevel = packet.smb2.get_field('smb2.sec_info.infolevel').get_attribute("show", "Unknown")
            self.packet.file_disposition_info = packet.smb2.get_field('smb2.file_disposition_info').get_attribute("showname", "Unknown")
            self.packet.file_rename_info = packet.smb2.get_field('smb2.file_rename_info').get_attribute("showname", "Unknown")
            self.packet.file_info_infolevel = packet.smb2.get_field('smb2.file_info.infolevel').get_attribute("show", "Unknown")
            self.packet.session_id = packet.smb2.get_field('smb2.sesid').get_attribute("show", "Unknown")
            self.packet.ntlmssp_verf = packet.smb2.get_field('ntlmssp.verf').get_attribute("showname", "Unknown")
            self.packet.acct = packet.smb2.get_field('smb2.acct').get_attribute("show", "Unknown")
            self.packet.domain = packet.smb2.get_field('smb2.domain').get_attribute("show", "Unknown")
            self.packet.msg_id = packet.smb2.get_field('smb2.msg_id').get_attribute("show", "Unknown")
            self.packet.tree_path = packet.smb2.get_field('smb2.tree').get_attribute("show", "Unknown")
            self.packet.tree_id = packet.smb2.get_field('smb2.tid').get_attribute("show", "Unknown") 
            self.packet.filename = packet.smb2.get_field('smb2.filename').get_attribute("show", "Unknown")
            self.packet.delete_on_close = packet.smb2.get_field('smb.nt.create_options.delete_on_close').get_attribute("show", "Unknown")
            self.packet.create_disposition = packet.smb2.get_field('smb2.create.disposition').get_attribute("show", "Unknown")
            self.packet.file_id = packet.smb2.get_field('smb2.fid').get_attribute("show", "Unknown")
            self.packet.file_attribute_directory = packet.smb2.get_field('smb2.file_attribute.directory').get_attribute("show", "Unknown")
            self.packet.create_action = packet.smb2.get_field('smb2.create.action').get_attribute("show", "Unknown")
            self.packet.last_write_time = packet.smb2.get_field('smb2.last_write.time').get_attribute("show", "Unknown")
            self.packet.owner = packet.smb2.get_field('nt.sid').get_attribute("show", "Unknown")
            self.packet.timestamp = datetime.fromtimestamp(float(packet.geninfo.get_field('timestamp').get_attribute("value", "Unknown")))
            self.packet.formatted_time = packet.geninfo.get_field('timestamp').get_attribute("value", "Unknown")
            self.packet.client_ip = packet.ip.get_field('ip.src').get_attribute("show", "Unknown") if self.packet.is_request else packet.ip.get_field('ip.dst').get_attribute("show", "Unknown")
            self.packet.client_port = packet.tcp.get_field('tcp.srcport').get_attribute("show", "Unknown") if self.packet.is_request else packet.tcp.get_field('tcp.dstport').get_attribute("show", "Unknown")
            self.packet.server_ip = packet.ip.get_field('ip.dst').get_attribute("show", "Unknown") if self.packet.is_request else packet.ip.get_field('ip.src').get_attribute("show", "Unknown")
            self.packet.server_port = packet.tcp.get_field('tcp.dstport').get_attribute("show", "Unknown") if self.packet.is_request else packet.tcp.get_field('tcp.srcport').get_attribute("show", "Unknown")
                        
        except Exception as e:
            logging.error(f"Error during packet get_values: {e}")
            logging.error(traceback.format_exc())
            return

    def process_smb2_packet(self):
        try:
            print("Starting SMB packet capture on interface:", self.interface)

            capture = PacketCapture(
                                    interface=self.interface,
                                    output_file=self.pcap_files,
                                    filter_expr=self.capture_filter,
                                    num_files=2000,
                                    filesize_kb=10240,
                                    duration_sec=1.0
                                )
            packets = capture.capture_packets()
        except Exception as e:
            logging.error(f"Error during initialization: {e}")
            logging.error(traceback.format_exc())
            return  
        try:
            for unparsed_packet in packets:
                parsed_packet = PDMLParser.parse_string(unparsed_packet)
                self.get_values(parsed_packet)
                if self.packet.cmd == '1':
                    if self.packet.buffer_code == '0x0009' and self.packet.nt_status == '0x00000000':
                        self.capture_smb2_session_setup()
                
                elif self.packet.cmd == '2':
                    if self.packet.is_response and self.packet.nt_status == '0x00000000':
                        self.logoff_session_response()
                
                elif self.packet.cmd == '3':
                    if self.packet.is_request:
                        self.tree_connect_request()
                    elif self.packet.is_response and self.packet.nt_status == '0x00000000' and self.packet.share_type == '0x01':
                            self.tree_connect_response()
                  
                elif self.packet.cmd == '4':
                    if self.packet.is_response and self.packet.nt_status == '0x00000000':
                        self.tree_disconnect_response()
                                        
                elif self.packet.cmd == '5':
                    if self.packet.buffer_code == '0x0039' and self.packet.is_request:
                        self.create_request()
                    elif self.packet.buffer_code == '0x0059' and self.packet.is_response:
                        self.create_response()
                
                elif self.packet.cmd == '6':
                    if self.packet.is_request:
                        self.close_request()
                    elif self.packet.is_response and self.packet.nt_status == '0x00000000':
                        self.close_response() 
                        
                elif self.packet.cmd == '8':
                    if self.packet.buffer_code == '0x0031':
                        self.file_accessed()
                        
                elif self.packet.cmd == '16':
                    if self.packet.is_request:
                        if self.packet.sec_info_infolevel == '0x00':
                            self.get_security_request()
                    elif self.packet.is_response:
                        if self.packet.sec_info_infolevel == '0x00' and self.packet.nt_status == '0x00000000':
                            self.get_security_response(parsed_packet)
                        
                elif self.packet.cmd == '17':
                    if self.packet.is_request:
                        if self.packet.file_disposition_info == 'SMB2_FILE_DISPOSITION_INFO':
                            self.folder_delete_request()
                        elif self.packet.file_rename_info == 'SMB2_FILE_RENAME_INFO':
                            self.handle_rename_request()
                        elif self.packet.sec_info_infolevel == '0x00':
                            self.set_security_request(parsed_packet)
                    elif self.packet.is_response and self.packet.nt_status == '0x00000000':
                        if self.packet.file_info_infolevel == '0x0d':
                            self.folder_delete_response()
                        elif self.packet.file_info_infolevel == '0x0a':
                            self.handle_rename_response()
                        elif self.packet.sec_info_infolevel == '0x00':
                            self.set_security_response()
                                
        except KeyboardInterrupt:
            logging.error("Manual interruption received (KeyboardInterrupt). Exiting.")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            logging.error("Error details:")
            logging.error(traceback.format_exc())
            
    def capture_smb2_session_setup(self):
        try:
            if self.packet.acct != 'Unknown' and self.packet.domain != 'Unknown' and self.packet.ntlmssp_verf == 'NTLMSSP Verifier':
                user_domain = f"{self.packet.domain}\\{self.packet.acct}"
                self.smb2_sessions[self.packet.session_id] = user_domain
        except AttributeError as e:
            logging.error("Error processing: capture_smb2_session_setup")
    
    def tree_connect_request(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            self.tree_request_info[msg_key] = self.packet.tree_path
        except AttributeError:
            logging.error("Error processing: tree_connect_request")

    def tree_connect_response(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            tree_path = self.tree_request_info.pop(msg_key, 'Unknown')
            if tree_path != 'Unknown':
                tree_key = (self.packet.tree_id, self.packet.session_id)
                self.tree_connect_info[tree_key] = tree_path
        except AttributeError:
            logging.error("Error processing: tree_connect_response")
    
    def tree_disconnect_response(self):
        try:
            tree_key = (self.packet.tree_id, self.packet.session_id)

            if tree_key in self.tree_connect_info:
                del self.tree_connect_info[tree_key]

        except AttributeError:
            logging.error("Error processing: tree_disconnect_response")
    
    def logoff_session_response(self):
        try:
            if self.packet.session_id in self.smb2_sessions:
                del self.smb2_sessions[self.packet.session_id]
        except AttributeError:
            logging.error("Error processing: logoff_session_response")

    def create_request(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            delete_status = 'True' if self.packet.delete_on_close == 'True' else 'False' if self.packet.delete_on_close == 'False' else 'Unknown'
            open_or_create = 'Create' if self.packet.create_disposition == '2' else 'Open' if self.packet.create_disposition == '1' else 'Unknown'
            self.create_request_info[msg_key] = (self.packet.filename, delete_status, open_or_create, self.packet.tree_id)
        except AttributeError:
            logging.error("Error processing: create_request")

    def create_response(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            filename, delete_status, open_or_create, tree_id = self.create_request_info.pop(msg_key, ('Unknown', 'Unknown', 'Unknown', 'Unknown'))

            if filename == 'Unknown':
                return
                                    
            file_or_dir = 'Directory' if self.packet.file_attribute_directory == 'True' else ('File' if self.packet.file_attribute_directory == 'False' else 'Unknown')
            create_action = 'Opened' if self.packet.create_action == '1' else ('Created' if self.packet.create_action == '2' else 'Unknown')

            file_key = (self.packet.session_id, self.packet.file_id)
            self.create_response_info[file_key] = (filename, file_or_dir)
            if delete_status == 'True' and file_or_dir == 'File' and self.packet.nt_status == '0x00000000':
                self.delete_file(filename, file_or_dir, tree_id)
            if create_action == 'Created' and open_or_create == 'Create' and self.packet.nt_status == '0x00000000':
                self.create_file_folder(filename, file_or_dir, tree_id)    
            if create_action == 'Opened' and open_or_create == 'Open' and self.packet.nt_status == '0x00000000' and file_or_dir == 'File':
                self.file_accessed_info[file_key] = (filename)
            if self.packet.last_write_time != 'Unknown' and file_or_dir == 'File' and create_action != 'Created':
                last_write_time = self.parse_timestamp(self.packet.last_write_time)  
                file_modify_key = (self.packet.session_id, filename)
                if file_modify_key in self.file_modifications and self.file_modifications[file_modify_key] < last_write_time:
                    self.file_modification(filename, tree_id)
                self.file_modifications[file_modify_key] = last_write_time        
        except AttributeError:
            logging.error("Error processing: create_response")

    def close_request(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            file_key = (self.packet.session_id, self.packet.file_id)
            filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            if filename == 'Unknown':
                return
            self.close_request_info[msg_key] = (file_key)
        except AttributeError:
            logging.error("Error processing: close_request")

    def close_response(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            file_key = self.close_request_info.pop(msg_key, ('Unknown'))
            if file_key == 'Unknown':
                return
            if file_key in self.create_response_info:
                del self.create_response_info[file_key]
        except AttributeError:
            logging.error("Error processing: close_response")

    def handle_rename_request(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            file_key = (self.packet.session_id, self.packet.file_id)
            old_filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            self.rename_info[msg_key] = (file_or_dir, old_filename, self.packet.filename)    
        except AttributeError:
            logging.error("Error processing: handle_rename_request")
  
    def handle_rename_response(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            file_or_dir, old_filename, new_filename = self.rename_info.pop(msg_key, ('Unknown', 'Unknown', 'Unknown'))
            if new_filename == 'Unknown' or old_filename == 'Unknown':
                return
            tree_key = (self.packet.tree_id, self.packet.session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(self.packet.session_id, 'Unknown')
            if user_domain == 'Unknown':
                user_domain = self.resolve_user_domain(new_filename, self.packet.client_ip, self.packet.session_id)
            if tree_path == 'Unknown':
                tree_path = self.resolve_tree_path(new_filename, self.packet.client_ip, tree_key)
            
            def split_path(filename):
                if '\\' in filename:
                    path, base_name = filename.rsplit('\\', 1)
                else:
                    path, base_name = '', filename  
                return path, base_name

            old_path, old_base_name = split_path(old_filename)
            new_path, new_base_name = split_path(new_filename)

            if old_base_name != new_base_name and old_path == new_path:
                self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Renamed',
                        'what': old_filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        'new_path': new_filename,
                        })
            elif old_path != new_path and old_base_name == new_base_name:
                self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Moved',
                        'what': old_filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        'new_path': new_filename,
                        })
            elif old_path != new_path and old_base_name != new_base_name:
                intermediate_filename = f"{new_path + '\\' if new_path else ''}{old_base_name}"
                self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Moved',
                        'what': old_filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        'new_path': intermediate_filename,
                        })
                self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Renamed',
                        'what': intermediate_filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        'new_path': new_filename,
                        })
        except AttributeError:
            logging.error("Error processing: handle_rename_response")

    def delete_file(self, filename, file_or_dir, tree_id):
        try:
            if filename == 'Unknown':
                return
            tree_key = (tree_id, self.packet.session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(self.packet.session_id, 'Unknown')
            if user_domain == 'Unknown':
                user_domain = self.resolve_user_domain(filename, self.packet.client_ip, self.packet.session_id)   
            if tree_path == 'Unknown':
                tree_path = self.resolve_tree_path(filename, self.packet.client_ip, tree_key)     
            self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Removed',
                        'what': filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        })
        except AttributeError:
            logging.error("Error processing: delete_file")
        
    def folder_delete_request(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            file_key = (self.packet.session_id, self.packet.file_id)
            filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            self.create_delete_info[msg_key] = (filename, file_or_dir)
        except AttributeError:
            logging.error("Error processing: folder_delete_request")
        
    def folder_delete_response(self):
        try:
            msg_key = (self.packet.msg_id, self.packet.session_id)
            filename, file_or_dir = self.create_delete_info.pop(msg_key, ('Unknown', 'Unknown'))
            if filename == 'Unknown':
                return
            tree_key = (self.packet.tree_id, self.packet.session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(self.packet.session_id, 'Unknown')
            if user_domain == 'Unknown':
                user_domain = self.resolve_user_domain(filename, self.packet.client_ip, self.packet.session_id)
            if tree_path == 'Unknown':
                tree_path = self.resolve_tree_path(filename, self.packet.client_ip, tree_key)            
            self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Removed',
                        'what': filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        })
        except AttributeError:
            logging.error("Error processing: folder_delete_response")
            
    def create_file_folder(self, filename, file_or_dir, tree_id):
        try:
            if filename == 'Unknown':
                return
            tree_key = (tree_id, self.packet.session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(self.packet.session_id, 'Unknown')
            if user_domain == 'Unknown':
                user_domain = self.resolve_user_domain(filename, self.packet.client_ip, self.packet.session_id)            
            if tree_path == 'Unknown':
                tree_path = self.resolve_tree_path(filename, self.packet.client_ip, tree_key)
            self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Created',
                        'what': filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        })
        except AttributeError:
            logging.error("Error processing: create_file_folder")

    def file_modification(self, filename, tree_id):
        try:
            if filename == 'Unknown':
                return
            tree_key = (self.packet.tree_id, self.packet.session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(self.packet.session_id, 'Unknown')  
            if user_domain == 'Unknown':
                user_domain = self.resolve_user_domain(filename, self.packet.client_ip, self.packet.session_id)
            if tree_path == 'Unknown':
                tree_path = self.resolve_tree_path(filename, self.packet.client_ip, tree_key)
            self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Modified',
                        'what': filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': 'File',
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        })
        except AttributeError:
            logging.error("Error processing: file_modification")

    def get_security_request(self):
        try:
            file_key = (self.packet.session_id, self.packet.file_id)
            filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            if filename == 'Unknown':
                return
            msg_key = (self.packet.msg_id, self.packet.session_id)
            self.security_request_info[msg_key] = (file_or_dir, filename)
        except Exception as e:
             logging.error(f"Error processing: get_security_request: {e}")
        
    def get_security_response(self, packet):
        try:   
            msg_key = (self.packet.msg_id, self.packet.session_id)
            file_or_dir, filename = self.security_request_info.pop(msg_key, ('Unknown', 'Unknown'))
            if filename and file_or_dir == 'Unknown':
                return
            acl = 'Unknown'
            acl_lines = []  
            lines = packet.smb2.get_field_count('')
            i = 0
            while i < int(lines):
                i += 1
                field = packet.smb2.get_field('', i)
                if field is not None:
                    acl_line = field.get_attribute('show')
                    if acl_line and acl_line.startswith("NT ACE:"):
                        acl_lines.append(acl_line)
            if acl_lines:  
                acl = '\n'.join(acl_lines)
            file_key = (self.packet.tree_id, filename, file_or_dir) 
            self.get_security_response_info[file_key] = (self.packet.owner, acl)
        except Exception as e:
             logging.error(f"Error processing: get_security_response: {e}")
      
    def set_security_request(self, packet):
        try:   
            file_key = (self.packet.session_id, self.packet.file_id)
            filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            if filename and file_or_dir == 'Unknown':
                return
            msg_key = (self.packet.msg_id, self.packet.session_id)
            acl = 'Unknown'
            acl_lines = []  
            lines = packet.smb2.get_field_count('')
            i = 0
            while i < int(lines):
                i += 1
                field = packet.smb2.get_field('', i)
                if field is not None:
                    acl_line = field.get_attribute('show')
                    if acl_line and acl_line.startswith("NT ACE:"):
                        acl_lines.append(acl_line)
            if acl_lines:
                acl = '\n'.join(acl_lines)
            self.set_security_info[msg_key] = (filename, file_or_dir, self.packet.owner, acl)
        except Exception as e:
             logging.error(f"Error processing: set_security_request: {e}")

    def set_security_response(self):
        try:
            
            msg_key = (self.packet.msg_id, self.packet.session_id)
            filename, file_or_dir, set_owner, set_acl = self.set_security_info.pop(msg_key, ('Unknown', 'Unknown', 'Unknown', 'Unknown'))
            if filename and file_or_dir == 'Unknown':
                return
            file_key = (self.packet.tree_id, filename, file_or_dir)
            get_owner, get_acl = self.get_security_response_info.get(file_key, ('Unknown', 'Unknown'))
            if set_owner == 'Unknown' and set_acl == 'Unknown':
                return
            if get_owner == 'Unknown' and get_acl == 'Unknown':
                return
                
            tree_key = (self.packet.tree_id, self.packet.session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(self.packet.session_id, 'Unknown')
            if user_domain == 'Unknown':
                user_domain = self.resolve_user_domain(filename, self.packet.client_ip, self.packet.session_id)
            if tree_path == 'Unknown':
                tree_path = self.resolve_tree_path(filename, self.packet.client_ip, tree_key)
                
            if get_owner != 'Unknown' and set_owner != 'Unknown' and set_owner != get_owner:
                get_owner_user = self.sid_to_name(get_owner)
                set_owner_user = self.sid_to_name(set_owner)
                self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Owner Changed',
                        'what': filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        'old_owner': get_owner_user,
                        'new_owner': set_owner_user,
                        })
            if get_acl != 'Unknown' and set_acl != 'Unknown' and set_acl != get_acl:
                get_acl_log = self.format_acl_lines(get_acl)
                set_acl_log = self.format_acl_lines(set_acl)
                self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'ACL modified',
                        'what': filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': file_or_dir,
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        'old_acl': get_acl_log,
                        'new_acl': set_acl_log,
                        })
        except Exception as e:
             logging.error(f"Error processing: set_security_response: {e}")

    def file_accessed(self):
        try:

            file_key = (self.packet.session_id, self.packet.file_id)
            filename = self.file_accessed_info.pop(file_key,('Unknown'))
            if filename == 'Unknown':
                return
                        
            tree_key = (self.packet.tree_id, self.packet.session_id)
            
            user_domain = self.smb2_sessions.get(self.packet.session_id, 'Unknown')
            if user_domain == 'Unknown':
                user_domain = self.resolve_user_domain(filename, self.packet.client_ip, self.packet.session_id) 
            
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            if tree_path == 'Unknown':
                tree_path = self.resolve_tree_path(filename, self.packet.client_ip, tree_key)
            self.log_data({
                        'when': self.packet.formatted_time,
                        'who': user_domain,
                        'action': 'Accessed',
                        'what': filename,
                        'where': self.computer_name,
                        'share_name': tree_path,
                        'object_type': 'File',
                        'host': self.packet.client_ip,
                        'status': 'Success',
                        })
        except AttributeError:
            logging.error("Error processing: file_accessed, attribute not found.")
        except Exception as e:
            logging.error(f"Unexpected error in file_accessed: {e}")

    def parse_timestamp(self, time_str):
        time_format = "%b %d, %Y %H:%M:%S.%f"
        if not time_str:
            logging.error("No timestamp provided.")
            return None
        try:
            main_part, _, tz_part = time_str.rpartition(' ')    
            date_time_part, _, fractional_part = main_part.rpartition('.')
            if len(fractional_part) > 6:  
                fractional_part = fractional_part[:6]  
            clean_time_str = f"{date_time_part}.{fractional_part}"
            parsed_time = datetime.strptime(clean_time_str, time_format)
            return parsed_time
        except ValueError as e:
            logging.error(f"Error parsing time '{time_str}': {e}")
            return None
    
    def resolve_user_domain(self, filename, ip_address, session_id):
        try:
            user_domain, script_path = self.run_script(filename, ip_address, "ClientUserName")
            if user_domain != 'Unknown':
                self.smb2_sessions[session_id] = user_domain
            return user_domain
        except Exception as e:
            logging.error(f"Error resolving user domain for file: {filename} from IP: {ip_address}. Error: {e}")
            return 'Unknown'
                        
    def resolve_tree_path(self, filename, ip_address, tree_key):
        try:
            tree_path = 'Unknown'
            full_path, script_path = self.run_script(filename, ip_address, "Path")
            
            if full_path != 'Unknown':
                full_path_lower = full_path.lower()

                for share_path, share_name in self.share_info_dict.items():
                    expected_path = f"{share_path}\\{script_path}"
                    expected_path_lower = expected_path.lower()
                    if full_path_lower == expected_path_lower:
                        tree_path = share_name
                        self.tree_connect_info[tree_key] = tree_path

                if tree_path == 'Unknown':
                    self.get_shared_folders()
                    for share_path, share_name in self.share_info_dict.items():
                        expected_path = f"{share_path}\\{script_path}"
                        expected_path_lower = expected_path.lower()
                        if full_path_lower == expected_path_lower:
                            tree_path = share_name
                            self.tree_connect_info[tree_key] = tree_path
                            break

            return tree_path
        except Exception as e:
            logging.error(f"Error in resolve_tree_path for file: {filename} from IP: {ip_address}. Error: {e}")
            return 'Unknown'
    
    def execute_powershell_script(self, path, ip_address, property_name):
        try:
            script = f'Get-SmbOpenFile | Where-Object {{ $_.ShareRelativePath -eq "{path}" -and $_.ClientComputerName -eq "{ip_address}" }} | Select-Object -Property {property_name} | Out-String -Width 4096'
            result = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", script], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 3:
                return lines[2].strip()
            else:
                return "Unknown"
        except subprocess.CalledProcessError as ex:
            logging.error(f"PowerShell script failed with exit code {ex.returncode}. Error: {ex.stderr}, Script {script}")
            return "Unknown"
        except Exception as ex:
            logging.error(f"Exception occurred: Script {script}, {ex}")
            return "Unknown"

    def run_script(self, path, ip_address, property_name):
        while True:
            result = self.execute_powershell_script( path, ip_address, property_name)
            if result != "Unknown":
                return result, path

            last_backslash_index = path.rfind("\\")
            if last_backslash_index != -1:
                path = path[:last_backslash_index]  
            else:
                break  
        return "Unknown", path
    
    def get_shared_folders(self):
        try:
            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
            query = "SELECT * FROM Win32_Share"
            result = wmi.ExecQuery(query)

            
            for share in result:
                share_path = f"\\\\{self.computer_name}\\{share.Name}"
                self.share_info_dict[share.Path] = share_path
            

            logging.info("Successfully updated shared folders.")
        except Exception as e:
            logging.error(f"Failed to retrieve shared folders. Error: {e}")
  
    def get_computer_name(self):
        return socket.gethostname().lower()

    def get_interface_ip_addresses(self, interface_name):
        """
        Retrieves both IPv4 and IPv6 addresses for the given network interface.
        """
        ipv4_address, ipv6_address = None, None
        
        addresses = psutil.net_if_addrs().get(interface_name)
        
        if addresses:
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    ipv4_address = addr.address
                elif addr.family == socket.AF_INET6:
                    ipv6_address = addr.address
                    
        if not ipv4_address and not ipv6_address:
            raise ValueError(f"No IP address found for interface {interface_name}")
        
        return ipv4_address, ipv6_address

    def generate_capture_filter(self, ipv4_address, ipv6_address):
        """
        Generates the capture filter string dynamically using IPv4 and IPv6 addresses.
        """
        base_filter = (
            '(((smb2.cmd == 3 and smb2.flags.response == 0 and !(smb2.tree contains "IPC$")) ' 
            'or (smb2.cmd == 4 and smb2.flags.response == 1 and smb2.nt_status == 0x00000000) '
            'or (smb2.cmd == 3 and smb2.flags.response == 1 and smb2.nt_status == 0 and !(smb2.tree contains "IPC$")) '
            'or (smb2.cmd == 5 and smb2.flags.response == 0 ) '
            'or (smb2.cmd == 5 and smb2.flags.response == 1 and smb2.last_access.time != 0 and smb2.nt_status == 0) '
            'or (smb2.cmd == 6 and smb2.flags.response == 0 ) '
            'or (smb2.cmd == 6 and smb2.flags.response == 1 and smb2.nt_status == 0) '
            'or (smb2.cmd == 8 and not dcerpc and smb2.file_offset == 0 and not data and (not smb2.share_type or smb2.share_type == 0x01)) '
            'or (smb2.cmd == 16 and smb2.sec_info.infolevel == 0x00 '
            'and (smb2.flags.response == 0 and smb2.getsetinfo_additional_secinfo.owner == 1 or smb2.getsetinfo_additional_secinfo.dacl == 1 or smb2.nt_status == 0)) '
            'or (smb2.cmd == 17)) and !(smb2.filename contains ":Zone.Identifier") '
            'and !(smb2.filename contains "") and !(smb2.filename contains ":") and !(smb2.filename == "srvsvc") and !(smb2.filename == "wkssvc") and !(smb2.filename == "MsFteWds") '
            'and !(smb2.file_attribute.hidden == 1)) '
        )
        ip_filter_parts = []
        if ipv4_address:
            ip_filter_parts.append(f"((ip.dst == {ipv4_address} and smb2.flags.response == 0) or (ip.src == {ipv4_address} and smb2.flags.response == 1))")
        if ipv6_address:
            ip_filter_parts.append(f"((ipv6.dst == {ipv6_address} and smb2.flags.response == 0) or (ipv6.src == {ipv6_address} and smb2.flags.response == 1))")
        
        ip_filter = ' or '.join(ip_filter_parts)
        capture_filter = f"{base_filter} and ({ip_filter})"
        return capture_filter
    
    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                self.interface = config.get('interface')
                if not self.interface:
                    raise ValueError("Interface not specified in config file.")
                self.url = config.get('url')
                self.token = config.get('basic-auth')
                self.save_to_file = config.get('save_to_file')
                self.num_files = config.get('num_files')
                self.logs_dir = config.get('logs_directory')
                self.pcap_files = config.get('pcap_files')
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            
    def format_acl_lines(self, acl_lines):
        get_acl_lines = acl_lines.split('\n') if acl_lines else []
        sid_pattern = re.compile(r'S-\d+-\d+(?:-\d+)+')
        formatted_lines = []
        for i, get_line in enumerate(get_acl_lines):
            sid_match = sid_pattern.search(get_line)
            if sid_match:
                sid = sid_match.group()
                acl_lines_formatted = self.sid_to_name(sid)

                line_parts = get_line.split(',', 1)
                if len(line_parts) == 2:
                    line_part1, line_part2 = line_parts
                    formatted_lines.append(f"[({i + 1}) {acl_lines_formatted},{line_part2}]")
                else:
                    logging.warning(f"({i + 1}) [Invalid line format: {get_line}]")

        log_string = '\n'.join(formatted_lines)
        return log_string
    
    def sid_to_name(self, sid_str):
        try:
            sid = win32security.ConvertStringSidToSid(sid_str)
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}"
        except Exception as e:
            logging.error(f"Error converting SID to name: {e}")
            return sid_str

def parse_arguments():
    parser = argparse.ArgumentParser(description='SMB2 Monitor with config file')
    parser.add_argument('-c', '--config', 
                        required=True,
                        help='Path to the configuration file')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    monitor = SMB2Monitor(config_file=args.config)
    monitor.process_smb2_packet()