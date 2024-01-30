from datetime import datetime
from collections import defaultdict
import logging
import time 
import pyshark
import re
import datetime
import logging
import json
import signal
import asyncio
import os
import traceback




logging.basicConfig(level=logging.INFO,
                    format='%(levelname)s - %(message)s',
                    filename='smb2monitor-test01.log')
class SMB2Monitor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.capture_filter = (
            '((smb2.cmd == 3 and smb2.flags.response == 0 and !(smb2.tree contains "IPC$")) ' 
            'or (smb2.cmd == 4 and  smb2.flags.response == 1 and smb2.nt_status == 0x00000000) '
            'or (smb2.cmd == 3 and smb2.flags.response == 1 and smb2.nt_status == 0 and !(smb2.tree contains "IPC$")) '
            'or (smb2.cmd == 5 and smb2.flags.response == 0 ) '
            'or (smb2.cmd == 5 and smb2.flags.response == 1 and smb2.last_access.time != 0 and smb2.nt_status == 0) '
            'or (smb2.cmd == 6 and smb2.flags.response == 0 ) '
            'or (smb2.cmd == 6 and smb2.flags.response == 1 and smb2.nt_status == 0) '
            'or (smb2.cmd == 8 and not dcerpc and smb2.file_offset == 0 and not data and (not smb2.share_type or smb2.share_type == 0x01)) '
            'or (smb2.cmd == 16 and smb2.sec_info.infolevel == 0x00 '
            'and (smb2.flags.response == 0 and smb2.getsetinfo_additional_secinfo.owner == 1 '
            'or smb2.getsetinfo_additional_secinfo.dacl == 1 or smb2.nt_status == 0)) or (smb2.cmd == 17)) '
            'and !(smb2.filename contains ":Zone.Identifier")'
            'and !(smb2.filename contains "") and !(smb2.filename contains ":") and !(smb2.filename == "srvsvc") and !(smb2.filename == "wkssvc") and !(smb2.filename == "MsFteWds") '
            'and !(smb2.file_attribute.hidden == 1) '
        )
        self.kerberos_info = {}  
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
        self.smb2_packet_count = 0

    async def async_log(self, message):
        """Asynchronous logging."""
        logging.info(message)
        
    def process_smb2_packet(self):
        print("Starting SMB packet read from file:", self.file_path)
        capture = pyshark.FileCapture(input_file=self.file_path, display_filter=self.capture_filter)
        start_time = time.perf_counter()

        try:
            for packet in capture:
                self.smb2_packet_count += 1
                if hasattr(packet, 'smb2'):
                    if packet.smb2.cmd == '1':
                        if packet.smb2.buffer_code == '0x0009':
                            if packet.smb2.nt_status == '0x00000000':
                                self.capture_smb2_session_setup(packet)
                    elif packet.smb2.cmd == '2':
                        if hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'True' and \
                        packet.smb2.nt_status == '0x00000000':
                                self.logoff_session_response(packet)
                    elif packet.smb2.cmd == '3':
                        if hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'False':
                            self.tree_connect_request(packet)
                        elif hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'True' and \
                            hasattr(packet.smb2, 'nt_status') and packet.smb2.nt_status == '0x00000000'and \
                            hasattr(packet.smb2, 'share_type') and packet.smb2.share_type == '0x01':
                                self.tree_connect_response(packet)    
                    elif packet.smb2.cmd == '4':
                        if hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'True' and \
                        hasattr(packet.smb2, 'nt_status') and packet.smb2.nt_status == '0x00000000':
                            self.tree_disconnect_response(packet)                       
                    elif packet.smb2.cmd == '5':
                        if packet.smb2.buffer_code == '0x0039':
                            self.create_request(packet)
                        elif packet.smb2.buffer_code == '0x0059':
                            self.create_response(packet)
                    elif packet.smb2.cmd == '6':
                        if hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'False':
                            self.close_request(packet)
                        elif hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'True' and \
                            hasattr(packet.smb2, 'nt_status') and packet.smb2.nt_status == '0x00000000':
                                self.close_response(packet)   
                    elif packet.smb2.cmd == '8':
                        if packet.smb2.buffer_code == '0x0031':
                            self.file_accessed(packet)
                    elif packet.smb2.cmd == '16':
                        if hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'False':
                            if hasattr(packet.smb2, 'sec_info.infolevel') and packet.smb2._all_fields['smb2.sec_info.infolevel'] == '0x00':
                                self.get_security_request(packet)
                        elif hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'True':
                            if hasattr(packet.smb2, 'sec_info_00') and packet.smb2.sec_info_00 == 'SMB2_SEC_INFO_00':
                                if hasattr(packet.smb2, 'nt_status') and packet.smb2.nt_status == '0x00000000':
                                    self.get_security_response(packet)
                    elif packet.smb2.cmd == '17':
                        if hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'False':
                            if hasattr(packet.smb2, 'file_disposition_info') and packet.smb2.file_disposition_info == 'SMB2_FILE_DISPOSITION_INFO':
                                self.folder_delete_request(packet)
                            elif hasattr(packet.smb2, 'file_rename_info') and packet.smb2.file_rename_info == 'SMB2_FILE_RENAME_INFO':
                                self.handle_rename_request(packet)
                            elif hasattr(packet.smb2, 'sec_info.infolevel') and packet.smb2._all_fields['smb2.sec_info.infolevel'] == '0x00':
                                self.set_security_request(packet)
                        elif hasattr(packet.smb2, 'flags.response') and packet.smb2._all_fields['smb2.flags.response'] == 'True':
                            if hasattr(packet.smb2, 'file_info.infolevel') and packet.smb2._all_fields['smb2.file_info.infolevel'] == '0x0d':
                                if hasattr(packet.smb2, 'nt_status') and packet.smb2.nt_status == '0x00000000':
                                    self.folder_delete_response(packet)
                            elif hasattr(packet.smb2, 'file_info.infolevel') and packet.smb2._all_fields['smb2.file_info.infolevel'] == '0x0a':
                                if hasattr(packet.smb2, 'nt_status') and packet.smb2.nt_status == '0x00000000':
                                    self.handle_rename_response(packet)
                            elif hasattr(packet.smb2, 'sec_info.infolevel') and packet.smb2._all_fields['smb2.sec_info.infolevel'] == '0x00':
                                if hasattr(packet.smb2, 'nt_status') and packet.smb2.nt_status == '0x00000000':
                                    self.set_security_response(packet)
        except KeyboardInterrupt:
            logging.info("Packet capture stopped by user.")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
        finally:
            end_time = time.perf_counter()  # Record the end time
            logging.info(f"Processed a total of {self.smb2_packet_count} SMB2 packet(s)")
            logging.info(f"Finished processing packets in {end_time - start_time} seconds.")  # Print the duration


    def capture_smb2_session_setup(self, packet):
        try:
            session_id = packet.smb2.sesid
            ip = packet.ip.dst
            user_domain = self.kerberos_info.get(ip, 'Unknown')

            if user_domain != 'Unknown':
                self.smb2_sessions[session_id] = user_domain
            else:
                
                ntlmssp_verf = packet.smb2._all_fields.get('ntlmssp.verf', None)
                if hasattr(packet.smb2, 'acct') and hasattr(packet.smb2, 'domain') and ntlmssp_verf == 'NTLMSSP Verifier':
                    username = packet.smb2._all_fields.get('smb2.acct', 'Unknown')
                    domain = packet.smb2._all_fields.get('smb2.domain', 'Unknown')
                    user_domain = f"{domain}\\{username}"
                    self.smb2_sessions[session_id] = user_domain
        except AttributeError as e:
            logging.error("Error processing: capture_smb2_session_setup")
    
    def tree_connect_request(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            tree_path = packet.smb2.tree
            self.tree_request_info[msg_key] = tree_path
        except AttributeError:
            logging.error("Error processing: tree_connect_request")

    def tree_connect_response(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            tree_id = packet.smb2.tid
            tree_path = self.tree_request_info.pop(msg_key, 'Unknown')
            if tree_path != 'Unknown':
                session_id = packet.smb2.sesid
                tree_key = (tree_id, session_id)
                self.tree_connect_info[tree_key] = tree_path
        except AttributeError:
            logging.error("Error processing: tree_connect_response")
    
    def tree_disconnect_response(self, packet):
        try:
            tree_id = packet.smb2.tid
            session_id = packet.smb2.sesid
            tree_key = (tree_id, session_id)

            if tree_key in self.tree_connect_info:
                del self.tree_connect_info[tree_key]

        except AttributeError:
            logging.error("Error processing: tree_disconnect_response")
    
    def logoff_session_response(self, packet):
        try:
            session_id = packet.smb2.sesid
            if session_id in self.smb2_sessions:
                del self.smb2_sessions[session_id]

        except AttributeError:
            logging.error("Error processing: logoff_session_response")

    def create_request(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            filename = packet.smb2.filename

            if ':' in filename:
                return

            delete_status = 'Unknown'
            open_or_create = 'Unknown'
            tree_id = packet.smb2.tid  
            if 'smb.nt.create_options.delete_on_close' in packet.smb2._all_fields:
                delete_status = 'True' if packet.smb2._all_fields['smb.nt.create_options.delete_on_close'] == 'True' else 'False'
            if 'smb2.create.disposition' in packet.smb2._all_fields:
                open_or_create = 'Create' if packet.smb2._all_fields['smb2.create.disposition'] == '2' else ('Open' if packet.smb2._all_fields['smb2.create.disposition'] == '1' else 'Unknown')  
            self.create_request_info[msg_key] = (filename, delete_status, open_or_create, tree_id)
        except AttributeError:
            logging.error("Error processing: create_request")

    def create_response(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            filename, delete_status, open_or_create, tree_id = self.create_request_info.pop(msg_key, ('Unknown', 'Unknown', 'Unknown', 'Unknown'))

            if filename == 'Unknown':
                return
            
            file_id = packet.smb2.fid
            status = packet.smb2.nt_status
            file_or_dir = 'Unknown'
            create_action = 'Unknown'
            file_or_dir = 'Directory' if packet.smb2.get_field_value('file_attribute.directory') == 'True' else ('File' if packet.smb2.get_field_value('file_attribute.directory') == 'False' else 'Unknown')
            create_action = 'Opened' if packet.smb2.get_field_value('create.action') == '1' else ('Created' if packet.smb2.get_field_value('create.action') == '2' else 'Unknown')

            file_key = (session_id, file_id)
            self.create_response_info[file_key] = (filename, file_or_dir)
            if delete_status == 'True' and file_or_dir == 'File' and status == '0x00000000' :
                self.delete_file(packet, filename, file_or_dir, tree_id)
            if create_action == 'Created' and open_or_create == 'Create' and status == '0x00000000':
                self.create_file_folder(packet, filename, file_or_dir, tree_id)    
            if create_action == 'Opened' and open_or_create == 'Open' and status == '0x00000000' and file_or_dir == 'File' :
                self.file_accessed_info[file_key] = (filename)
            if hasattr(packet.smb2, 'last_write_time') and file_or_dir == 'File' and create_action != 'Created' :
                last_write_time_str = packet.smb2.last_write_time  
                last_write_time = self.parse_timestamp(last_write_time_str)  
                file_modify_key = (session_id, filename)
                if file_modify_key in self.file_modifications and self.file_modifications[file_modify_key] < last_write_time:
                    self.file_modification(packet, filename, last_write_time, tree_id)
                self.file_modifications[file_modify_key] = last_write_time        
        except AttributeError:
            logging.error("Error processing: create_response")

    def close_request(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            file_id = packet.smb2.fid
            file_key = (session_id, file_id)
            filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            if filename == 'Unknown':
                return
            self.close_request_info[msg_key] = (file_key)
        except AttributeError:
            logging.error("Error processing: close_request")

    def close_response(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            file_key = self.close_request_info.pop(msg_key, ('Unknown'))
            if file_key == 'Unknown':
                return
            filename, file_or_dir = self.create_response_info.pop(file_key, ('Unknown', 'Unknown'))
        except AttributeError:
            logging.error("Error processing: close_response")

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
            parsed_time = datetime.datetime.strptime(clean_time_str, time_format)
            return parsed_time
        except ValueError as e:
            logging.error(f"Error parsing time '{time_str}': {e}")
            return None
    
    def handle_rename_request(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            file_id = packet.smb2.fid
            file_key = (session_id, file_id)
            old_filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            new_filename = packet.smb2.filename
            self.rename_info[msg_key] = (file_or_dir, old_filename, new_filename)    
        except AttributeError:
            pass  

    def handle_rename_response(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            file_or_dir, old_filename, new_filename = self.rename_info.pop(msg_key, ('Unknown', 'Unknown', 'Unknown'))
            if new_filename == 'Unknown' or old_filename == 'Unknown':
                return
            timestamp = datetime.datetime.fromtimestamp(float(packet.sniff_timestamp))
            formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ip = packet.ip.dst
            tree_id = packet.smb2.tid
            tree_key = (tree_id, session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(session_id, 'Unknown')
            
            def split_path(filename):
                if '\\' in filename:
                    path, base_name = filename.rsplit('\\', 1)
                else:
                    path, base_name = '', filename  
                return path, base_name

            old_path, old_base_name = split_path(old_filename)
            new_path, new_base_name = split_path(new_filename)

            if old_base_name != new_base_name and old_path == new_path:
                logging.info(f"[{formatted_time}] [{ip}] [Renamed] [{file_or_dir}] [{user_domain}] [{tree_path}] [{old_filename}] [{new_filename}]")
            elif old_path != new_path and old_base_name == new_base_name:
                logging.info(f"[{formatted_time}] [{ip}] [Moved] [{file_or_dir}] [{user_domain}] [{tree_path}] [{old_filename}] [{new_filename}]")
            elif old_path != new_path and old_base_name != new_base_name:
                intermediate_filename = f"{new_path + '\\' if new_path else ''}{old_base_name}"
                logging.info(f"[{formatted_time}] [{ip}] [Moved] [{file_or_dir}] [{user_domain}] [{tree_path}] [{old_filename}] [{intermediate_filename}]")
                logging.info(f"[{formatted_time}] [{ip}] [Renamed] [{file_or_dir}] [{user_domain}] [{tree_path}] [{intermediate_filename}] [{new_filename}]")
        except AttributeError:
            logging.error("Error processing: handle_rename_response")

    def delete_file(self, packet, filename, file_or_dir, tree_id):
        try:
            if filename == 'Unknown':
                return
            timestamp = datetime.datetime.fromtimestamp(float(packet.sniff_timestamp))
            formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ip = packet.ip.dst
            session_id = packet.smb2.sesid
            tree_key = (tree_id, session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(session_id, 'Unknown')
            logging.info(f"[{formatted_time}] [{ip}] [Deleted] [{file_or_dir}] [{user_domain}] [{tree_path}] [{filename}]")
        except AttributeError:
            logging.error("Error processing: delete_file")
        
    def folder_delete_request(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            file_id = packet.smb2.fid
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            file_key = (session_id, file_id)
            filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            self.create_delete_info[msg_key] = (filename, file_or_dir)
        except AttributeError:
            logging.error("Error processing: folder_delete_request")
        
    def folder_delete_response(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            filename, file_or_dir = self.create_delete_info.pop(msg_key, ('Unknown', 'Unknown'))
            if filename == 'Unknown':
                return
            timestamp = datetime.datetime.fromtimestamp(float(packet.sniff_timestamp))
            formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ip = packet.ip.dst
            tree_id = packet.smb2.tid
            
            tree_key = (tree_id, session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(session_id, 'Unknown')

            logging.info(f"2[{formatted_time}] [{ip}] [Deleted] [{file_or_dir}] [{user_domain}] [{tree_path}] [{filename}]")
        except AttributeError:
            logging.error("Error processing: folder_delete_response")
            
    def create_file_folder(self, packet, filename, file_or_dir, tree_id):
        try:
            if filename == 'Unknown':
                return
            timestamp = datetime.datetime.fromtimestamp(float(packet.sniff_timestamp))
            formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ip = packet.ip.dst
            session_id = packet.smb2.sesid
            tree_key = (tree_id, session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(session_id, 'Unknown')
            logging.info(f"[{formatted_time}] [{ip}] [Created] [{file_or_dir}] [{user_domain}] [{tree_path}] [{filename}]")
        except AttributeError:
            logging.error("Error processing: create_file_folder")

    def file_modification(self, packet, filename, last_write_time, tree_id):
        try:
            if filename == 'Unknown':
                return
            timestamp = datetime.datetime.fromtimestamp(float(packet.sniff_timestamp))
            formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ip = packet.ip.dst
            session_id = packet.smb2.sesid
            tree_key = (tree_id, session_id)
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
            user_domain = self.smb2_sessions.get(session_id, 'Unknown')  
            logging.info(f"[{formatted_time}] [{ip}] [Modified] [File] [{user_domain}] [{tree_path}] [{filename}]")
        except AttributeError:
            logging.error("Error processing: file_modification")

    def set_security_request(self, packet):
        try:   
            file_id = packet.smb2.fid
            session_id = packet.smb2.sesid
            file_key = (session_id, file_id)
            filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            if filename and file_or_dir == 'Unknown':
                return
            msg_id = packet.smb2.msg_id
            msg_key = (msg_id, session_id)
            acl = 'Unknown'
            owner = 'Unknown'
            acl_lines = [] 
            smb_header_str = str(packet.smb2) 
            owner_pattern = re.compile(r'Owner:\s*(S-1-5-\d+-\d+)')
            nt_ace_pattern = re.compile(r'NT ACE:')     
            for line in smb_header_str.split('\n'):
                clean_line = re.sub(r'\x1b\[.*?m', '', line).strip()  
                owner_match = owner_pattern.search(clean_line)
                if owner_match:
                    owner = owner_match.group(1)
                elif nt_ace_pattern.search(clean_line):
                    acl_lines.append(clean_line)
            acl = '\n'.join(acl_lines)
            self.set_security_info[msg_key] = (filename, file_or_dir, owner, acl)
        except AttributeError:
            logging.error("Error processing: set_security_request")

    def set_security_response(self, packet):
        try:
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            tree_id = packet.smb2.tid
            filename, file_or_dir, set_owner, set_acl = self.set_security_info.pop(msg_key, ('Unknown', 'Unknown', 'Unknown', 'Unknown'))
            if filename and file_or_dir == 'Unknown':
                return
            file_key = (tree_id, filename, file_or_dir)
            get_owner, get_acl = self.get_security_response_info.pop(file_key, ('Unknown', 'Unknown'))
            if set_owner == 'Unknown' and set_acl == 'Unknown':
                return
            if get_owner == 'Unknown' and get_acl == 'Unknown':
                return
            changes = []
            if get_owner != 'Unknown' or get_acl == 'Unknown':
                if set_owner != get_owner:
                    changes.append('Owner changed')
            if get_acl != 'Unknown' or get_owner == 'Unknown':
                if set_acl != get_acl:
                    changes.append('ACL modified')
            if changes:
                change_message = ' and '.join(changes).capitalize()
                timestamp = datetime.datetime.fromtimestamp(float(packet.sniff_timestamp))
                formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                ip = packet.ip.dst
                tree_key = (tree_id, session_id)
                tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
                user_domain = self.smb2_sessions.get(session_id, 'Unknown')
                logging.info(f"[{formatted_time}] [{ip}] [{change_message}] [{file_or_dir}] [{user_domain}] [{tree_path}] [{filename}]")    
        except AttributeError:
             logging.error("Error processing: set_security_response")
        
    def get_security_request(self, packet):
        try:
            file_id = packet.smb2.fid
            session_id = packet.smb2.sesid
            file_key = (session_id, file_id)
            filename, file_or_dir = self.create_response_info.get(file_key, ('Unknown', 'Unknown'))
            if filename == 'Unknown':
                return
            msg_id = packet.smb2.msg_id
            msg_key = (msg_id, session_id)
            self.security_request_info[msg_key] = (file_or_dir, filename)
        except AttributeError:
             logging.error("Error processing: get_security_request")
        
    def get_security_response(self, packet):
        try:   
            msg_id = packet.smb2.msg_id
            session_id = packet.smb2.sesid
            msg_key = (msg_id, session_id)
            file_or_dir, filename = self.security_request_info.pop(msg_key, ('Unknown', 'Unknown'))
            if filename and file_or_dir == 'Unknown':
                return
            tree_id = packet.smb2.tid
            acl_lines = []  
            owner = 'Unknown'
            acl = 'Unknown'  
            smb_header_str = str(packet.smb2)
            owner_pattern = re.compile(r'Owner:\s*(S-1-5-\d+-\d+)')
            nt_ace_pattern = re.compile(r'NT ACE:')     
            for line in smb_header_str.split('\n'):
                clean_line = re.sub(r'\x1b\[.*?m', '', line).strip()
                owner_match = owner_pattern.search(clean_line)
                if owner_match:
                    owner = owner_match.group(1)
                elif nt_ace_pattern.search(clean_line):
                    acl_lines.append(clean_line)  
            file_key = (tree_id, filename, file_or_dir)
            if acl_lines:  
                acl = '\n'.join(acl_lines)  
            self.get_security_response_info[file_key] = (owner, acl)
        except AttributeError:
            logging.error("Error processing: get_security_response")
        
    def file_accessed(self, packet):
        try:
            
            file_id = packet.smb2.fid
            session_id = packet.smb2.sesid
            file_key = (session_id, file_id)
            filename = self.file_accessed_info.pop(file_key,('Unknown'))
            if filename == 'Unknown':
                return
            
            
            timestamp = datetime.datetime.fromtimestamp(float(packet.sniff_timestamp))
            formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            
            ip = packet.ip.src
            tree_id = packet.smb2.tid
            tree_key = (tree_id, session_id)
            
            user_domain = self.smb2_sessions.get(session_id, 'Unknown')           
            tree_path = self.tree_connect_info.get(tree_key, 'Unknown')
           
            logging.info(f"[{formatted_time}] [{ip}] [Accessed] [File] [{user_domain}] [{tree_path}] [{filename}]")
        
        except AttributeError:
            logging.error("Error processing: file_accessed, attribute not found.")
        except Exception as e:
            logging.error(f"Unexpected error in file_accessed: {e}")

if __name__ == "__main__":
    monitor = SMB2Monitor(file_path=r"file/path/here")
    monitor.process_smb2_packet()
