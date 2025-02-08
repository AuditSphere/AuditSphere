import logging
import time
import json
from requests.exceptions import ConnectTimeout, RequestException
import requests
import os
import threading
import queue
import datetime

class SaveLogs:
    def __init__(self, url='', token=None, save_to_file=False, num_files=30, logs_dir='logs'):
        self.save_to_file = save_to_file
        self.num_files = num_files
        self.logs_dir = logs_dir

        # Create logs directory if it doesn't exist
        if self.save_to_file:
            os.makedirs(self.logs_dir, exist_ok=True)

        if url != '':
            self.send_to_log_server = True
            self.url = url
            self.token = token
        else:
            self.send_to_log_server = False
            self.url = None
            self.token = None

        self.local_log_file = os.path.join(self.logs_dir, 'unsent_logs.json')
        self.log_queue = queue.Queue()

        # Set up logging to file in the specified directory
        log_file = os.path.join(self.logs_dir, 'save_logs.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=log_file
        )

        self.log_thread = threading.Thread(target=self._send_log_data_worker)
        self.log_thread.daemon = True
        self.log_thread.start()

        logging.info("SaveLogs initialized successfully")

    def add_log_data(self, log_data):
        """Add a log entry to the queue for processing."""
        try:
            if not isinstance(log_data, dict):
                raise ValueError("Log data must be a dictionary")
            self.log_queue.put(log_data)
        except Exception as e:
            logging.error(f"Error adding log data: {e}")

    def _send_log_data_worker(self):
        """Background worker thread for processing logs."""
        while True:
            try:
                batch_logs = []
                # Collect logs from queue
                while not self.log_queue.empty() and len(batch_logs) < 50:
                    batch_logs.append(self.log_queue.get_nowait())
                    self.log_queue.task_done()

                if batch_logs:
                    server_success = True
                    if self.send_to_log_server:
                        server_success = self.send_logs_to_server(batch_logs)
                        if not server_success:
                            self.save_logs_locally(batch_logs)

                    # Save to daily files if enabled
                    if self.save_to_file:
                        self._save_to_daily_file(batch_logs)

                    # Attempt to send any saved logs from previous failures
                    self.send_saved_logs()

                time.sleep(1)  # Prevent busy waiting
            except Exception as e:
                logging.error(f"Error in send log data worker: {e}")
                time.sleep(5)  # Back off on error

    def send_logs_to_server(self, logs):
        """Send logs to the remote server."""
        if not logs:
            return True

        headers = {
            'Authorization': f'Basic {self.token}',
            'Content-Type': 'application/json'
        }
        
        retries = 2
        timeout = 2
        
        for attempt in range(retries):
            try:
                response = requests.post(
                    self.url, 
                    headers=headers, 
                    json=logs, 
                    timeout=timeout
                )
                
                if response.status_code == 200:
                    logging.info(f"Successfully sent {len(logs)} logs to server")
                    return True
                else:
                    logging.error(f"Failed to send logs: HTTP {response.status_code}")
                    
            except ConnectTimeout:
                logging.error(f"Connection timeout on attempt {attempt + 1}/{retries}")
            except RequestException as e:
                logging.error(f"Request failed on attempt {attempt + 1}/{retries}: {e}")
            except Exception as e:
                logging.error(f"Unexpected error sending logs: {e}")
                
            if attempt < retries - 1:
                time.sleep(1)
                
        return False

    def save_logs_locally(self, logs):
        """Save logs to local file when server is unavailable."""
        try:
            existing_logs = []
            if os.path.exists(self.local_log_file):
                with open(self.local_log_file, 'r') as file:
                    existing_logs = json.load(file)
                    
            with open(self.local_log_file, 'w') as file:
                existing_logs.extend(logs)
                json.dump(existing_logs, file)
                
            logging.info(f"Saved {len(logs)} logs locally")
            
        except Exception as e:
            logging.error(f"Error saving logs locally: {e}")

    def send_saved_logs(self):
        """Attempt to send previously saved logs to the server."""
        if not os.path.exists(self.local_log_file):
            return

        try:
            with open(self.local_log_file, 'r') as file:
                saved_logs = json.load(file)

            if not saved_logs:
                os.remove(self.local_log_file)
                return

            batch_size = 50
            logs_sent = 0
            
            while saved_logs:
                current_batch = saved_logs[:batch_size]
                if self.send_logs_to_server(current_batch):
                    saved_logs = saved_logs[batch_size:]
                    logs_sent += len(current_batch)
                else:
                    break

            with open(self.local_log_file, 'w') as file:
                json.dump(saved_logs, file)

            if not saved_logs:
                os.remove(self.local_log_file)
                
            if logs_sent > 0:
                logging.info(f"Successfully sent {logs_sent} saved logs")

        except Exception as e:
            logging.error(f"Error processing saved logs: {e}")

    def _save_to_daily_file(self, logs):
        """Save logs to daily file and rotate old files if necessary."""
        if not self.save_to_file or not logs:
            return

        current_date = time.strftime("%d-%m-%Y")
        filename = os.path.join(self.logs_dir, f"smb_{current_date}.log")

        try:
            with open(filename, 'a') as f:
                for log_entry in logs:
                    json_line = json.dumps(log_entry)
                    f.write(json_line + '\n')
            logging.info(f"Appended {len(logs)} logs to {filename}")
        except Exception as e:
            logging.error(f"Failed to save logs to {filename}: {e}")

        self._rotate_log_files()

    def _rotate_log_files(self):
        """Delete oldest log files if the number exceeds the specified limit."""
        log_files = []
        for file in os.listdir(self.logs_dir):
            if file.startswith('smb_') and file.endswith('.log'):
                date_str = file[4:-4]
                try:
                    date = datetime.datetime.strptime(date_str, "%d-%m-%Y")
                    log_files.append((date, file))
                except ValueError:
                    continue

        log_files.sort(key=lambda x: x[0])

        num_files = len(log_files)
        if num_files > self.num_files:
            files_to_remove = num_files - self.num_files
            for i in range(files_to_remove):
                file_to_remove = os.path.join(self.logs_dir, log_files[i][1])
                try:
                    os.remove(file_to_remove)
                    logging.info(f"Removed old log file: {file_to_remove}")
                except OSError as e:
                    logging.error(f"Error removing file {file_to_remove}: {e}")