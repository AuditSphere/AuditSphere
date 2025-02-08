import subprocess
import os
import logging
from typing import Generator
from pathlib import Path
from threading import Thread
import queue


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProcessError(Exception):
    """Custom exception for process-related errors"""
    pass

class FileManager:
    """Handles file operations."""
    @staticmethod
    def delete_file(filepath: Path) -> None:
        """Delete a file with error handling."""
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.debug(f"Deleted capture file: {filepath}")
            else:
                logger.debug(f"File already deleted: {filepath}")
        except OSError as e:
            logger.error(f"Failed to delete file {filepath}: {e}")

class PacketCapture:
    def __init__(
        self,
        interface: str,
        output_file: str,
        filter_expr: str = "smb2",
        num_files: int = 10,
        filesize_kb: int = 1024,
        duration_sec: int = 1,
        num_tshark_processes: int = 8
    ):
        self.interface = interface
        self.output_file = output_file
        self.filter_expr = filter_expr
        self.num_files = num_files
        self.filesize_kb = filesize_kb
        self.duration_sec = duration_sec
        self.num_tshark_processes = num_tshark_processes
        self.capture_process = None
        self.tshark_processes = []
        self.filepath_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.dumpcap_thread = None

        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                logger.info(f"Created output directory: {output_dir}")
            except OSError as e:
                raise ProcessError(f"Failed to create output directory {output_dir}: {e}")
        self._setup_paths()

    def _setup_paths(self):
        """Setup Wireshark executable paths"""
        default_path = "C:\\Program Files\\Wireshark"
        self.dumpcap_path = os.path.join(default_path, "dumpcap.exe")
        self.tshark_path = os.path.join(default_path, "tshark.exe")

        if not os.path.exists(self.dumpcap_path):
            raise FileNotFoundError(f"dumpcap.exe not found at {self.dumpcap_path}")
        if not os.path.exists(self.tshark_path):
            raise FileNotFoundError(f"tshark.exe not found at {self.tshark_path}")

    def run_dumpcap(self) -> subprocess.Popen:
        """Start packet capture process"""
        command = [
            self.dumpcap_path,
            "-i", self.interface,
            "-b", f"files:{self.num_files}",
            "-b", f"filesize:{self.filesize_kb}",
            "-b", f"duration:{self.duration_sec}",
            "-b", "printname:stdout",
            "-w", self.output_file
        ]

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=1,
            universal_newlines=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        return process

    def delete_file_async(self, filepath):
        Thread(target=FileManager.delete_file, args=(filepath,), daemon=True).start()

    def run_tshark(self, filepath: str) -> Generator[str, None, None]:
        """Analyze a PCAP file and yield PDML content"""
        
        command = [
            self.tshark_path,
            "-r", filepath,
            "-Y", self.filter_expr,
            "-T", "pdml",
        ]

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        if process.poll() is not None:
            stderr = process.stderr.read()
            raise ProcessError(f"Tshark failed to start: {stderr}")

        buffer = []
        in_packet = False

        while True:
            line = process.stdout.readline()
            if not line:
                break

            line = line.strip()
            if line.startswith("<packet>"):
                in_packet = True
                buffer = [line]
            elif line.endswith("</packet>"):
                buffer.append(line)
                yield "\n".join(buffer)
                buffer = []
                in_packet = False
            elif in_packet:
                buffer.append(line)

        process.terminate()
        self.delete_file_async(filepath)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def _tshark_worker(self):
        """Worker function to process files with tshark"""
        while True:
            filepath = self.filepath_queue.get()
            if filepath is None:
                break
            logger.debug(f"Tshark worker picked up file: {filepath}")  # Debug FIFO behavior
            try:
                for packet in self.run_tshark(filepath):
                    logger.debug(f"Processed packet from file: {filepath}")  # Track packet processing
                    self.results_queue.put(packet)
            except Exception as e:
                logger.error(f"Error processing file {filepath}: {e}")
            finally:
                self.filepath_queue.task_done()

    def _dumpcap_worker(self):
        """Worker function to run dumpcap and monitor its output"""
        try:
            self.capture_process = self.run_dumpcap()
            while True:
                filepath = self.capture_process.stdout.readline().strip()
                if filepath:
                    logger.debug(f"File added to queue: {filepath}")  # Debug FIFO behavior
                    self.filepath_queue.put(filepath)
        except Exception as e:
            logger.error(f"Error in dumpcap worker: {e}")
        finally:
            # Signal tshark workers to stop
            for _ in range(self.num_tshark_processes):
                self.filepath_queue.put(None)
            if self.capture_process:
                self.capture_process.terminate()

    def capture_packets(self) -> Generator[str, None, None]:
        """Capture and analyze packets, yielding packet data"""
        try:
            # Start tshark worker threads
            tshark_threads = []
            for _ in range(self.num_tshark_processes):
                thread = Thread(target=self._tshark_worker, daemon=True)
                thread.start()
                tshark_threads.append(thread)

            # Start dumpcap thread
            self.dumpcap_thread = Thread(target=self._dumpcap_worker, daemon=True)
            self.dumpcap_thread.start()

            # Yield results as they become available
            while any(thread.is_alive() for thread in tshark_threads + [self.dumpcap_thread]):
                try:
                    packet = self.results_queue.get(timeout=0.1)
                    yield packet
                    self.results_queue.task_done()
                except queue.Empty:
                    continue

        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            raise
        finally:
            self.cleanup()
            
    def cleanup(self):
        """Cleanup processes"""
        if self.capture_process and self.capture_process.poll() is None:
            try:
                self.capture_process.kill()
                self.capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.capture_process.kill()
                self.capture_process.wait()
            except Exception as e:
                logger.error(f"Error stopping capture process: {e}")
                