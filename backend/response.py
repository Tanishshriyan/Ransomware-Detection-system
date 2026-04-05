"""
Automated Response System for Ransomware Detection
Implements automated threat mitigation [web:51]
"""

import psutil
import os
import shutil
from datetime import datetime
from typing import Dict
import asyncio

from utils.resource_path import runtime_path

class AutomatedResponse:
    """
    Executes automated responses to detected ransomware threats
    Actions: Kill process, quarantine file, isolate system [web:51]
    """
    
    def __init__(self):
        self.quarantine_dir = runtime_path("data/quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.response_log = []
    
    async def execute(self, event_data: Dict) -> Dict:
        """
        Execute automated response based on threat level
        Returns: Result of actions taken
        """
        actions_taken = []
        
        try:
            # Kill malicious process
            if 'pid' in event_data:
                kill_result = await self.kill_process(event_data['pid'])
                actions_taken.append(kill_result)
            
            # Quarantine suspicious file
            if 'file_path' in event_data and os.path.exists(event_data['file_path']):
                quarantine_result = await self.quarantine_file(event_data['file_path'])
                actions_taken.append(quarantine_result)
            
            # Log response
            response_record = {
                'timestamp': datetime.now().isoformat(),
                'event': event_data,
                'actions': actions_taken
            }
            self.response_log.append(response_record)
            
            return {
                'success': True,
                'actions': actions_taken,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'actions': actions_taken
            }
    
    async def kill_process(self, pid: int) -> Dict:
        """
        Terminate suspicious process [web:51]
        """
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            # Kill process
            process.terminate()
            
            # Wait for termination
            await asyncio.sleep(1)
            
            if process.is_running():
                process.kill()  # Force kill if still running
            
            print(f" Killed process: {process_name} (PID: {pid})")
            
            return {
                'action': 'kill_process',
                'success': True,
                'process': process_name,
                'pid': pid
            }
            
        except psutil.NoSuchProcess:
            return {
                'action': 'kill_process',
                'success': False,
                'error': 'Process not found',
                'pid': pid
            }
        except psutil.AccessDenied:
            return {
                'action': 'kill_process',
                'success': False,
                'error': 'Access denied (run as administrator)',
                'pid': pid
            }
        except Exception as e:
            return {
                'action': 'kill_process',
                'success': False,
                'error': str(e),
                'pid': pid
            }
    
    async def quarantine_file(self, file_path: str) -> Dict:
        """
        Move suspicious file to quarantine [web:51]
        """
        try:
            if not os.path.exists(file_path):
                return {
                    'action': 'quarantine_file',
                    'success': False,
                    'error': 'File not found'
                }
            
            # Generate quarantine filename
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_path = os.path.join(
                self.quarantine_dir,
                f"{timestamp}_{filename}.quarantine"
            )
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            print(f" Quarantined: {file_path} → {quarantine_path}")
            
            return {
                'action': 'quarantine_file',
                'success': True,
                'original_path': file_path,
                'quarantine_path': quarantine_path
            }
            
        except Exception as e:
            return {
                'action': 'quarantine_file',
                'success': False,
                'error': str(e),
                'file_path': file_path
            }
    
    def get_response_log(self) -> list:
        """Get history of automated responses"""
        return self.response_log
