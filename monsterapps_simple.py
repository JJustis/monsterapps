#!/usr/bin/env python3
"""
MonsterApps Enhanced Client - Complete Fixed Version
A distributed app store with mesh networking, PFS encryption, and MySQL node discovery.
Fixed version with proper error handling, simplified database operations, and thread safety.
"""

import os
import sys
import json
import uuid
import time
import hmac
import hashlib
import secrets
import threading
import webbrowser
import socket
import struct
import base64
import sqlite3
import shutil
import logging
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Any, Tuple
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Setup comprehensive logging to catch silent errors
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler('monsterapps.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Optional imports with fallbacks
try:
    import requests
    try:
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        pass
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False
    logger.warning("Requests not available")

try:
    import mysql.connector
    from mysql.connector.pooling import MySQLConnectionPool
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    logger.warning("MySQL connector not available. Install with: pip install mysql-connector-python")

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("Cryptography not available. Install with: pip install cryptography")

# ===========================
# CONFIGURATION
# ===========================

CONFIG = {
    'PORTAL_URL': 'http://secupgrade.com/appstore.php',
    'MYSQL_HOST': 'localhost',
    'MYSQL_USER': 'root',
    'MYSQL_PASSWORD': '',
    'MYSQL_DATABASE': 'monsterapps_mesh',
    'P2P_PORT_RANGE': (9000, 9100),
    'WEBSERVER_PORT': 9001,
    'HEARTBEAT_INTERVAL': 120,
    'NODE_TIMEOUT': 1220,
    'UPLOAD_PATH': 'meshnetwork/monsterapps/apps',
    'MAX_PEERS': 10,
    'APPS_DIR': 'installed_apps',
    'EXPANSIONS_DIR': 'expansions',
    'BACKUPS_DIR': 'client_backups',
    'ENABLE_DATABASE': True,
    'ENABLE_PORTAL': True
}

# ===========================
# EXCEPTION WRAPPER FOR THREADING
# ===========================

def safe_thread_wrapper(func):
    """Wrapper to catch and log exceptions in threads"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Thread error in {func.__name__}: {e}", exc_info=True)
            # Don't re-raise - just log to prevent silent crashes
    return wrapper

# ===========================
# DATA MODELS
# ===========================

@dataclass
class AppInfo:
    """Enhanced application information model"""
    app_id: str
    name: str
    version: str
    description: str
    category: str
    developer: str
    company: str = "Unknown"
    file_path: str = ""
    file_size: int = 0
    file_hash: str = ""
    app_token: str = ""
    downloads: int = 0
    rating: float = 0.0
    created_at: float = 0.0
    uploaded: bool = False
    is_expansion: bool = False
    usage_time: float = 0.0
    last_used: float = 0.0
    launch_count: int = 0
    badges: List[str] = None
    
    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.badges is None:
            self.badges = []
        if not self.app_token:
            self.app_token = secrets.token_hex(16)
        if not self.company:
            self.company = "Unknown"
    
    def to_dict(self):
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data):
        if 'company' not in data:
            data['company'] = "Unknown"
        if 'app_token' not in data:
            data['app_token'] = secrets.token_hex(16)
        if 'is_expansion' not in data:
            data['is_expansion'] = False
        if 'usage_time' not in data:
            data['usage_time'] = 0.0
        if 'last_used' not in data:
            data['last_used'] = 0.0
        if 'launch_count' not in data:
            data['launch_count'] = 0
        if 'badges' not in data:
            data['badges'] = []
        
        return cls(**data)

@dataclass
class NodeInfo:
    """Enhanced node information with chat support"""
    node_id: str
    username: str
    ip_address: str
    port: int
    public_key: Optional[bytes] = None
    last_seen: float = 0.0
    connected: bool = False
    apps_count: int = 0
    chat_enabled: bool = True
    status: str = "online"
    
    def __post_init__(self):
        if self.last_seen == 0.0:
            self.last_seen = time.time()

# ===========================
# SIMPLIFIED DATABASE CLASS
# ===========================

class SimpleDatabase:
    """Simplified database class with PDO-style execute and query methods"""
    
    def __init__(self):
        self.pool = None
        self.fallback_mode = False
        self.connection_lock = threading.RLock()
        self.last_error = None
        self.error_count = 0
        self.max_errors = 5
        
        if MYSQL_AVAILABLE and CONFIG['ENABLE_DATABASE']:
            self._init_connection_pool()
        else:
            logger.warning("Database disabled - using fallback mode")
            self.fallback_mode = True
        
        # Fallback storage
        self.fallback_data = {
            'nodes': {},
            'messages': [],
            'apps': []
        }
    
    def _init_connection_pool(self):
        """Initialize MySQL connection pool"""
        try:
            # First ensure database exists
            temp_config = {
                'host': CONFIG['MYSQL_HOST'],
                'user': CONFIG['MYSQL_USER'],
                'password': CONFIG['MYSQL_PASSWORD'],
                'charset': 'utf8mb4',
                'autocommit': True
            }
            
            temp_conn = mysql.connector.connect(**temp_config)
            cursor = temp_conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {CONFIG['MYSQL_DATABASE']}")
            cursor.close()
            temp_conn.close()
            
            # Create connection pool
            pool_config = {
                'host': CONFIG['MYSQL_HOST'],
                'user': CONFIG['MYSQL_USER'],
                'password': CONFIG['MYSQL_PASSWORD'],
                'database': CONFIG['MYSQL_DATABASE'],
                'charset': 'utf8mb4',
                'autocommit': True,
                'pool_name': 'monsterapps_pool',
                'pool_size': 5,
                'pool_reset_session': True
            }
            
            self.pool = MySQLConnectionPool(**pool_config)
            
            # Initialize tables
            self._init_tables()
            
            logger.info("Database connection pool initialized")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            self.fallback_mode = True
    
    def _init_tables(self):
        """Initialize database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS mesh_nodes (
                node_id VARCHAR(64) PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                port INT NOT NULL,
                webserver_port INT DEFAULT 9001,
                public_key TEXT,
                client_token VARCHAR(128),
                last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                apps_count INT DEFAULT 0,
                status ENUM('online', 'offline', 'busy') DEFAULT 'online',
                chat_enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_last_heartbeat (last_heartbeat),
                INDEX idx_status (status)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender_node_id VARCHAR(64) NOT NULL,
                receiver_node_id VARCHAR(64),
                message_type ENUM('direct', 'broadcast', 'system') DEFAULT 'direct',
                content TEXT NOT NULL,
                encrypted BOOLEAN DEFAULT FALSE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered BOOLEAN DEFAULT FALSE,
                INDEX idx_receiver (receiver_node_id),
                INDEX idx_timestamp (timestamp)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS app_availability (
                id INT AUTO_INCREMENT PRIMARY KEY,
                node_id VARCHAR(64) NOT NULL,
                app_token VARCHAR(64) NOT NULL,
                app_name VARCHAR(200) NOT NULL,
                app_category VARCHAR(50) NOT NULL,
                file_size BIGINT NOT NULL,
                file_hash VARCHAR(64) NOT NULL,
                download_url VARCHAR(500),
                last_verified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                status ENUM('available', 'unavailable', 'verifying') DEFAULT 'available',
                UNIQUE KEY unique_node_app (node_id, app_token),
                INDEX idx_node_id (node_id)
            )
            """
        ]
        
        for table_sql in tables:
            self.execute(table_sql)
    
    def execute(self, query: str, params: tuple = None) -> bool:
        """Execute a query (INSERT, UPDATE, DELETE) - returns success"""
        if self.fallback_mode:
            return self._execute_fallback(query, params)
        
        with self.connection_lock:
            connection = None
            cursor = None
            try:
                connection = self.pool.get_connection()
                cursor = connection.cursor(buffered=True)
                
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                # Connection pool handles commit with autocommit=True
                self.error_count = 0  # Reset on success
                return True
                
            except Exception as e:
                self._handle_error(f"Execute error: {e}")
                return False
                
            finally:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()  # Returns to pool
    
    def query(self, query: str, params: tuple = None, fetch_one: bool = False) -> Optional[Any]:
        """Execute a SELECT query - returns results"""
        if self.fallback_mode:
            return self._query_fallback(query, params, fetch_one)
        
        with self.connection_lock:
            connection = None
            cursor = None
            try:
                connection = self.pool.get_connection()
                cursor = connection.cursor(buffered=True)
                
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch_one:
                    result = cursor.fetchone()
                else:
                    result = cursor.fetchall()
                
                self.error_count = 0  # Reset on success
                return result
                
            except Exception as e:
                self._handle_error(f"Query error: {e}")
                return None
                
            finally:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()  # Returns to pool
    
    def _handle_error(self, error_msg: str):
        """Handle database errors with fallback"""
        self.error_count += 1
        self.last_error = error_msg
        logger.error(error_msg)
        
        if self.error_count >= self.max_errors:
            logger.warning("Too many database errors - switching to fallback mode")
            self.fallback_mode = True
    
    def _execute_fallback(self, query: str, params: tuple = None) -> bool:
        """Fallback execute for when database is unavailable"""
        logger.debug(f"Fallback execute: {query[:50]}...")
        return True  # Always succeed in fallback
    
    def _query_fallback(self, query: str, params: tuple = None, fetch_one: bool = False) -> Optional[Any]:
        """Fallback query for when database is unavailable"""
        logger.debug(f"Fallback query: {query[:50]}...")
        
        # Simple fallback for common queries
        if "mesh_nodes" in query.lower():
            nodes = list(self.fallback_data['nodes'].values())
            return nodes[0] if fetch_one and nodes else nodes
        elif "chat_messages" in query.lower():
            return self.fallback_data['messages']
        elif "app_availability" in query.lower():
            return self.fallback_data['apps']
        
        return None if fetch_one else []
    
    def is_available(self) -> bool:
        """Check if database is available"""
        return not self.fallback_mode
    
    def close(self):
        """Close database connections"""
        if self.pool:
            # Connection pools don't need explicit closing in mysql-connector-python
            pass

# ===========================
# WEB SERVER FOR APP HOSTING
# ===========================

class AppDownloadHandler(BaseHTTPRequestHandler):
    """HTTP handler for app download requests"""
    
    def __init__(self, *args, app_manager=None, auth_system=None, **kwargs):
        self.app_manager = app_manager
        self.auth_system = auth_system
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests for app downloads"""
        try:
            parsed = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            if parsed.path == '/grab':
                self.handle_app_download(query_params)
            elif parsed.path == '/status':
                self.handle_status_check()
            elif parsed.path == '/apps':
                self.handle_app_list()
            elif parsed.path == '/verify':
                self.handle_hash_verification(query_params)
            elif parsed.path == '/debug':
                self.handle_debug_info(query_params)
            elif parsed.path == '/refresh_hashes':
                self.handle_refresh_hashes()
            else:
                self.send_error(404, "Endpoint not found")
                
        except Exception as e:
            logger.error(f"Web server error: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_app_download(self, params):
        """Handle app download with token verification"""
        app_token = params.get('ack', [None])[0]
        
        if not app_token:
            self.send_error(400, "Missing app token")
            return
        
        # Find app by token
        target_app = None
        for app in self.app_manager.get_apps():
            if app.app_token == app_token:
                target_app = app
                break
        
        if not target_app:
            self.send_error(404, "App not found or token invalid")
            return
        
        if not os.path.exists(target_app.file_path):
            self.send_error(404, "App file not found on server")
            return
        
        # Send file
        try:
            with open(target_app.file_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{target_app.name}.exe"')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('X-App-Hash', target_app.file_hash)
            self.send_header('X-App-Token', target_app.app_token)
            self.end_headers()
            
            self.wfile.write(content)
            
            # Update download count
            target_app.downloads += 1
            self.app_manager.save_apps()
            
            logger.info(f"App downloaded: {target_app.name} (token: {app_token})")
            
        except Exception as e:
            self.send_error(500, f"Download failed: {e}")
    
    def handle_hash_verification(self, params):
        """Handle MD5 hash verification requests"""
        app_token = params.get('token', [None])[0] or params.get('app_token', [None])[0]
        
        if not app_token:
            self.send_error(400, "Missing app token")
            return
        
        # Find app and calculate current hash
        target_app = None
        for app in self.app_manager.get_apps():
            if app.app_token == app_token:
                target_app = app
                break
        
        if not target_app:
            self.send_error(404, "App not found")
            return
        
        if not os.path.exists(target_app.file_path):
            self.send_error(404, "App file not found on disk")
            return
        
        # Calculate current file hash
        try:
            current_hash = self._calculate_md5_hash(target_app.file_path)
            
            response_data = {
                'app_token': app_token,
                'stored_hash': target_app.file_hash,
                'current_hash': current_hash,
                'verified': current_hash == target_app.file_hash,
                'file_size': os.path.getsize(target_app.file_path),
                'app_name': target_app.name,
                'file_exists': True,
                'debug_info': {
                    'stored_hash_length': len(target_app.file_hash),
                    'current_hash_length': len(current_hash),
                    'file_path': target_app.file_path,
                    'file_size_bytes': os.path.getsize(target_app.file_path)
                }
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            self.wfile.write(json.dumps(response_data, indent=2).encode())
            
            logger.info(f"Hash verification: {target_app.name} - Match: {current_hash == target_app.file_hash}")
            
        except Exception as e:
            error_response = {
                'success': False,
                'error': f"Hash verification failed: {str(e)}",
                'app_token': app_token,
                'app_name': target_app.name if target_app else 'Unknown'
            }
            
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(error_response).encode())
            
            logger.error(f"Hash verification error for {app_token}: {e}")
    
    def handle_status_check(self):
        """Handle server status requests"""
        status_data = {
            'status': 'online',
            'timestamp': time.time(),
            'apps_available': len(self.app_manager.get_apps()),
            'node_id': self.auth_system.node_id if self.auth_system else 'unknown'
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        self.wfile.write(json.dumps(status_data).encode())
    
    def handle_app_list(self):
        """Handle app list requests"""
        apps_data = []
        for app in self.app_manager.get_apps():
            apps_data.append({
                'app_token': app.app_token,
                'name': app.name,
                'version': app.version,
                'category': app.category,
                'developer': app.developer,
                'company': app.company,
                'file_size': app.file_size,
                'downloads': app.downloads,
                'rating': app.rating,
                'is_expansion': app.is_expansion
            })
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        self.wfile.write(json.dumps(apps_data).encode())
    
    def handle_debug_info(self, params):
        """Handle debug information requests"""
        try:
            apps_info = []
            for app in self.app_manager.get_apps():
                file_exists = os.path.exists(app.file_path)
                current_size = os.path.getsize(app.file_path) if file_exists else 0
                
                apps_info.append({
                    'name': app.name,
                    'app_token': app.app_token,
                    'stored_hash': app.file_hash,
                    'stored_size': app.file_size,
                    'file_path': app.file_path,
                    'file_exists': file_exists,
                    'current_size': current_size,
                    'size_match': current_size == app.file_size if file_exists else False
                })
            
            debug_data = {
                'total_apps': len(self.app_manager.get_apps()),
                'web_server_port': CONFIG['WEBSERVER_PORT'],
                'apps': apps_info,
                'server_status': 'running'
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(debug_data, indent=2).encode())
            
        except Exception as e:
            self.send_error(500, f"Debug info failed: {e}")
    
    def handle_refresh_hashes(self):
        """Refresh all app hashes"""
        try:
            updated_count = 0
            errors = []
            
            for app in self.app_manager.get_apps():
                if os.path.exists(app.file_path):
                    try:
                        new_hash = self._calculate_md5_hash(app.file_path)
                        if new_hash and new_hash != app.file_hash:
                            old_hash = app.file_hash
                            app.file_hash = new_hash
                            app.file_size = os.path.getsize(app.file_path)
                            updated_count += 1
                            logger.info(f"Updated hash for {app.name}: {old_hash} -> {new_hash}")
                    except Exception as e:
                        errors.append(f"{app.name}: {str(e)}")
                else:
                    errors.append(f"{app.name}: File not found")
            
            # Save updated hashes
            if updated_count > 0:
                self.app_manager.save_apps()
            
            response_data = {
                'success': True,
                'updated_count': updated_count,
                'total_apps': len(self.app_manager.get_apps()),
                'errors': errors
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data, indent=2).encode())
            
            logger.info(f"Hash refresh completed: {updated_count} apps updated")
            
        except Exception as e:
            self.send_error(500, f"Hash refresh failed: {e}")
    
    def _calculate_md5_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file (consistent method)"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def log_message(self, format, *args):
        """Override to reduce spam"""
        pass

class AppWebServer:
    """Web server for hosting apps"""
    
    def __init__(self, app_manager, auth_system, port=9001):
        self.app_manager = app_manager
        self.auth_system = auth_system
        self.port = port
        self.server = None
        self.server_thread = None
        
    def start(self):
        """Start the web server"""
        try:
            def handler(*args, **kwargs):
                AppDownloadHandler(*args, app_manager=self.app_manager, 
                                 auth_system=self.auth_system, **kwargs)
            
            self.server = HTTPServer(('0.0.0.0', self.port), handler)
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            
            logger.info(f"App web server started on port {self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start web server: {e}")
            return False
    
    def stop(self):
        """Stop the web server"""
        if self.server:
            self.server.shutdown()
            logger.info("App web server stopped")

# ===========================
# 8-BIT CPU EMULATOR
# ===========================

class CPU8BitEmulator:
    """8-bit CPU emulator with assembler"""
    
    def __init__(self):
        self.memory = [0] * 256
        self.registers = {'A': 0, 'B': 0, 'C': 0, 'D': 0}
        self.pc = 0
        self.sp = 255
        self.flags = {'Z': False, 'C': False, 'N': False}
        self.running = False
        self.instructions = {
            'MOV': self.mov, 'ADD': self.add, 'SUB': self.sub,
            'JMP': self.jmp, 'JZ': self.jz, 'JNZ': self.jnz,
            'CMP': self.cmp, 'PUSH': self.push, 'POP': self.pop,
            'HALT': self.halt, 'NOP': self.nop, 'LOAD': self.load,
            'STORE': self.store
        }
    
    def assemble(self, assembly_code):
        """Assemble text to bytecode"""
        lines = assembly_code.strip().split('\n')
        bytecode = []
        labels = {}
        
        # First pass - find labels
        pc = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            if line.endswith(':'):
                labels[line[:-1]] = pc
            else:
                pc += 1
        
        # Second pass - generate bytecode
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';') or line.endswith(':'):
                continue
            
            parts = line.split()
            instruction = {
                'op': parts[0],
                'args': parts[1:] if len(parts) > 1 else []
            }
            
            # Replace labels with addresses
            for i, arg in enumerate(instruction['args']):
                if arg in labels:
                    instruction['args'][i] = str(labels[arg])
            
            bytecode.append(instruction)
        
        return bytecode
    
    def load_program(self, bytecode):
        """Load program into memory"""
        self.pc = 0
        self.running = True
        self.program = bytecode
    
    def step(self):
        """Execute one instruction"""
        if not self.running or self.pc >= len(self.program):
            self.running = False
            return False
        
        instruction = self.program[self.pc]
        op = instruction['op']
        args = instruction['args']
        
        if op in self.instructions:
            self.instructions[op](args)
        else:
            logger.warning(f"Unknown instruction: {op}")
            self.running = False
        
        return self.running
    
    def run(self, max_cycles=1000):
        """Run program until halt or max cycles"""
        cycles = 0
        while self.running and cycles < max_cycles:
            if not self.step():
                break
            cycles += 1
        
        return cycles
    
    # Instruction implementations
    def mov(self, args):
        """MOV reg, value or MOV reg1, reg2"""
        if args[1] in self.registers:
            self.registers[args[0]] = self.registers[args[1]]
        else:
            self.registers[args[0]] = int(args[1])
        self.pc += 1
    
    def add(self, args):
        """ADD reg, value"""
        if args[1] in self.registers:
            value = self.registers[args[1]]
        else:
            value = int(args[1])
        
        result = self.registers[args[0]] + value
        self.flags['C'] = result > 255
        self.registers[args[0]] = result & 0xFF
        self.flags['Z'] = self.registers[args[0]] == 0
        self.pc += 1
    
    def sub(self, args):
        """SUB reg, value"""
        if args[1] in self.registers:
            value = self.registers[args[1]]
        else:
            value = int(args[1])
        
        result = self.registers[args[0]] - value
        self.flags['N'] = result < 0
        self.registers[args[0]] = result & 0xFF
        self.flags['Z'] = self.registers[args[0]] == 0
        self.pc += 1
    
    def cmp(self, args):
        """CMP reg, value"""
        if args[1] in self.registers:
            value = self.registers[args[1]]
        else:
            value = int(args[1])
        
        result = self.registers[args[0]] - value
        self.flags['Z'] = result == 0
        self.flags['N'] = result < 0
        self.pc += 1
    
    def jmp(self, args):
        """JMP address"""
        self.pc = int(args[0])
    
    def jz(self, args):
        """JZ address"""
        if self.flags['Z']:
            self.pc = int(args[0])
        else:
            self.pc += 1
    
    def jnz(self, args):
        """JNZ address"""
        if not self.flags['Z']:
            self.pc = int(args[0])
        else:
            self.pc += 1
    
    def push(self, args):
        """PUSH reg"""
        self.memory[self.sp] = self.registers[args[0]]
        self.sp -= 1
        self.pc += 1
    
    def pop(self, args):
        """POP reg"""
        self.sp += 1
        self.registers[args[0]] = self.memory[self.sp]
        self.pc += 1
    
    def load(self, args):
        """LOAD reg, address"""
        address = int(args[1])
        self.registers[args[0]] = self.memory[address]
        self.pc += 1
    
    def store(self, args):
        """STORE reg, address"""
        address = int(args[1])
        self.memory[address] = self.registers[args[0]]
        self.pc += 1
    
    def halt(self, args):
        """HALT"""
        self.running = False
    
    def nop(self, args):
        """NOP"""
        self.pc += 1
    
    def get_state(self):
        """Get current CPU state"""
        return {
            'registers': self.registers.copy(),
            'pc': self.pc,
            'sp': self.sp,
            'flags': self.flags.copy(),
            'running': self.running
        }

# ===========================
# ENHANCED APP MANAGER
# ===========================

class EnhancedAppManager:
    """Enhanced app manager with expansion support and usage tracking"""
    
    def __init__(self, data_dir: str = "monsterapps_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.registry_file = self.data_dir / "apps.json"
        self.usage_db = self.data_dir / "usage.db"
        self.upload_dir = self.data_dir / CONFIG['UPLOAD_PATH']
        self.apps_dir = self.data_dir / CONFIG['APPS_DIR']
        self.expansions_dir = self.data_dir / CONFIG['EXPANSIONS_DIR']
        self.backups_dir = self.data_dir / CONFIG['BACKUPS_DIR']
        
        # Create directories
        for directory in [self.upload_dir, self.apps_dir, self.expansions_dir, self.backups_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        self.apps: Dict[str, AppInfo] = {}
        self.init_usage_database()
        self.load_apps()
        
        try:
            self.validate_and_fix_hashes()
        except Exception as e:
            logger.warning(f"Hash validation warning: {e}")
    
    def init_usage_database(self):
        """Initialize SQLite database for usage tracking"""
        try:
            conn = sqlite3.connect(self.usage_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS app_usage (
                    app_id TEXT PRIMARY KEY,
                    total_usage_time REAL DEFAULT 0,
                    launch_count INTEGER DEFAULT 0,
                    last_used REAL DEFAULT 0,
                    badges TEXT DEFAULT "[]"
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usage_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id TEXT,
                    start_time REAL,
                    end_time REAL,
                    duration REAL,
                    FOREIGN KEY (app_id) REFERENCES app_usage (app_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Usage database initialized")
            
        except Exception as e:
            logger.error(f"Usage database initialization failed: {e}")
    
    def load_apps(self):
        """Load apps from registry file with error handling"""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r') as f:
                    data = json.load(f)
                    
                for app_id, app_data in data.items():
                    try:
                        app = AppInfo.from_dict(app_data)
                        self.apps[app.app_id] = app
                    except Exception as e:
                        logger.error(f"Error loading app {app_id}: {e}")
                        continue
                        
                logger.info(f"Loaded {len(self.apps)} apps successfully")
                        
            except Exception as e:
                logger.error(f"Error loading apps registry: {e}")
                try:
                    backup_file = self.registry_file.with_suffix('.json.backup')
                    shutil.copy2(self.registry_file, backup_file)
                    logger.info(f"Corrupted registry backed up to {backup_file}")
                except:
                    pass
    
    def validate_and_fix_hashes(self):
        """Validate and fix app hashes after loading"""
        if not self.apps:
            return
        
        logger.info("Validating app file hashes...")
        updated_count = 0
        
        for app_id, app in self.apps.items():
            if not os.path.exists(app.file_path):
                logger.warning(f"File not found for {app.name}: {app.file_path}")
                continue
            
            try:
                current_hash = self._calculate_hash(app.file_path)
                current_size = os.path.getsize(app.file_path)
                
                if current_hash != app.file_hash or current_size != app.file_size:
                    logger.info(f"Updating hash for {app.name}")
                    app.file_hash = current_hash
                    app.file_size = current_size
                    updated_count += 1
                    
            except Exception as e:
                logger.error(f"Error validating {app.name}: {e}")
        
        if updated_count > 0:
            logger.info(f"Updated {updated_count} app hashes")
            self.save_apps()
        else:
            logger.info("All app hashes are up to date")
    
    def save_apps(self):
        """Save apps to registry file"""
        try:
            with open(self.registry_file, 'w') as f:
                json.dump({aid: app.to_dict() for aid, app in self.apps.items()}, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving apps: {e}")
    
    def add_app(self, file_path: str, name: str = None, category: str = "Utilities", 
                company: str = "Unknown", is_expansion: bool = False) -> bool:
        """Add new app with enhanced metadata"""
        try:
            if not os.path.exists(file_path):
                return False
            
            file_size = os.path.getsize(file_path)
            file_hash = self._calculate_hash(file_path)
            app_token = secrets.token_hex(16)
            
            app = AppInfo(
                app_id=str(uuid.uuid4()),
                name=name or Path(file_path).stem,
                version="1.0.0",
                description=f"Added from {file_path}",
                category=category,
                developer="Local User",
                company=company,
                file_path=file_path,
                file_size=file_size,
                file_hash=file_hash,
                app_token=app_token,
                is_expansion=is_expansion
            )
            
            self.apps[app.app_id] = app
            self.save_apps()
            
            target_dir = self.expansions_dir if is_expansion else self.apps_dir
            self._prepare_for_hosting(app, target_dir)
            
            self._init_app_usage(app.app_id)
            
            logger.info(f"Added app: {app.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding app: {e}")
            return False
    
    def _prepare_for_hosting(self, app: AppInfo, target_dir: Path):
        """Prepare app for network hosting"""
        try:
            file_ext = Path(app.file_path).suffix
            hosted_filename = f"{app.app_token}{file_ext}"
            hosted_path = target_dir / hosted_filename
            
            shutil.copy2(app.file_path, hosted_path)
            
            app.file_path = str(hosted_path)
            app.uploaded = True
            self.save_apps()
            
        except Exception as e:
            logger.error(f"Hosting preparation failed: {e}")
    
    def launch_app(self, app_id: str, callback=None) -> bool:
        """Launch app and track usage"""
        if app_id not in self.apps:
            return False
        
        app = self.apps[app_id]
        
        if app.is_expansion:
            return self._launch_expansion(app, callback)
        
        try:
            start_time = time.time()
            self._record_launch(app_id)
            
            if app.file_path.endswith('.py'):
                subprocess.Popen([sys.executable, app.file_path])
            elif app.file_path.endswith('.exe'):
                subprocess.Popen([app.file_path])
            else:
                if sys.platform == "win32":
                    os.startfile(app.file_path)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", app.file_path])
                else:
                    subprocess.Popen(["xdg-open", app.file_path])
            
            if callback:
                threading.Thread(target=self._track_usage_session, 
                               args=(app_id, start_time, callback), daemon=True).start()
            
            logger.info(f"Launched app: {app.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to launch app: {e}")
            return False
    
    def _launch_expansion(self, app: AppInfo, callback=None) -> bool:
        """Launch expansion with backup prompt"""
        result = messagebox.askyesno(
            "Expansion Installation",
            f"'{app.name}' is an expansion that may modify the client.\n\n"
            "Would you like to create a backup before proceeding?\n"
            "This allows you to restore the client if issues occur."
        )
        
        if result:
            backup_created = self._create_client_backup()
            if not backup_created:
                messagebox.showerror("Backup Failed", "Could not create backup. Installation cancelled.")
                return False
        
        try:
            self._record_launch(app.app_id)
            
            if app.file_path.endswith('.py'):
                subprocess.Popen([sys.executable, app.file_path, '--expansion-mode'])
            else:
                subprocess.Popen([app.file_path])
            
            logger.info(f"Launched expansion: {app.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to launch expansion: {e}")
            return False
    
    def _create_client_backup(self) -> bool:
        """Create backup of current client"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"client_backup_{timestamp}"
            backup_path = self.backups_dir / backup_name
            
            shutil.copytree('.', backup_path, ignore=shutil.ignore_patterns('*.pyc', '__pycache__'))
            
            logger.info(f"Client backup created: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return False
    
    @safe_thread_wrapper
    def _track_usage_session(self, app_id: str, start_time: float, callback):
        """Track app usage session"""
        import time
        time.sleep(5)  # Simulate 5 seconds of usage
        
        end_time = time.time()
        duration = end_time - start_time
        
        try:
            conn = sqlite3.connect(self.usage_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO usage_sessions (app_id, start_time, end_time, duration)
                VALUES (?, ?, ?, ?)
            ''', (app_id, start_time, end_time, duration))
            
            cursor.execute('''
                UPDATE app_usage 
                SET total_usage_time = total_usage_time + ?, last_used = ?
                WHERE app_id = ?
            ''', (duration, end_time, app_id))
            
            conn.commit()
            conn.close()
            
            if app_id in self.apps:
                self.apps[app_id].usage_time += duration
                self.apps[app_id].last_used = end_time
                self._update_badges(app_id)
            
            if callback:
                callback(app_id, duration)
                
        except Exception as e:
            logger.error(f"Usage tracking error: {e}")
    
    def _record_launch(self, app_id: str):
        """Record app launch"""
        try:
            conn = sqlite3.connect(self.usage_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE app_usage 
                SET launch_count = launch_count + 1, last_used = ?
                WHERE app_id = ?
            ''', (time.time(), app_id))
            
            conn.commit()
            conn.close()
            
            if app_id in self.apps:
                self.apps[app_id].launch_count += 1
                
        except Exception as e:
            logger.error(f"Launch recording error: {e}")
    
    def _init_app_usage(self, app_id: str):
        """Initialize usage tracking for new app"""
        try:
            conn = sqlite3.connect(self.usage_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO app_usage (app_id) VALUES (?)
            ''', (app_id,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Usage initialization error: {e}")
    
    def _update_badges(self, app_id: str):
        """Update achievement badges for app"""
        if app_id not in self.apps:
            return
        
        app = self.apps[app_id]
        badges = set(app.badges)
        
        if app.launch_count >= 10:
            badges.add("🎯 Frequent User")
        if app.usage_time >= 3600:
            badges.add("⏰ Time Master")
        if app.usage_time >= 86400:
            badges.add("🏆 Power User")
        if app.downloads >= 100:
            badges.add("📈 Popular")
        if app.is_expansion:
            badges.add("🔧 Expansion")
        
        app.badges = list(badges)
        self.save_apps()
    
    def get_app_stats(self, app_id: str) -> Dict:
        """Get comprehensive app statistics"""
        if app_id not in self.apps:
            return {}
        
        app = self.apps[app_id]
        
        try:
            conn = sqlite3.connect(self.usage_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT total_usage_time, launch_count, last_used 
                FROM app_usage WHERE app_id = ?
            ''', (app_id,))
            
            result = cursor.fetchone()
            if result:
                total_time, launches, last_used = result
            else:
                total_time, launches, last_used = 0, 0, 0
            
            cursor.execute('''
                SELECT COUNT(*) FROM usage_sessions WHERE app_id = ?
            ''', (app_id,))
            
            session_count = cursor.fetchone()[0]
            conn.close()
            
        except Exception as e:
            logger.error(f"Stats retrieval error: {e}")
            total_time, launches, last_used, session_count = 0, 0, 0, 0
        
        return {
            'name': app.name,
            'version': app.version,
            'developer': app.developer,
            'company': app.company,
            'category': app.category,
            'file_size': app.file_size,
            'total_usage_time': total_time,
            'launch_count': launches,
            'session_count': session_count,
            'last_used': last_used,
            'downloads': app.downloads,
            'rating': app.rating,
            'badges': app.badges,
            'is_expansion': app.is_expansion,
            'created_at': app.created_at
        }
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file (consistent method)"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def get_apps(self) -> List[AppInfo]:
        """Get all apps"""
        return list(self.apps.values())
    
    def remove_app(self, app_id: str) -> bool:
        """Remove app from registry"""
        if app_id in self.apps:
            del self.apps[app_id]
            self.save_apps()
            return True
        return False

# ===========================
# SIMPLIFIED NODE DISCOVERY
# ===========================

class SimpleNodeDiscovery:
    """Simplified node discovery with better error handling"""
    
    def __init__(self, auth_system):
        self.auth = auth_system
        self.db = SimpleDatabase()
        self.fallback_nodes = {}
        self.fallback_messages = []
        self.last_cleanup = time.time()
        
    def register_node(self, ip_address: str, port: int, webserver_port: int = 9001) -> bool:
        """Register node in database or fallback"""
        try:
            success = self.db.execute("""
                INSERT INTO mesh_nodes (node_id, username, ip_address, port, webserver_port, 
                                      public_key, client_token, apps_count, chat_enabled, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    ip_address = VALUES(ip_address),
                    port = VALUES(port),
                    webserver_port = VALUES(webserver_port),
                    last_heartbeat = CURRENT_TIMESTAMP,
                    status = 'online'
            """, (
                self.auth.node_id, self.auth.username, ip_address, port, webserver_port,
                base64.b64encode(self.auth.public_key_bytes).decode() if self.auth.public_key_bytes else '',
                self.auth.client_token, 0, True, 'online'
            ))
            
            if success:
                logger.info("Node registered in database")
                return True
            
        except Exception as e:
            logger.error(f"Node registration error: {e}")
        
        # Fallback
        self.fallback_nodes[self.auth.node_id] = {
            'node_id': self.auth.node_id,
            'username': self.auth.username,
            'ip_address': ip_address,
            'port': port,
            'webserver_port': webserver_port,
            'last_seen': time.time(),
            'status': 'online'
        }
        logger.info("Node registered in fallback mode")
        return True
    
    def get_online_nodes(self) -> List[NodeInfo]:
        """Get online nodes with simplified error handling"""
        try:
            rows = self.db.query("""
                SELECT node_id, username, ip_address, port, apps_count, 
                       UNIX_TIMESTAMP(last_heartbeat) as last_seen, status,
                       COALESCE(webserver_port, 9001) as webserver_port,
                       COALESCE(public_key, '') as public_key,
                       COALESCE(chat_enabled, TRUE) as chat_enabled
                FROM mesh_nodes 
                WHERE status IN ('online', 'busy') 
                AND last_heartbeat > NOW() - INTERVAL %s SECOND
                AND node_id != %s
                ORDER BY last_heartbeat DESC
                LIMIT %s
            """, (CONFIG['NODE_TIMEOUT'], self.auth.node_id, CONFIG['MAX_PEERS']))
            
            if rows is not None:
                nodes = []
                for row in rows:
                    try:
                        (node_id, username, ip, port, apps_count, last_seen, status,
                         web_port, pub_key, chat_enabled) = row
                        
                        public_key_bytes = None
                        if pub_key:
                            try:
                                public_key_bytes = base64.b64decode(pub_key)
                            except:
                                pass
                        
                        nodes.append(NodeInfo(
                            node_id=node_id,
                            username=username,
                            ip_address=ip,
                            port=port,
                            public_key=public_key_bytes,
                            last_seen=last_seen,
                            apps_count=apps_count,
                            status=status,
                            chat_enabled=bool(chat_enabled),
                            connected=True
                        ))
                    except Exception as e:
                        logger.warning(f"Error processing node row: {e}")
                        continue
                
                return nodes
            
        except Exception as e:
            logger.error(f"Error getting online nodes: {e}")
        
        # Fallback
        nodes = []
        current_time = time.time()
        
        for node_data in self.fallback_nodes.values():
            if node_data['node_id'] != self.auth.node_id:
                if current_time - node_data['last_seen'] < CONFIG['NODE_TIMEOUT']:
                    nodes.append(NodeInfo(
                        node_id=node_data['node_id'],
                        username=node_data['username'],
                        ip_address=node_data['ip_address'],
                        port=node_data['port'],
                        last_seen=node_data['last_seen'],
                        apps_count=0,
                        status=node_data['status'],
                        chat_enabled=True,
                        connected=True
                    ))
        
        return nodes
    
    def update_heartbeat(self, apps_count: int = 0) -> bool:
        """Update heartbeat with error handling"""
        try:
            success = self.db.execute("""
                UPDATE mesh_nodes 
                SET last_heartbeat = CURRENT_TIMESTAMP, apps_count = %s, status = 'online'
                WHERE node_id = %s
            """, (apps_count, self.auth.node_id))
            
            if success:
                return True
            
        except Exception as e:
            logger.error(f"Heartbeat update error: {e}")
        
        # Fallback
        if self.auth.node_id in self.fallback_nodes:
            self.fallback_nodes[self.auth.node_id]['last_seen'] = time.time()
            self.fallback_nodes[self.auth.node_id]['apps_count'] = apps_count
        
        return True
    
    def send_chat_message(self, message: str, receiver_node_id: str = None, 
                         message_type: str = 'direct') -> bool:
        """Send chat message with error handling"""
        try:
            success = self.db.execute("""
                INSERT INTO chat_messages (sender_node_id, receiver_node_id, message_type, content)
                VALUES (%s, %s, %s, %s)
            """, (self.auth.node_id, receiver_node_id, message_type, message))
            
            if success:
                return True
            
        except Exception as e:
            logger.error(f"Chat message send error: {e}")
        
        # Fallback
        message_data = {
            'id': len(self.fallback_messages) + 1,
            'sender_id': self.auth.node_id,
            'username': self.auth.username,
            'receiver_id': receiver_node_id,
            'type': message_type,
            'content': message,
            'timestamp': datetime.now(),
            'encrypted': False
        }
        self.fallback_messages.append(message_data)
        logger.info(f"Chat message stored in fallback mode")
        return True
    
    def get_chat_messages(self, since_timestamp: str = None) -> List[Dict]:
        """Get chat messages with error handling"""
        try:
            query = """
                SELECT cm.id, cm.sender_node_id, mn.username, cm.message_type, 
                       cm.content, cm.timestamp, cm.encrypted
                FROM chat_messages cm
                JOIN mesh_nodes mn ON cm.sender_node_id = mn.node_id
                WHERE (cm.receiver_node_id = %s OR cm.message_type = 'broadcast')
                AND cm.sender_node_id != %s
            """
            
            params = [self.auth.node_id, self.auth.node_id]
            
            if since_timestamp:
                query += " AND cm.timestamp > %s"
                params.append(since_timestamp)
            
            query += " ORDER BY cm.timestamp ASC LIMIT 50"
            
            rows = self.db.query(query, tuple(params))
            
            if rows is not None:
                messages = []
                for row in rows:
                    try:
                        msg_id, sender_id, username, msg_type, content, timestamp, encrypted = row
                        messages.append({
                            'id': msg_id,
                            'sender_id': sender_id,
                            'username': username,
                            'type': msg_type,
                            'content': content,
                            'timestamp': timestamp,
                            'encrypted': encrypted
                        })
                    except Exception as e:
                        logger.warning(f"Error processing message row: {e}")
                        continue
                
                return messages
            
        except Exception as e:
            logger.error(f"Error getting chat messages: {e}")
        
        # Fallback
        messages = []
        since_time = datetime.min
        
        if since_timestamp:
            try:
                if isinstance(since_timestamp, str):
                    since_time = datetime.strptime(since_timestamp, '%Y-%m-%d %H:%M:%S')
                else:
                    since_time = since_timestamp
            except:
                since_time = datetime.min
        
        for msg in self.fallback_messages:
            if (msg['receiver_id'] == self.auth.node_id or msg['type'] == 'broadcast') and \
               msg['sender_id'] != self.auth.node_id and \
               msg['timestamp'] > since_time:
                messages.append(msg)
        
        return messages[-50:]
    
    def register_app_availability(self, app: AppInfo, download_url: str) -> bool:
        """Register app availability"""
        try:
            success = self.db.execute("""
                INSERT INTO app_availability (node_id, app_token, app_name, app_category, 
                                            file_size, file_hash, download_url)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    app_name = VALUES(app_name),
                    download_url = VALUES(download_url),
                    last_verified = CURRENT_TIMESTAMP
            """, (
                self.auth.node_id, app.app_token, app.name, app.category,
                app.file_size, app.file_hash, download_url
            ))
            
            return success
            
        except Exception as e:
            logger.error(f"App registration error: {e}")
            return False
    
    def get_available_apps(self) -> List[Dict]:
        """Get available apps"""
        try:
            rows = self.db.query("""
                SELECT aa.node_id, mn.username, mn.status, aa.app_token, aa.app_name, 
                       aa.app_category, aa.file_size, aa.file_hash, aa.download_url,
                       aa.last_verified, aa.status as app_status
                FROM app_availability aa
                JOIN mesh_nodes mn ON aa.node_id = mn.node_id
                WHERE mn.last_heartbeat > NOW() - INTERVAL 300 SECOND
                AND aa.status = 'available'
                ORDER BY aa.app_name, mn.username
            """)
            
            if rows is not None:
                apps = []
                for row in rows:
                    try:
                        (node_id, username, node_status, app_token, app_name, 
                         category, file_size, file_hash, download_url, last_verified, app_status) = row
                        
                        apps.append({
                            'node_id': node_id,
                            'username': username,
                            'node_status': node_status,
                            'app_token': app_token,
                            'app_name': app_name,
                            'category': category,
                            'file_size': file_size,
                            'file_hash': file_hash,
                            'download_url': download_url,
                            'last_verified': last_verified,
                            'app_status': app_status,
                            'available': node_status == 'online'
                        })
                    except Exception as e:
                        logger.warning(f"Error processing app row: {e}")
                        continue
                
                return apps
            
        except Exception as e:
            logger.error(f"Error getting available apps: {e}")
        
        return []
    
    def cleanup_old_data(self):
        """Cleanup old data with better error handling"""
        try:
            current_time = time.time()
            if current_time - self.last_cleanup > 3600:  # Cleanup every hour
                self.db.execute("DELETE FROM chat_messages WHERE timestamp < NOW() - INTERVAL 7 DAY")
                self.db.execute("DELETE FROM mesh_nodes WHERE last_heartbeat < NOW() - INTERVAL 1 HOUR AND status = 'offline'")
                self.db.execute("DELETE FROM app_availability WHERE last_verified < NOW() - INTERVAL 1 DAY AND status = 'unavailable'")
                self.last_cleanup = current_time
                logger.info("Database cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

# ===========================
# ENHANCED AUTHENTICATION
# ===========================

class EnhancedAuth:
    """Enhanced authentication with node registration"""
    
    def __init__(self):
        try:
            self.node_id = f"node_{secrets.token_hex(16)}"
            self.username = f"User_{secrets.token_hex(4)}"
            self.master_key = secrets.token_bytes(32)
            self.session_key = secrets.token_bytes(32)
            self.client_token = secrets.token_hex(32)
            
            if CRYPTO_AVAILABLE:
                self.private_key = x25519.X25519PrivateKey.generate()
                self.public_key = self.private_key.public_key()
                self.public_key_bytes = self.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                self.private_key = None
                self.public_key = None
                self.public_key_bytes = b''
            
            self.registration_token = self._generate_registration_token()
            logger.info(f"Auth system initialized for node: {self.node_id}")
            
        except Exception as e:
            logger.error(f"Auth initialization error: {e}")
            raise
    
    def _generate_registration_token(self) -> str:
        """Generate cryptographically secure registration token"""
        try:
            timestamp = str(int(time.time()))
            data = f"{self.node_id}:{self.username}:{timestamp}"
            signature = hmac.new(self.master_key, data.encode(), hashlib.sha256).hexdigest()
            
            token_data = {
                'node_id': self.node_id,
                'username': self.username,
                'timestamp': timestamp,
                'signature': signature,
                'public_key': base64.b64encode(self.public_key_bytes).decode() if self.public_key_bytes else '',
                'client_token': self.client_token
            }
            
            return base64.b64encode(json.dumps(token_data).encode()).decode()
        except Exception as e:
            logger.error(f"Token generation error: {e}")
            return ""
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for portal requests"""
        try:
            timestamp = str(int(time.time()))
            message = f"{self.node_id}:{timestamp}"
            signature = hmac.new(self.session_key, message.encode(), hashlib.sha256).hexdigest()
            
            return {
                'X-Client-Token': self.registration_token,
                'X-Node-ID': self.node_id,
                'X-Username': self.username,
                'X-Timestamp': timestamp,
                'X-Signature': signature,
                'X-Public-Key': base64.b64encode(self.public_key_bytes).decode() if self.public_key_bytes else '',
                'User-Agent': 'MonsterApps-Enhanced/2024.1'
            }
        except Exception as e:
            logger.error(f"Auth headers error: {e}")
            return {}
    
    @safe_thread_wrapper
    def register_with_portal(self) -> bool:
        """Register node with portal for live status"""
        if not HTTP_AVAILABLE or not CONFIG['ENABLE_PORTAL']:
            return False
        
        try:
            portal_url = CONFIG['PORTAL_URL'].replace('appstore.php', 'api/register_node.php')
            
            data = {
                'node_id': self.node_id,
                'username': self.username,
                'client_token': self.client_token,
                'timestamp': time.time(),
                'signature': hmac.new(self.master_key, 
                                    f"{self.node_id}:{self.client_token}".encode(), 
                                    hashlib.sha256).hexdigest()
            }
            
            response = requests.post(portal_url, json=data, timeout=5, verify=False)
            if response.status_code == 200:
                logger.info("Portal registration successful")
                return True
            else:
                logger.warning(f"Portal registration failed: HTTP {response.status_code}")
                return False
            
        except requests.exceptions.Timeout:
            logger.warning("Portal registration timeout")
            return False
        except requests.exceptions.ConnectionError:
            logger.warning("Portal registration failed: Cannot connect to server")
            return False
        except Exception as e:
            logger.error(f"Portal registration failed: {e}")
            return False

# ===========================
# ENHANCED GUI
# ===========================

class EnhancedMonsterAppsGUI:
    """Enhanced GUI with better error handling and all functionality"""
    
    def __init__(self):
        try:
            self.root = tk.Tk()
            self.root.title("MonsterApps Enhanced - P2P App Distribution")
            self.root.geometry("1400x900")
            self.root.configure(bg='#0f172a')
            
            # Enhanced styling
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#4CAF50')
            style.configure('Expansion.TButton', background='#FF6B35', foreground='white')
            style.configure('App.TButton', background='#4CAF50', foreground='white')
            
            # Initialize components with error handling
            self.auth = EnhancedAuth()
            self.app_manager = EnhancedAppManager()
            self.discovery = SimpleNodeDiscovery(self.auth)
            self.web_server = AppWebServer(self.app_manager, self.auth)
            
            # State
            self.connected_nodes = {}
            self.chat_messages = []
            self.last_chat_check = time.time()
            self.selected_app = None
            self.service_errors = []
            
            # Setup GUI with error handling
            self.setup_gui()
            self.setup_menu()
            
            # Start services in background
            threading.Thread(target=self.start_services_safe, daemon=True).start()
            
            # Schedule periodic updates
            self.schedule_updates()
            
            logger.info("GUI initialized successfully")
            
        except Exception as e:
            logger.error(f"GUI initialization error: {e}")
            messagebox.showerror("Startup Error", f"Failed to initialize application: {e}")
            sys.exit(1)
    
    def setup_gui(self):
        """Setup enhanced GUI with multiple panels"""
        try:
            # Main container with notebook
            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Apps Panel
            apps_frame = tk.Frame(self.notebook, bg='#1e293b')
            self.notebook.add(apps_frame, text="📱 My Apps")
            self.setup_apps_panel(apps_frame)
            
            # Store Panel
            store_frame = tk.Frame(self.notebook, bg='#1e293b')
            self.notebook.add(store_frame, text="🛒 App Store")
            self.setup_store_panel(store_frame)
            
            # Network Panel
            network_frame = tk.Frame(self.notebook, bg='#1e293b')
            self.notebook.add(network_frame, text="🌐 Network")
            self.setup_network_panel(network_frame)
            
            # Chat Panel
            chat_frame = tk.Frame(self.notebook, bg='#1e293b')
            self.notebook.add(chat_frame, text="💬 Chat")
            self.setup_chat_panel(chat_frame)
            
            # CPU Emulator Panel
            cpu_frame = tk.Frame(self.notebook, bg='#1e293b')
            self.notebook.add(cpu_frame, text="🖥️ 8-Bit CPU")
            self.setup_cpu_panel(cpu_frame)
            
            # Status bar
            self.setup_status_bar()
            
        except Exception as e:
            logger.error(f"GUI setup error: {e}")
            raise
    
    def setup_apps_panel(self, parent):
        """Setup enhanced apps panel with detailed cards"""
        try:
            # Header
            header = tk.Frame(parent, bg='#1e293b')
            header.pack(fill='x', padx=10, pady=5)
            
            tk.Label(header, text="📱 My Applications", font=('Arial', 20, 'bold'),
                    fg='#4CAF50', bg='#1e293b').pack(side='left')
            
            # Controls
            controls = tk.Frame(header, bg='#1e293b')
            controls.pack(side='right')
            
            tk.Button(controls, text="➕ Add App", command=self.add_app_dialog,
                     bg='#4CAF50', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=2)
            
            tk.Button(controls, text="🔧 Add Expansion", command=self.add_expansion_dialog,
                     bg='#FF6B35', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=2)
            
            tk.Button(controls, text="🔄 Refresh", command=self.refresh_apps,
                     bg='#2196F3', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=2)
            
            # Apps container with scrollable frame
            apps_container = tk.Frame(parent, bg='#1e293b')
            apps_container.pack(fill='both', expand=True, padx=10, pady=5)
            
            # Canvas for scrolling
            canvas = tk.Canvas(apps_container, bg='#1e293b', highlightthickness=0)
            scrollbar = ttk.Scrollbar(apps_container, orient='vertical', command=canvas.yview)
            self.apps_scroll_frame = tk.Frame(canvas, bg='#1e293b')
            
            self.apps_scroll_frame.bind(
                '<Configure>',
                lambda e: canvas.configure(scrollregion=canvas.bbox('all'))
            )
            
            canvas.create_window((0, 0), window=self.apps_scroll_frame, anchor='nw')
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side='left', fill='both', expand=True)
            scrollbar.pack(side='right', fill='y')
            
            self.apps_canvas = canvas
            
            # Mouse wheel scrolling
            def _on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            canvas.bind("<MouseWheel>", _on_mousewheel)
            
        except Exception as e:
            logger.error(f"Apps panel setup error: {e}")
    
    def setup_store_panel(self, parent):
        """Setup app store panel with availability status"""
        try:
            # Header
            header = tk.Frame(parent, bg='#1e293b')
            header.pack(fill='x', padx=10, pady=5)
            
            tk.Label(header, text="🛒 MonsterApps Store", font=('Arial', 20, 'bold'),
                    fg='#4CAF50', bg='#1e293b').pack(side='left')
            
            # Refresh button
            tk.Button(header, text="🔄 Refresh Store", command=self.refresh_store,
                     bg='#2196F3', fg='white', font=('Arial', 10, 'bold')).pack(side='right')
            
            # Search bar
            search_frame = tk.Frame(parent, bg='#1e293b')
            search_frame.pack(fill='x', padx=10, pady=5)
            
            tk.Label(search_frame, text="Search:", fg='white', bg='#1e293b').pack(side='left')
            self.search_var = tk.StringVar()
            search_entry = tk.Entry(search_frame, textvariable=self.search_var, font=('Arial', 11))
            search_entry.pack(side='left', fill='x', expand=True, padx=5)
            search_entry.bind('<KeyRelease>', self.on_search_change)
            
            # Category filter
            tk.Label(search_frame, text="Category:", fg='white', bg='#1e293b').pack(side='left', padx=(10,0))
            self.category_var = tk.StringVar(value="All")
            category_combo = ttk.Combobox(search_frame, textvariable=self.category_var, width=15)
            category_combo['values'] = ('All', 'Games', 'Utilities', 'Development', 'Graphics', 'Network', 'Business', 'Expansions')
            category_combo.pack(side='left', padx=5)
            category_combo.bind('<<ComboboxSelected>>', self.on_category_change)
            
            # Store items container
            store_container = tk.Frame(parent, bg='#1e293b')
            store_container.pack(fill='both', expand=True, padx=10, pady=5)
            
            # Store canvas for scrolling
            store_canvas = tk.Canvas(store_container, bg='#1e293b', highlightthickness=0)
            store_scrollbar = ttk.Scrollbar(store_container, orient='vertical', command=store_canvas.yview)
            self.store_scroll_frame = tk.Frame(store_canvas, bg='#1e293b')
            
            self.store_scroll_frame.bind(
                '<Configure>',
                lambda e: store_canvas.configure(scrollregion=store_canvas.bbox('all'))
            )
            
            store_canvas.create_window((0, 0), window=self.store_scroll_frame, anchor='nw')
            store_canvas.configure(yscrollcommand=store_scrollbar.set)
            
            store_canvas.pack(side='left', fill='both', expand=True)
            store_scrollbar.pack(side='right', fill='y')
            
            self.store_canvas = store_canvas
            
            # Mouse wheel scrolling for store
            def _on_store_mousewheel(event):
                store_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            store_canvas.bind("<MouseWheel>", _on_store_mousewheel)
            
        except Exception as e:
            logger.error(f"Store panel setup error: {e}")
    
    def setup_network_panel(self, parent):
        """Setup network panel with node status"""
        try:
            # Network status header
            header = tk.Frame(parent, bg='#1e293b')
            header.pack(fill='x', padx=10, pady=5)
            
            tk.Label(header, text="🌐 Network Status", font=('Arial', 20, 'bold'),
                    fg='#4CAF50', bg='#1e293b').pack(side='left')
            
            self.network_status_label = tk.Label(header, text="Initializing...", 
                                               fg='#ffa500', bg='#1e293b')
            self.network_status_label.pack(side='right')
            
            # Node info
            info_frame = tk.LabelFrame(parent, text="Node Information", fg='white', bg='#1e293b')
            info_frame.pack(fill='x', padx=10, pady=5)
            
            node_info = f"""Node ID: {self.auth.node_id}
Username: {self.auth.username}
Web Server: http://localhost:{CONFIG['WEBSERVER_PORT']}
Client Token: {self.auth.client_token[:16]}..."""
            
            tk.Label(info_frame, text=node_info, fg='#cccccc', bg='#1e293b', 
                    justify='left', font=('Consolas', 10)).pack(padx=10, pady=10)
            
            # Connected nodes
            nodes_frame = tk.LabelFrame(parent, text="Connected Nodes", fg='white', bg='#1e293b')
            nodes_frame.pack(fill='both', expand=True, padx=10, pady=5)
            
            # Nodes tree
            columns = ('username', 'status', 'apps', 'chat', 'last_seen')
            self.nodes_tree = ttk.Treeview(nodes_frame, columns=columns, show='tree headings')
            
            self.nodes_tree.heading('#0', text='Node ID')
            self.nodes_tree.heading('username', text='Username')
            self.nodes_tree.heading('status', text='Status')
            self.nodes_tree.heading('apps', text='Apps')
            self.nodes_tree.heading('chat', text='Chat')
            self.nodes_tree.heading('last_seen', text='Last Seen')
            
            nodes_v_scroll = ttk.Scrollbar(nodes_frame, orient='vertical', command=self.nodes_tree.yview)
            self.nodes_tree.configure(yscrollcommand=nodes_v_scroll.set)
            
            self.nodes_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
            nodes_v_scroll.pack(side='right', fill='y', pady=5)
            
            self.nodes_tree.bind('<Double-Button-1>', self.on_node_double_click)
            
        except Exception as e:
            logger.error(f"Network panel setup error: {e}")
    
    def setup_chat_panel(self, parent):
        """Setup enhanced chat panel"""
        try:
            # Chat header
            header = tk.Frame(parent, bg='#1e293b')
            header.pack(fill='x', padx=10, pady=5)
            
            tk.Label(header, text="💬 Network Chat", font=('Arial', 20, 'bold'),
                    fg='#4CAF50', bg='#1e293b').pack(side='left')
            
            self.chat_status_label = tk.Label(header, text="Chat Ready", 
                                            fg='#4CAF50', bg='#1e293b')
            self.chat_status_label.pack(side='right')
            
            # Chat display
            chat_frame = tk.Frame(parent, bg='#1e293b')
            chat_frame.pack(fill='both', expand=True, padx=10, pady=5)
            
            self.chat_text = scrolledtext.ScrolledText(
                chat_frame, 
                wrap=tk.WORD, 
                font=('Consolas', 11),
                bg='#0f172a', 
                fg='#e2e8f0',
                insertbackground='#e2e8f0',
                height=20
            )
            self.chat_text.pack(fill='both', expand=True, pady=(0, 5))
            self.chat_text.config(state='disabled')
            
            # Message input
            input_frame = tk.Frame(parent, bg='#1e293b')
            input_frame.pack(fill='x', padx=10, pady=5)
            
            # Target selection
            target_frame = tk.Frame(input_frame, bg='#1e293b')
            target_frame.pack(fill='x', pady=(0, 5))
            
            tk.Label(target_frame, text="To:", fg='white', bg='#1e293b').pack(side='left')
            self.chat_target_var = tk.StringVar(value="Broadcast")
            self.chat_target_combo = ttk.Combobox(target_frame, textvariable=self.chat_target_var, 
                                                width=20, state='readonly')
            self.chat_target_combo['values'] = ('Broadcast',)
            self.chat_target_combo.pack(side='left', padx=5)
            
            # Message entry
            msg_frame = tk.Frame(input_frame, bg='#1e293b')
            msg_frame.pack(fill='x')
            
            self.chat_entry = tk.Entry(msg_frame, font=('Arial', 11), bg='#0f172a', 
                                     fg='#e2e8f0', insertbackground='#e2e8f0')
            self.chat_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
            self.chat_entry.bind('<Return>', self.send_chat_message)
            
            tk.Button(msg_frame, text="Send", command=self.send_chat_message,
                     bg='#4CAF50', fg='white', font=('Arial', 10, 'bold')).pack(side='right')
            
            # Add welcome message
            self.add_chat_message("System", "Welcome to MonsterApps Network Chat! 🚀", "system")
            
        except Exception as e:
            logger.error(f"Chat panel setup error: {e}")
    
    def setup_cpu_panel(self, parent):
        """Setup 8-bit CPU emulator panel"""
        try:
            # CPU header
            header = tk.Frame(parent, bg='#1e293b')
            header.pack(fill='x', padx=10, pady=5)
            
            tk.Label(header, text="🖥️ 8-Bit CPU Emulator", font=('Arial', 20, 'bold'),
                    fg='#4CAF50', bg='#1e293b').pack(side='left')
            
            # CPU controls
            controls = tk.Frame(header, bg='#1e293b')
            controls.pack(side='right')
            
            tk.Button(controls, text="▶️ Run", command=self.run_cpu_program,
                     bg='#4CAF50', fg='white').pack(side='left', padx=2)
            
            tk.Button(controls, text="⏸️ Step", command=self.step_cpu,
                     bg='#FF9800', fg='white').pack(side='left', padx=2)
            
            tk.Button(controls, text="🔄 Reset", command=self.reset_cpu,
                     bg='#f44336', fg='white').pack(side='left', padx=2)
            
            # Main CPU layout
            cpu_main = tk.Frame(parent, bg='#1e293b')
            cpu_main.pack(fill='both', expand=True, padx=10, pady=5)
            
            # Left panel - Code editor
            left_panel = tk.LabelFrame(cpu_main, text="Assembly Code", fg='white', bg='#1e293b')
            left_panel.pack(side='left', fill='both', expand=True, padx=(0, 5))
            
            self.cpu_code_text = scrolledtext.ScrolledText(
                left_panel,
                wrap=tk.NONE,
                font=('Consolas', 10),
                bg='#0f172a',
                fg='#e2e8f0',
                insertbackground='#e2e8f0',
                width=40
            )
            self.cpu_code_text.pack(fill='both', expand=True, padx=5, pady=5)
            
            # Sample program
            sample_program = """; Sample 8-bit CPU Program
; Add two numbers and store result

MOV A, 10    ; Load 10 into register A
MOV B, 5     ; Load 5 into register B
ADD A, B     ; Add B to A (result in A)
STORE A, 100 ; Store result at memory address 100
HALT         ; Stop execution

; Try other instructions:
; SUB A, B    ; Subtract
; CMP A, B    ; Compare  
; JZ label    ; Jump if zero
; JNZ label   ; Jump if not zero
; PUSH A      ; Push to stack
; POP A       ; Pop from stack"""
            
            self.cpu_code_text.insert('1.0', sample_program)
            
            # Right panel - CPU state
            right_panel = tk.Frame(cpu_main, bg='#1e293b')
            right_panel.pack(side='right', fill='y', padx=(5, 0))
            
            # Registers
            reg_frame = tk.LabelFrame(right_panel, text="Registers", fg='white', bg='#1e293b', width=200)
            reg_frame.pack(fill='x', pady=(0, 5))
            reg_frame.pack_propagate(False)
            
            self.cpu_reg_labels = {}
            for reg in ['A', 'B', 'C', 'D']:
                frame = tk.Frame(reg_frame, bg='#1e293b')
                frame.pack(fill='x', padx=5, pady=2)
                tk.Label(frame, text=f"{reg}:", fg='white', bg='#1e293b', width=3).pack(side='left')
                label = tk.Label(frame, text="0", fg='#4CAF50', bg='#1e293b', 
                               font=('Consolas', 12, 'bold'))
                label.pack(side='left')
                self.cpu_reg_labels[reg] = label
            
            # CPU state
            state_frame = tk.LabelFrame(right_panel, text="CPU State", fg='white', bg='#1e293b')
            state_frame.pack(fill='x', pady=(0, 5))
            
            self.cpu_state_labels = {}
            for item in ['PC', 'SP']:
                frame = tk.Frame(state_frame, bg='#1e293b')
                frame.pack(fill='x', padx=5, pady=2)
                tk.Label(frame, text=f"{item}:", fg='white', bg='#1e293b', width=3).pack(side='left')
                label = tk.Label(frame, text="0", fg='#FF9800', bg='#1e293b', 
                               font=('Consolas', 12, 'bold'))
                label.pack(side='left')
                self.cpu_state_labels[item] = label
            
            # Flags
            flags_frame = tk.LabelFrame(right_panel, text="Flags", fg='white', bg='#1e293b')
            flags_frame.pack(fill='x', pady=(0, 5))
            
            self.cpu_flag_labels = {}
            for flag in ['Z', 'C', 'N']:
                frame = tk.Frame(flags_frame, bg='#1e293b')
                frame.pack(fill='x', padx=5, pady=2)
                tk.Label(frame, text=f"{flag}:", fg='white', bg='#1e293b', width=3).pack(side='left')
                label = tk.Label(frame, text="0", fg='#f44336', bg='#1e293b', 
                               font=('Consolas', 12, 'bold'))
                label.pack(side='left')
                self.cpu_flag_labels[flag] = label
            
            # Memory view
            mem_frame = tk.LabelFrame(right_panel, text="Memory (0-15)", fg='white', bg='#1e293b')
            mem_frame.pack(fill='both', expand=True)
            
            self.cpu_memory_text = scrolledtext.ScrolledText(
                mem_frame,
                wrap=tk.NONE,
                font=('Consolas', 9),
                bg='#0f172a',
                fg='#e2e8f0',
                height=8,
                width=25
            )
            self.cpu_memory_text.pack(fill='both', expand=True, padx=5, pady=5)
            
            # Initialize CPU
            self.cpu = CPU8BitEmulator()
            self.update_cpu_display()
            
        except Exception as e:
            logger.error(f"CPU panel setup error: {e}")
    
    def setup_status_bar(self):
        """Setup status bar"""
        try:
            status_frame = tk.Frame(self.root, bg='#1e293b', relief='sunken', bd=1)
            status_frame.pack(side='bottom', fill='x')
            
            self.status_label = tk.Label(status_frame, text="Starting services...", 
                                       fg='white', bg='#1e293b', anchor='w')
            self.status_label.pack(side='left', padx=5, pady=2)
            
            # Service indicators
            indicators = tk.Frame(status_frame, bg='#1e293b')
            indicators.pack(side='right', padx=5, pady=2)
            
            self.web_status = tk.Label(indicators, text="Web: ⏳", fg='#ffa500', bg='#1e293b')
            self.web_status.pack(side='left', padx=5)
            
            self.db_status = tk.Label(indicators, text="DB: ⏳", fg='#ffa500', bg='#1e293b')
            self.db_status.pack(side='left', padx=5)
            
            self.chat_indicator = tk.Label(indicators, text="Chat: ⏳", fg='#ffa500', bg='#1e293b')
            self.chat_indicator.pack(side='left', padx=5)
            
        except Exception as e:
            logger.error(f"Status bar setup error: {e}")

    def setup_menu(self):
        """Setup application menu"""
        try:
            menubar = tk.Menu(self.root)
            self.root.config(menu=menubar)
            
            # File menu
            file_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="File", menu=file_menu)
            file_menu.add_command(label="Add App", command=self.add_app_dialog)
            file_menu.add_command(label="Add Expansion", command=self.add_expansion_dialog)
            file_menu.add_separator()
            file_menu.add_command(label="Open Portal", command=self.open_portal)
            file_menu.add_separator()
            file_menu.add_command(label="Exit", command=self.on_closing)
            
            # Network menu
            network_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Network", menu=network_menu)
            network_menu.add_command(label="Refresh Nodes", command=self.refresh_nodes)
            network_menu.add_command(label="Network Status", command=self.show_network_status)
            network_menu.add_command(label="Generate Invite Link", command=self.generate_invite_link)
            
            # Tools menu
            tools_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Tools", menu=tools_menu)
            tools_menu.add_command(label="Client Backup", command=self.create_backup)
            tools_menu.add_command(label="Restore Backup", command=self.restore_backup)
            tools_menu.add_command(label="Clear Chat", command=self.clear_chat)
            
            # Help menu
            help_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Help", menu=help_menu)
            help_menu.add_command(label="About", command=self.show_about)
            help_menu.add_command(label="CPU Instructions", command=self.show_cpu_help)
            
        except Exception as e:
            logger.error(f"Menu setup error: {e}")

    # ===========================
    # SERVICE MANAGEMENT
    # ===========================
    
    @safe_thread_wrapper
    def start_services_safe(self):
        """Start all services with comprehensive error handling"""
        try:
            logger.info("Starting services...")
            
            # Start web server
            if self.web_server.start():
                self.root.after(0, lambda: self.update_service_status("web", "✅", "#4CAF50"))
                self.root.after(0, lambda: self.status_label.config(text="Web server started on port 9001"))
            else:
                self.root.after(0, lambda: self.update_service_status("web", "❌", "#f44336"))
            
            # Register with database/discovery
            local_ip = self._get_local_ip()
            if self.discovery.register_node(local_ip, CONFIG['WEBSERVER_PORT']):
                if self.discovery.db.is_available():
                    self.root.after(0, lambda: self.update_service_status("db", "✅", "#4CAF50"))
                    
                    # Register available apps
                    for app in self.app_manager.get_apps():
                        download_url = f"http://{local_ip}:{CONFIG['WEBSERVER_PORT']}/grab?ack={app.app_token}"
                        self.discovery.register_app_availability(app, download_url)
                        
                else:
                    self.root.after(0, lambda: self.update_service_status("db", "⚠️ Fallback", "#ffa500"))
                    self.root.after(0, lambda: self.status_label.config(text="Database unavailable - using fallback mode"))
            else:
                self.root.after(0, lambda: self.update_service_status("db", "❌", "#f44336"))
            
            # Start chat system
            self.root.after(0, lambda: self.update_service_status("chat", "✅", "#4CAF50"))
            
            # Register with portal
            if self.auth.register_with_portal():
                self.root.after(0, lambda: self.update_portal_status("Connected", "#4CAF50"))
            else:
                self.root.after(0, lambda: self.update_portal_status("Offline", "#f44336"))
            
            # Final status update
            if self.discovery.db.is_available():
                self.root.after(0, lambda: self.status_label.config(text="All services started - Database connected"))
            else:
                self.root.after(0, lambda: self.status_label.config(text="Services started - Running in fallback mode"))
            
            logger.info("All services started successfully")
            
        except Exception as e:
            logger.error(f"Service startup error: {e}")
            self.root.after(0, lambda: self.show_service_error(str(e)))
    
    def _get_local_ip(self) -> str:
        """Get local IP address with error handling"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception as e:
            logger.warning(f"Could not get local IP: {e}")
            return "127.0.0.1"
    
    def update_service_status(self, service: str, text: str, color: str):
        """Update service status in GUI"""
        try:
            if service == "web":
                self.web_status.config(text=f"Web: {text}", fg=color)
            elif service == "db":
                self.db_status.config(text=f"DB: {text}", fg=color)
            elif service == "chat":
                self.chat_indicator.config(text=f"Chat: {text}", fg=color)
        except Exception as e:
            logger.error(f"Service status update error: {e}")
    
    def update_portal_status(self, status: str, color: str):
        """Update portal status"""
        try:
            self.network_status_label.config(text=f"Portal: {status}", fg=color)
        except Exception as e:
            logger.error(f"Portal status update error: {e}")
    
    def show_service_error(self, error: str):
        """Show service error in GUI"""
        try:
            self.status_label.config(text=f"Service error: {error}")
            logger.error(f"Service error displayed: {error}")
        except Exception as e:
            logger.error(f"Error showing service error: {e}")
    
    def schedule_updates(self):
        """Schedule periodic updates with error handling"""
        try:
            self.refresh_nodes_safe()
            self.check_chat_messages_safe()
            self.refresh_apps_safe()
            
            # Update heartbeat
            threading.Thread(target=self.update_heartbeat_safe, daemon=True).start()
            
            # Schedule next update
            self.root.after(5000, self.schedule_updates)
            
        except Exception as e:
            logger.error(f"Update scheduling error: {e}")
            # Continue scheduling even if this update failed
            self.root.after(10000, self.schedule_updates)
    
    @safe_thread_wrapper
    def update_heartbeat_safe(self):
        """Update heartbeat safely"""
        try:
            apps_count = len(self.app_manager.get_apps())
            self.discovery.update_heartbeat(apps_count)
        except Exception as e:
            logger.error(f"Heartbeat update error: {e}")

    # ===========================
    # APP PANEL METHODS
    # ===========================
    
    def create_app_card(self, app: AppInfo, parent_frame):
        """Create enhanced app card with animations and details"""
        try:
            # Main card frame
            card = tk.Frame(parent_frame, bg='#2d3748', relief='raised', bd=2)
            card.pack(fill='x', padx=5, pady=5)
            
            # Header with app name and type
            header = tk.Frame(card, bg='#2d3748')
            header.pack(fill='x', padx=10, pady=(10, 5))
            
            # App icon and name
            name_frame = tk.Frame(header, bg='#2d3748')
            name_frame.pack(side='left', fill='x', expand=True)
            
            # App type indicator
            app_type = "🔧 EXPANSION" if app.is_expansion else "📱 APP"
            type_color = '#FF6B35' if app.is_expansion else '#4CAF50'
            
            tk.Label(name_frame, text=app_type, fg=type_color, bg='#2d3748', 
                    font=('Arial', 8, 'bold')).pack(anchor='w')
            
            tk.Label(name_frame, text=app.name, fg='white', bg='#2d3748',
                    font=('Arial', 14, 'bold')).pack(anchor='w')
            
            tk.Label(name_frame, text=f"v{app.version} by {app.company}", 
                    fg='#a0aec0', bg='#2d3748', font=('Arial', 9)).pack(anchor='w')
            
            # Launch button
            button_color = '#FF6B35' if app.is_expansion else '#4CAF50'
            launch_btn = tk.Button(header, text="▶️ Launch" if not app.is_expansion else "🔧 Install",
                                  bg=button_color, fg='white', font=('Arial', 10, 'bold'),
                                  command=lambda: self.launch_app(app.app_id))
            launch_btn.pack(side='right', padx=(10, 0))
            
            # Stats row
            stats_frame = tk.Frame(card, bg='#2d3748')
            stats_frame.pack(fill='x', padx=10, pady=5)
            
            # Usage stats
            stats = self.app_manager.get_app_stats(app.app_id)
            usage_time = stats.get('total_usage_time', 0)
            launch_count = stats.get('launch_count', 0)
            
            stats_text = f"📊 {launch_count} launches | ⏱️ {self._format_time(usage_time)} | 💾 {self._format_size(app.file_size)}"
            if app.downloads > 0:
                stats_text += f" | ⬇️ {app.downloads} downloads"
            
            tk.Label(stats_frame, text=stats_text, fg='#a0aec0', bg='#2d3748',
                    font=('Arial', 9)).pack(side='left')
            
            # Rating
            if app.rating > 0:
                stars = "⭐" * int(app.rating)
                tk.Label(stats_frame, text=f"{stars} {app.rating:.1f}", 
                        fg='#ffd700', bg='#2d3748').pack(side='right')
            
            # Badges
            if app.badges:
                badges_frame = tk.Frame(card, bg='#2d3748')
                badges_frame.pack(fill='x', padx=10, pady=(0, 5))
                
                for badge in app.badges[:3]:  # Show max 3 badges
                    badge_label = tk.Label(badges_frame, text=badge, fg='#ffd700', bg='#1a202c',
                                         font=('Arial', 8), padx=3, pady=1)
                    badge_label.pack(side='left', padx=(0, 2))
            
            # Description (collapsible)
            if len(app.description) > 50:
                desc_text = app.description[:50] + "..."
            else:
                desc_text = app.description
            
            desc_label = tk.Label(card, text=desc_text, fg='#e2e8f0', bg='#2d3748',
                                font=('Arial', 9), wraplength=400, justify='left')
            desc_label.pack(fill='x', padx=10, pady=(0, 10))
            
            # Context menu
            def show_context_menu(event):
                try:
                    context_menu = tk.Menu(self.root, tearoff=0)
                    context_menu.add_command(label="📝 Edit Details", 
                                           command=lambda: self.edit_app_details(app.app_id))
                    context_menu.add_command(label="📊 View Stats", 
                                           command=lambda: self.show_detailed_stats(app.app_id))
                    context_menu.add_command(label="📤 Share to Network", 
                                           command=lambda: self.share_app_to_network(app.app_id))
                    context_menu.add_command(label="🗑️ Remove", 
                                           command=lambda: self.remove_app(app.app_id))
                    
                    try:
                        context_menu.tk_popup(event.x_root, event.y_root)
                    finally:
                        context_menu.grab_release()
                except Exception as e:
                    logger.error(f"Context menu error: {e}")
            
            card.bind("<Button-3>", show_context_menu)
            
            return card
            
        except Exception as e:
            logger.error(f"App card creation error: {e}")
            return None
    
    def create_store_item(self, app_data, parent_frame):
        """Create store item with availability status"""
        try:
            # Store item frame
            item = tk.Frame(parent_frame, bg='#2d3748', relief='raised', bd=1)
            item.pack(fill='x', padx=5, pady=3)
            
            # Header
            header = tk.Frame(item, bg='#2d3748')
            header.pack(fill='x', padx=10, pady=5)
            
            # App info
            info_frame = tk.Frame(header, bg='#2d3748')
            info_frame.pack(side='left', fill='x', expand=True)
            
            # Availability indicator
            available = app_data.get('available', False)
            status_color = '#4CAF50' if available else '#f44336'
            status_text = "🟢 ONLINE" if available else "🔴 OFFLINE"
            
            tk.Label(info_frame, text=status_text, fg=status_color, bg='#2d3748',
                    font=('Arial', 8, 'bold')).pack(anchor='w')
            
            tk.Label(info_frame, text=app_data['app_name'], fg='white', bg='#2d3748',
                    font=('Arial', 12, 'bold')).pack(anchor='w')
            
            provider_text = f"From: {app_data['username']} | {app_data['category']}"
            tk.Label(info_frame, text=provider_text, fg='#a0aec0', bg='#2d3748',
                    font=('Arial', 9)).pack(anchor='w')
            
            # Download button
            if available:
                download_btn = tk.Button(header, text="⬇️ Download", bg='#4CAF50', fg='white',
                                       font=('Arial', 10, 'bold'),
                                       command=lambda: self.download_app_from_store(app_data))
                download_btn.pack(side='right')
            else:
                tk.Label(header, text="⏳ Offline", fg='#f44336', bg='#2d3748',
                        font=('Arial', 10, 'bold')).pack(side='right')
            
            # Details
            details_frame = tk.Frame(item, bg='#2d3748')
            details_frame.pack(fill='x', padx=10, pady=(0, 5))
            
            size_text = f"💾 {self._format_size(app_data['file_size'])}"
            downloads_text = f"⬇️ {app_data.get('downloads', 0)} downloads"
            
            tk.Label(details_frame, text=f"{size_text} | {downloads_text}", 
                    fg='#a0aec0', bg='#2d3748', font=('Arial', 9)).pack(side='left')
            
            # Last verified
            last_verified = app_data.get('last_verified', 'Unknown')
            tk.Label(details_frame, text=f"Last seen: {last_verified}", 
                    fg='#a0aec0', bg='#2d3748', font=('Arial', 9)).pack(side='right')
                    
        except Exception as e:
            logger.error(f"Store item creation error: {e}")
    
    def refresh_apps_safe(self):
        """Refresh apps display safely"""
        try:
            self.root.after(0, self.refresh_apps)
        except Exception as e:
            logger.error(f"Apps refresh scheduling error: {e}")
    
    def refresh_apps(self):
        """Refresh the apps display"""
        try:
            # Clear existing app cards
            for widget in self.apps_scroll_frame.winfo_children():
                widget.destroy()
            
            # Create new app cards
            apps = self.app_manager.get_apps()
            if not apps:
                tk.Label(self.apps_scroll_frame, text="No apps installed\nClick 'Add App' to get started!",
                        fg='#a0aec0', bg='#1e293b', font=('Arial', 12), justify='center').pack(pady=50)
            else:
                for app in sorted(apps, key=lambda x: (x.is_expansion, x.name)):
                    self.create_app_card(app, self.apps_scroll_frame)
            
            # Update canvas scroll region
            self.apps_scroll_frame.update_idletasks()
            self.apps_canvas.configure(scrollregion=self.apps_canvas.bbox("all"))
            
        except Exception as e:
            logger.error(f"Apps refresh error: {e}")
    
    def refresh_store(self):
        """Refresh the store display"""
        try:
            # Clear existing store items
            for widget in self.store_scroll_frame.winfo_children():
                widget.destroy()
            
            # Show loading message
            loading_label = tk.Label(self.store_scroll_frame, text="🔄 Loading apps from network...",
                                   fg='#ffa500', bg='#1e293b', font=('Arial', 12))
            loading_label.pack(pady=20)
            
            # Fetch apps in background
            threading.Thread(target=self._fetch_store_apps, daemon=True).start()
            
        except Exception as e:
            logger.error(f"Store refresh error: {e}")
    
    @safe_thread_wrapper
    def _fetch_store_apps(self):
        """Fetch apps from network stores"""
        try:
            available_apps = self.discovery.get_available_apps()
            
            # Update GUI in main thread
            self.root.after(0, lambda: self._display_store_apps(available_apps))
            
        except Exception as e:
            logger.error(f"Store fetch error: {e}")
            self.root.after(0, lambda: self._show_store_error(str(e)))
    
    def _display_store_apps(self, apps):
        """Display apps in store"""
        try:
            # Clear loading message
            for widget in self.store_scroll_frame.winfo_children():
                widget.destroy()
            
            if not apps:
                tk.Label(self.store_scroll_frame, text="No apps available in network\nConnect to more nodes to see apps!",
                        fg='#a0aec0', bg='#1e293b', font=('Arial', 12), justify='center').pack(pady=50)
            else:
                # Group by category
                categorized = {}
                for app in apps:
                    category = app['category']
                    if category not in categorized:
                        categorized[category] = []
                    categorized[category].append(app)
                
                # Display by category
                for category, category_apps in categorized.items():
                    # Category header
                    cat_frame = tk.Frame(self.store_scroll_frame, bg='#1e293b')
                    cat_frame.pack(fill='x', padx=5, pady=(10, 5))
                    
                    tk.Label(cat_frame, text=f"📂 {category} ({len(category_apps)} apps)",
                            fg='#4CAF50', bg='#1e293b', font=('Arial', 14, 'bold')).pack(anchor='w')
                    
                    # Apps in category
                    for app in sorted(category_apps, key=lambda x: x['app_name']):
                        if self._should_show_app(app):
                            self.create_store_item(app, self.store_scroll_frame)
            
            # Update canvas scroll region
            self.store_scroll_frame.update_idletasks()
            self.store_canvas.configure(scrollregion=self.store_canvas.bbox("all"))
            
        except Exception as e:
            logger.error(f"Store display error: {e}")
    
    def _should_show_app(self, app):
        """Check if app should be shown based on filters"""
        try:
            # Search filter
            search_term = self.search_var.get().lower()
            if search_term and search_term not in app['app_name'].lower():
                return False
            
            # Category filter
            category_filter = self.category_var.get()
            if category_filter != "All" and category_filter != app['category']:
                return False
            
            return True
        except Exception as e:
            logger.error(f"App filter error: {e}")
            return True
    
    def _show_store_error(self, error):
        """Show store error message"""
        try:
            for widget in self.store_scroll_frame.winfo_children():
                widget.destroy()
            
            tk.Label(self.store_scroll_frame, text=f"❌ Error loading store:\n{error}",
                    fg='#f44336', bg='#1e293b', font=('Arial', 12), justify='center').pack(pady=50)
        except Exception as e:
            logger.error(f"Store error display error: {e}")

    # ===========================
    # EVENT HANDLERS
    # ===========================
    
    def add_app_dialog(self):
        """Show add app dialog"""
        self._show_add_dialog(is_expansion=False)
    
    def add_expansion_dialog(self):
        """Show add expansion dialog"""
        self._show_add_dialog(is_expansion=True)
    
    def _show_add_dialog(self, is_expansion=False):
        """Show app/expansion add dialog"""
        try:
            dialog_title = "Add Expansion" if is_expansion else "Add Application"
            
            file_path = filedialog.askopenfilename(
                title=f"Select {dialog_title}",
                filetypes=[
                    ("Executable files", "*.exe *.app"),
                    ("Python files", "*.py"),
                    ("Java files", "*.jar"),
                    ("All files", "*.*")
                ]
            )
            
            if file_path:
                dialog = tk.Toplevel(self.root)
                dialog.title(dialog_title)
                dialog.geometry("500x400")
                dialog.configure(bg='#1e293b')
                dialog.transient(self.root)
                dialog.grab_set()
                
                # Header
                header_color = '#FF6B35' if is_expansion else '#4CAF50'
                tk.Label(dialog, text=f"{'🔧' if is_expansion else '📱'} {dialog_title}", 
                        font=('Arial', 16, 'bold'), fg=header_color, bg='#1e293b').pack(pady=20)
                
                # Form
                form_frame = tk.Frame(dialog, bg='#1e293b')
                form_frame.pack(fill='both', expand=True, padx=20, pady=10)
                
                # App name
                tk.Label(form_frame, text="Name:", fg='white', bg='#1e293b').pack(anchor='w')
                name_entry = tk.Entry(form_frame, width=50, font=('Arial', 11))
                name_entry.pack(fill='x', pady=(0, 10))
                name_entry.insert(0, Path(file_path).stem)
                
                # Company
                tk.Label(form_frame, text="Company/Developer:", fg='white', bg='#1e293b').pack(anchor='w')
                company_entry = tk.Entry(form_frame, width=50, font=('Arial', 11))
                company_entry.pack(fill='x', pady=(0, 10))
                company_entry.insert(0, "Local Developer")
                
                # Category
                tk.Label(form_frame, text="Category:", fg='white', bg='#1e293b').pack(anchor='w')
                category_var = tk.StringVar(value="Expansions" if is_expansion else "Utilities")
                category_combo = ttk.Combobox(form_frame, textvariable=category_var, width=47)
                if is_expansion:
                    category_combo['values'] = ('Expansions', 'Client Tools', 'Plugins')
                else:
                    category_combo['values'] = ('Games', 'Utilities', 'Development', 'Graphics', 'Network', 'Business')
                category_combo.pack(fill='x', pady=(0, 10))
                
                # Description
                tk.Label(form_frame, text="Description:", fg='white', bg='#1e293b').pack(anchor='w')
                desc_text = scrolledtext.ScrolledText(form_frame, height=6, wrap=tk.WORD)
                desc_text.pack(fill='x', pady=(0, 10))
                desc_text.insert('1.0', f"{'Expansion' if is_expansion else 'Application'} added from {file_path}")
                
                # Warning for expansions
                if is_expansion:
                    warning_frame = tk.Frame(form_frame, bg='#FF6B35', relief='raised', bd=2)
                    warning_frame.pack(fill='x', pady=10)
                    
                    tk.Label(warning_frame, text="⚠️ WARNING: EXPANSION", 
                            font=('Arial', 12, 'bold'), fg='white', bg='#FF6B35').pack(pady=5)
                    tk.Label(warning_frame, text="This will modify the client. A backup will be created automatically.",
                            fg='white', bg='#FF6B35', wraplength=400).pack(pady=(0, 5))
                
                # Buttons
                button_frame = tk.Frame(form_frame, bg='#1e293b')
                button_frame.pack(fill='x', pady=20)
                
                def add_app():
                    try:
                        name = name_entry.get().strip()
                        company = company_entry.get().strip()
                        category = category_var.get()
                        description = desc_text.get('1.0', tk.END).strip()
                        
                        if name:
                            if self.app_manager.add_app(file_path, name, category, company, is_expansion):
                                messagebox.showinfo("Success", f"{dialog_title} added successfully!")
                                dialog.destroy()
                                self.refresh_apps()
                                
                                # Register with network
                                if not is_expansion:
                                    app = next((a for a in self.app_manager.get_apps() if a.name == name), None)
                                    if app:
                                        local_ip = self._get_local_ip()
                                        download_url = f"http://{local_ip}:{CONFIG['WEBSERVER_PORT']}/grab?ack={app.app_token}"
                                        self.discovery.register_app_availability(app, download_url)
                            else:
                                messagebox.showerror("Error", f"Failed to add {dialog_title.lower()}")
                        else:
                            messagebox.showerror("Error", "Name is required")
                    except Exception as e:
                        logger.error(f"Add app error: {e}")
                        messagebox.showerror("Error", f"Failed to add {dialog_title.lower()}: {e}")
                
                button_color = '#FF6B35' if is_expansion else '#4CAF50'
                tk.Button(button_frame, text=f"Add {dialog_title}", command=add_app,
                         bg=button_color, fg='white', font=('Arial', 12, 'bold')).pack(side='left')
                
                tk.Button(button_frame, text="Cancel", command=dialog.destroy,
                         bg='#6c757d', fg='white', font=('Arial', 12)).pack(side='right')
                         
        except Exception as e:
            logger.error(f"Add dialog error: {e}")
            messagebox.showerror("Error", f"Failed to open add dialog: {e}")
    
    def launch_app(self, app_id: str):
        """Launch application"""
        try:
            success = self.app_manager.launch_app(app_id, self.on_app_usage_update)
            if success:
                app = self.app_manager.apps.get(app_id)
                if app:
                    self.status_label.config(text=f"Launched: {app.name}")
            else:
                messagebox.showerror("Launch Error", "Failed to launch application")
        except Exception as e:
            logger.error(f"Launch app error: {e}")
            messagebox.showerror("Launch Error", f"Failed to launch application: {e}")
    
    def on_app_usage_update(self, app_id: str, duration: float):
        """Handle app usage update"""
        try:
            app = self.app_manager.apps.get(app_id)
            if app:
                self.status_label.config(text=f"Session ended: {app.name} ({duration:.1f}s)")
                # Refresh apps to show updated stats
                self.refresh_apps()
        except Exception as e:
            logger.error(f"Usage update error: {e}")

    # ===========================
    # NETWORK METHODS
    # ===========================
    
    @safe_thread_wrapper
    def refresh_nodes_safe(self):
        """Refresh nodes with error handling"""
        try:
            nodes = self.discovery.get_online_nodes()
            self.connected_nodes = {node.node_id: node for node in nodes}
            self.root.after(0, self._update_nodes_display_safe)
            self.root.after(0, self._update_chat_targets_safe)
        except Exception as e:
            logger.error(f"Node refresh error: {e}")
    
    def refresh_nodes(self):
        """Refresh connected nodes display"""
        threading.Thread(target=self.refresh_nodes_safe, daemon=True).start()
    
    def _update_nodes_display_safe(self):
        """Update nodes display with error handling"""
        try:
            # Clear existing
            for item in self.nodes_tree.get_children():
                self.nodes_tree.delete(item)
            
            # Add nodes
            for node in self.connected_nodes.values():
                status_icon = {"online": "🟢", "busy": "🟡", "offline": "🔴"}.get(node.status, "⚪")
                chat_status = "✅" if node.chat_enabled else "❌"
                last_seen = datetime.fromtimestamp(node.last_seen).strftime('%H:%M:%S')
                
                self.nodes_tree.insert('', 'end', node.node_id,
                                     text=node.node_id[:12] + "...",
                                     values=(node.username, f"{status_icon} {node.status.title()}", 
                                            node.apps_count, chat_status, last_seen))
        except Exception as e:
            logger.error(f"Nodes display update error: {e}")
    
    def _update_chat_targets_safe(self):
        """Update chat target dropdown safely"""
        try:
            targets = ['Broadcast']
            for node in self.connected_nodes.values():
                if node.chat_enabled:
                    targets.append(f"{node.username} ({node.node_id[:8]})")
            
            self.chat_target_combo['values'] = targets
        except Exception as e:
            logger.error(f"Chat targets update error: {e}")
    
    def on_node_double_click(self, event):
        """Handle node double-click for direct chat"""
        try:
            selection = self.nodes_tree.selection()
            if selection:
                node_id = selection[0]
                node = self.connected_nodes.get(node_id)
                if node and node.chat_enabled:
                    target_text = f"{node.username} ({node.node_id[:8]})"
                    self.chat_target_var.set(target_text)
                    self.notebook.select(3)  # Switch to chat tab
                    self.chat_entry.focus()
        except Exception as e:
            logger.error(f"Node double-click error: {e}")

    # ===========================
    # CHAT SYSTEM
    # ===========================
    
    @safe_thread_wrapper
    def check_chat_messages_safe(self):
        """Check chat messages with error handling"""
        try:
            since_timestamp = datetime.fromtimestamp(self.last_chat_check).strftime('%Y-%m-%d %H:%M:%S')
            messages = self.discovery.get_chat_messages(since_timestamp)
            
            if messages:
                for msg in messages:
                    self.root.after(0, lambda m=msg: self._display_chat_message_safe(m))
                self.last_chat_check = time.time()
                
        except Exception as e:
            logger.error(f"Chat check error: {e}")
    
    def _display_chat_message_safe(self, message):
        """Display chat message with error handling"""
        try:
            msg_type = message['type']
            sender = message['username']
            content = message['content']
            timestamp = message['timestamp']
            
            if isinstance(timestamp, str):
                timestamp_str = timestamp[:8]  # Extract time part
            else:
                timestamp_str = timestamp.strftime('%H:%M:%S')
            
            if msg_type == 'broadcast':
                self.add_chat_message(f"{sender} (Broadcast)", content, "broadcast", timestamp_str)
            else:
                self.add_chat_message(sender, content, "direct", timestamp_str)
        except Exception as e:
            logger.error(f"Chat display error: {e}")
    
    def send_chat_message(self, event=None):
        """Send chat message"""
        try:
            message = self.chat_entry.get().strip()
            if not message:
                return
            
            target = self.chat_target_var.get()
            
            # Determine message type and target
            if target == "Broadcast":
                message_type = "broadcast"
                target_node_id = None
                display_target = "Broadcast"
            else:
                message_type = "direct"
                # Extract node ID from target string
                target_node_id = target.split('(')[-1].split(')')[0]
                display_target = target.split(' (')[0]
            
            # Send message
            success = self.discovery.send_chat_message(message, target_node_id, message_type)
            
            if success:
                # Display in local chat
                if message_type == "broadcast":
                    self.add_chat_message("You (Broadcast)", message, "sent")
                else:
                    self.add_chat_message(f"You → {display_target}", message, "sent")
                
                self.chat_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Chat Error", "Failed to send message")
                
        except Exception as e:
            logger.error(f"Send chat message error: {e}")
            messagebox.showerror("Chat Error", f"Failed to send message: {e}")
    
    def add_chat_message(self, sender: str, message: str, msg_type: str = "received", timestamp: str = None):
        """Add message to chat display"""
        try:
            if not timestamp:
                timestamp = datetime.now().strftime('%H:%M:%S')
            
            self.chat_text.config(state='normal')
            
            # Color coding
            colors = {
                "system": "#ffa500",
                "broadcast": "#4CAF50", 
                "direct": "#2196F3",
                "sent": "#FF9800",
                "received": "#e2e8f0"
            }
            
            color = colors.get(msg_type, "#e2e8f0")
            
            # Insert message
            self.chat_text.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
            
            # Apply color to last line
            line_start = self.chat_text.index("end-2c linestart")
            line_end = self.chat_text.index("end-2c lineend")
            
            tag_name = f"msg_{msg_type}_{int(time.time())}"
            self.chat_text.tag_add(tag_name, line_start, line_end)
            self.chat_text.tag_config(tag_name, foreground=color)
            
            self.chat_text.config(state='disabled')
            self.chat_text.see(tk.END)
            
        except Exception as e:
            logger.error(f"Add chat message error: {e}")

    # ===========================
    # CPU EMULATOR METHODS
    # ===========================
    
    def run_cpu_program(self):
        """Run CPU program"""
        try:
            code = self.cpu_code_text.get('1.0', tk.END).strip()
            
            # Assemble code
            bytecode = self.cpu.assemble(code)
            
            # Load and run
            self.cpu.load_program(bytecode)
            cycles = self.cpu.run(max_cycles=1000)
            
            self.update_cpu_display()
            self.status_label.config(text=f"CPU program executed ({cycles} cycles)")
            
        except Exception as e:
            logger.error(f"CPU run error: {e}")
            messagebox.showerror("CPU Error", f"Execution failed: {e}")
    
    def step_cpu(self):
        """Step CPU one instruction"""
        try:
            if not hasattr(self.cpu, 'program') or not self.cpu.program:
                code = self.cpu_code_text.get('1.0', tk.END).strip()
                bytecode = self.cpu.assemble(code)
                self.cpu.load_program(bytecode)
            
            if self.cpu.step():
                self.update_cpu_display()
                self.status_label.config(text="CPU stepped one instruction")
            else:
                self.status_label.config(text="CPU execution completed")
                
        except Exception as e:
            logger.error(f"CPU step error: {e}")
            messagebox.showerror("CPU Error", f"Step failed: {e}")
    
    def reset_cpu(self):
        """Reset CPU state"""
        try:
            self.cpu = CPU8BitEmulator()
            self.update_cpu_display()
            self.status_label.config(text="CPU reset")
        except Exception as e:
            logger.error(f"CPU reset error: {e}")
    
    def update_cpu_display(self):
        """Update CPU state display"""
        try:
            state = self.cpu.get_state()
            
            # Update registers
            for reg, value in state['registers'].items():
                self.cpu_reg_labels[reg].config(text=str(value))
            
            # Update CPU state
            self.cpu_state_labels['PC'].config(text=str(state['pc']))
            self.cpu_state_labels['SP'].config(text=str(state['sp']))
            
            # Update flags
            for flag, value in state['flags'].items():
                self.cpu_flag_labels[flag].config(
                    text="1" if value else "0",
                    fg='#4CAF50' if value else '#f44336'
                )
            
            # Update memory view
            self.cpu_memory_text.config(state='normal')
            self.cpu_memory_text.delete('1.0', tk.END)
            
            memory_view = ""
            for i in range(0, 16, 4):
                row = f"{i:02X}: "
                for j in range(4):
                    addr = i + j
                    if addr < len(self.cpu.memory):
                        row += f"{self.cpu.memory[addr]:02X} "
                    else:
                        row += "00 "
                memory_view += row + "\n"
            
            self.cpu_memory_text.insert('1.0', memory_view)
            self.cpu_memory_text.config(state='disabled')
            
        except Exception as e:
            logger.error(f"CPU display update error: {e}")

    # ===========================
    # UTILITY METHODS
    # ===========================
    
    def _format_time(self, seconds: float) -> str:
        """Format time duration"""
        try:
            if seconds < 60:
                return f"{seconds:.0f}s"
            elif seconds < 3600:
                return f"{seconds/60:.1f}m"
            else:
                return f"{seconds/3600:.1f}h"
        except:
            return "0s"
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size"""
        try:
            if size_bytes == 0:
                return "0 B"
            
            size_names = ["B", "KB", "MB", "GB"]
            import math
            i = int(math.floor(math.log(size_bytes, 1024)))
            p = math.pow(1024, i)
            s = round(size_bytes / p, 2)
            return f"{s} {size_names[i]}"
        except:
            return "0 B"
    
    def on_search_change(self, event):
        """Handle search text change"""
        try:
            # Refresh store with filter (debounced)
            if hasattr(self, 'store_scroll_frame'):
                self.root.after(100, self.refresh_store)  # Debounce
        except Exception as e:
            logger.error(f"Search change error: {e}")
    
    def on_category_change(self, event):
        """Handle category filter change"""
        try:
            self.refresh_store()
        except Exception as e:
            logger.error(f"Category change error: {e}")
    
    def download_app_from_store(self, app_data):
        """Download app from store"""
        try:
            download_url = app_data['download_url']
            
            # Download file
            response = requests.get(download_url, timeout=30)
            if response.status_code == 200:
                # Verify hash
                received_hash = hashlib.md5(response.content).hexdigest()
                expected_hash = app_data['file_hash']
                
                if received_hash == expected_hash:
                    # Save file
                    filename = f"{app_data['app_name']}.exe"
                    file_path = self.app_manager.apps_dir / filename
                    
                    with open(file_path, 'wb') as f:
                        f.write(response.content)
                    
                    # Add to local apps
                    self.app_manager.add_app(str(file_path), app_data['app_name'], app_data['category'])
                    
                    messagebox.showinfo("Success", f"Downloaded: {app_data['app_name']}")
                    self.refresh_apps()
                else:
                    messagebox.showerror("Error", "File verification failed - corrupt download")
            else:
                messagebox.showerror("Error", f"Download failed: HTTP {response.status_code}")
                
        except Exception as e:
            logger.error(f"Download error: {e}")
            messagebox.showerror("Download Error", f"Failed to download: {e}")
    
    def open_portal(self):
        """Open web portal"""
        try:
            portal_url = CONFIG['PORTAL_URL']
            auth_params = urllib.parse.urlencode(self.auth.get_auth_headers())
            full_url = f"{portal_url}?{auth_params}"
            webbrowser.open(full_url)
        except Exception as e:
            logger.error(f"Open portal error: {e}")
            messagebox.showerror("Portal Error", f"Failed to open portal: {e}")
    
    def clear_chat(self):
        """Clear chat display"""
        try:
            self.chat_text.config(state='normal')
            self.chat_text.delete('1.0', tk.END)
            self.chat_text.config(state='disabled')
            self.add_chat_message("System", "Chat cleared", "system")
        except Exception as e:
            logger.error(f"Clear chat error: {e}")
    
    def show_about(self):
        """Show about dialog"""
        try:
            about_text = f"""MonsterApps Enhanced Client
Version: 2024.1 Advanced

🚀 Features:
• P2P App Distribution with Web Server
• MySQL-based Node Discovery  
• Real-time Network Chat
• 8-bit CPU Emulator & Assembler
• Expansion System with Backups
• Usage Tracking & Badges
• Encrypted Communications

🔧 Your Node:
• ID: {self.auth.node_id}
• Username: {self.auth.username}
• Web Server: Port {CONFIG['WEBSERVER_PORT']}
• Apps Shared: {len(self.app_manager.get_apps())}

Visit: {CONFIG['PORTAL_URL']}"""
            
            messagebox.showinfo("About MonsterApps", about_text)
        except Exception as e:
            logger.error(f"Show about error: {e}")
    
    def show_cpu_help(self):
        """Show CPU instruction help"""
        try:
            help_text = """8-Bit CPU Instruction Set:

BASIC OPERATIONS:
• MOV reg, value    - Move value to register
• MOV reg1, reg2    - Copy register to register
• ADD reg, value    - Add to register
• SUB reg, value    - Subtract from register

MEMORY OPERATIONS:
• LOAD reg, addr    - Load from memory address
• STORE reg, addr   - Store to memory address
• PUSH reg          - Push register to stack  
• POP reg           - Pop from stack to register

CONTROL FLOW:
• JMP addr          - Jump to address
• JZ addr           - Jump if zero flag set
• JNZ addr          - Jump if zero flag clear
• CMP reg, value    - Compare and set flags

SYSTEM:
• HALT              - Stop execution
• NOP               - No operation

REGISTERS: A, B, C, D (8-bit each)
MEMORY: 256 bytes (0-255)
STACK: Grows downward from address 255

Example Program:
MOV A, 10
MOV B, 5  
ADD A, B
STORE A, 100
HALT"""
            
            messagebox.showinfo("CPU Instruction Set", help_text)
        except Exception as e:
            logger.error(f"Show CPU help error: {e}")
    
    # Additional utility methods for more features
    def edit_app_details(self, app_id: str):
        """Edit app details dialog"""
        try:
            messagebox.showinfo("Feature", "Edit app details dialog would open here")
        except Exception as e:
            logger.error(f"Edit app details error: {e}")
    
    def show_detailed_stats(self, app_id: str):
        """Show detailed app statistics"""
        try:
            stats = self.app_manager.get_app_stats(app_id)
            if stats:
                stats_text = f"""App Statistics for {stats['name']}:

Launches: {stats['launch_count']}
Usage Time: {self._format_time(stats['total_usage_time'])}
Downloads: {stats['downloads']}
Rating: {stats['rating']:.1f}/5.0
Badges: {', '.join(stats['badges']) if stats['badges'] else 'None'}"""
                messagebox.showinfo(f"Stats: {stats['name']}", stats_text)
        except Exception as e:
            logger.error(f"Show detailed stats error: {e}")
    
    def share_app_to_network(self, app_id: str):
        """Share app to network"""
        try:
            if app_id not in self.app_manager.apps:
                return
            
            app = self.app_manager.apps[app_id]
            
            local_ip = self._get_local_ip()
            download_url = f"http://{local_ip}:{CONFIG['WEBSERVER_PORT']}/grab?ack={app.app_token}"
            
            if self.discovery.register_app_availability(app, download_url):
                messagebox.showinfo("Success", f"'{app.name}' is now shared on the network!")
            else:
                messagebox.showerror("Error", "Failed to share app to network")
                
        except Exception as e:
            logger.error(f"Share app error: {e}")
            messagebox.showerror("Error", f"Failed to share app: {e}")
    
    def remove_app(self, app_id: str):
        """Remove app with confirmation"""
        try:
            if app_id not in self.app_manager.apps:
                return
            
            app = self.app_manager.apps[app_id]
            
            result = messagebox.askyesno("Confirm Removal", 
                                       f"Remove '{app.name}' from your collection?\n\n"
                                       "This will not delete the original file.")
            
            if result:
                if self.app_manager.remove_app(app_id):
                    messagebox.showinfo("Removed", f"'{app.name}' has been removed")
                    self.refresh_apps()
                else:
                    messagebox.showerror("Error", "Failed to remove app")
        except Exception as e:
            logger.error(f"Remove app error: {e}")
    
    def generate_invite_link(self):
        """Generate network invite link"""
        try:
            invite_link = f"{CONFIG['PORTAL_URL']}?invite={self.auth.client_token[:16]}"
            messagebox.showinfo("Invite Link", f"Share this link:\n{invite_link}")
        except Exception as e:
            logger.error(f"Generate invite link error: {e}")
    
    def show_network_status(self):
        """Show detailed network status"""
        try:
            status_text = f"""Network Status:

Connected Nodes: {len(self.connected_nodes)}
Database: {'Connected' if self.discovery.db.is_available() else 'Fallback Mode'}
Web Server: Running on port {CONFIG['WEBSERVER_PORT']}
Apps Shared: {len(self.app_manager.get_apps())}"""
            messagebox.showinfo("Network Status", status_text)
        except Exception as e:
            logger.error(f"Show network status error: {e}")
    
    def create_backup(self):
        """Create client backup"""
        try:
            backup_created = self.app_manager._create_client_backup()
            if backup_created:
                messagebox.showinfo("Backup Created", "Client backup created successfully!")
            else:
                messagebox.showerror("Error", "Failed to create backup")
        except Exception as e:
            logger.error(f"Create backup error: {e}")
            messagebox.showerror("Backup Error", f"Backup failed: {e}")
    
    def restore_backup(self):
        """Restore from backup"""
        try:
            messagebox.showinfo("Feature", "Backup restore functionality would be implemented here")
        except Exception as e:
            logger.error(f"Restore backup error: {e}")
    
    def on_closing(self):
        """Handle application closing with proper cleanup"""
        try:
            if messagebox.askyesno("Exit", "Exit MonsterApps Enhanced Client?"):
                logger.info("Application shutting down...")
                
                # Stop services
                try:
                    if hasattr(self, 'web_server'):
                        self.web_server.stop()
                    
                    if hasattr(self, 'discovery'):
                        # Set node as offline
                        self.discovery.db.execute(
                            "UPDATE mesh_nodes SET status = 'offline' WHERE node_id = %s", 
                            (self.auth.node_id,)
                        )
                        self.discovery.db.close()
                    
                    logger.info("Services stopped successfully")
                    
                except Exception as e:
                    logger.error(f"Error stopping services: {e}")
                
                self.root.destroy()
                
        except Exception as e:
            logger.error(f"Shutdown error: {e}")
            self.root.destroy()

def main():
    """Main application entry point with comprehensive error handling"""
    try:
        logger.info("Starting Enhanced MonsterApps Client...")
        
        # Check dependencies
        if not MYSQL_AVAILABLE:
            logger.warning("MySQL not available - limited functionality")
        
        if not CRYPTO_AVAILABLE:
            logger.warning("Cryptography not available - using fallback")
        
        # Create data directories
        for directory in ['monsterapps_data', 'installed_apps', 'expansions', 'client_backups']:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                logger.error(f"Could not create directory {directory}: {e}")
        
        # Start GUI
        app = EnhancedMonsterAppsGUI()
        app.root.protocol("WM_DELETE_WINDOW", app.on_closing)
        
        # Handle uncaught exceptions
        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
            
            logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
            try:
                messagebox.showerror("Unexpected Error", 
                                   f"An unexpected error occurred:\n{exc_type.__name__}: {exc_value}")
            except:
                pass  # If GUI is already destroyed
        
        sys.excepthook = handle_exception
        
        # Start main loop
        logger.info("Starting GUI main loop...")
        app.root.mainloop()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Critical error: {e}", exc_info=True)
        try:
            messagebox.showerror("Critical Error", f"Application failed to start: {e}")
        except:
            print(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()