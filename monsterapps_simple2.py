#!/usr/bin/env python3
"""
MonsterApps Enhanced Client - Direct Mod Access Version
A distributed app store with mesh networking, PFS encryption, and MySQL node discovery.
Mods now have DIRECT access to modify the client GUI and functionality.
Applications are separate launchable programs like Skype.
WARNING: Mods can break the client - this is by design for maximum flexibility.
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
import importlib.util

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Setup comprehensive logging with Unicode support
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler('monsterapps.log', encoding='utf-8'),
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
# DEBUG MONSTERAPPS PYTHON SCRIPT
# Add this to the TOP of monsterapps_simple2.py
# ===========================

import sys
import os
import traceback
import platform

# Create debug log file
debug_log = "monsterapps_debug.log"

def log_debug(message):
    """Log debug messages to file and console"""
    try:
        with open(debug_log, "a", encoding='utf-8') as f:
            f.write(f"{message}\n")
        print(message)
    except:
        print(message)

# Initial system info
log_debug("=" * 50)
log_debug("MONSTERAPPS DEBUG LOG")
log_debug("=" * 50)
log_debug(f"Python version: {sys.version}")
log_debug(f"Platform: {platform.platform()}")
log_debug(f"Architecture: {platform.architecture()}")
log_debug(f"Working directory: {os.getcwd()}")
log_debug(f"Script path: {os.path.abspath(__file__)}")
log_debug(f"Python executable: {sys.executable}")

# Check critical directories
required_dirs = [
    "monsterapps_data",
    "monsterapps_data/installed_apps", 
    "monsterapps_data/mods",
    "monsterapps_data/client_backups"
]

log_debug("\nDIRECTORY CHECK:")
for dir_path in required_dirs:
    if os.path.exists(dir_path):
        log_debug(f"✓ {dir_path} - EXISTS")
    else:
        log_debug(f"✗ {dir_path} - MISSING")

# Check module imports
log_debug("\nMODULE IMPORT CHECK:")

modules_to_check = [
    ("tkinter", "GUI framework"),
    ("mysql.connector", "Database connectivity"),
    ("cryptography", "Encryption features"),
    ("PIL", "Image processing"),
    ("cv2", "Computer vision"),
    ("numpy", "Numerical computing"),
    ("requests", "HTTP requests"),
    ("pathlib", "Path handling"),
    ("threading", "Threading support"),
    ("json", "JSON processing"),
    ("hashlib", "Hashing"),
    ("secrets", "Secure random"),
    ("sqlite3", "SQLite database"),
    ("base64", "Base64 encoding"),
    ("datetime", "Date/time handling")
]

import_results = {}
for module_name, description in modules_to_check:
    try:
        if module_name == "mysql.connector":
            import mysql.connector
            from mysql.connector.pooling import MySQLConnectionPool
        elif module_name == "cryptography":
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import x25519
        elif module_name == "PIL":
            from PIL import Image, ImageTk, ImageEnhance
        elif module_name == "cv2":
            import cv2
        else:
            __import__(module_name)
        
        log_debug(f"✓ {module_name} - OK ({description})")
        import_results[module_name] = True
    except ImportError as e:
        log_debug(f"✗ {module_name} - MISSING: {e}")
        import_results[module_name] = False
    except Exception as e:
        log_debug(f"⚠ {module_name} - ERROR: {e}")
        import_results[module_name] = False

# Check tkinter specifically (common issue)
log_debug("\nTKINTER DETAILED CHECK:")
try:
    import tkinter as tk
    import tkinter.ttk as ttk
    import tkinter.filedialog as filedialog
    import tkinter.messagebox as messagebox
    import tkinter.scrolledtext as scrolledtext
    log_debug("✓ All tkinter modules imported successfully")
    
    # Test tkinter window creation
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the window
        root.destroy()
        log_debug("✓ tkinter window creation test passed")
    except Exception as e:
        log_debug(f"✗ tkinter window creation failed: {e}")
        
except Exception as e:
    log_debug(f"✗ tkinter import failed: {e}")

# Custom exception handler
def handle_exception(exc_type, exc_value, exc_traceback):
    """Custom exception handler to log all errors"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    error_msg = f"UNCAUGHT EXCEPTION: {exc_type.__name__}: {exc_value}"
    log_debug(error_msg)
    log_debug("TRACEBACK:")
    
    # Log full traceback
    tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    for line in tb_lines:
        log_debug(line.strip())
    
    # Also show message box if tkinter is available
    try:
        import tkinter.messagebox as mb
        mb.showerror("MonsterApps Error", f"A critical error occurred:\n\n{exc_type.__name__}: {exc_value}\n\nCheck {debug_log} for details.")
    except:
        pass

# Install the exception handler
sys.excepthook = handle_exception

log_debug("\nSTARTING MONSTERAPPS INITIALIZATION...")

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
    'MODS_DIR': 'mods',
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
    return wrapper

# ===========================
# DATA MODELS
# ===========================

@dataclass
class AppInfo:
    """Application information model - distinguishes between apps and mods"""
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
    is_mod: bool = False  # True for mods, False for applications
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
        if 'is_mod' not in data:
            # Handle legacy 'is_expansion' field
            data['is_mod'] = data.get('is_expansion', False)
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
    """Node information with chat support"""
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
        
        self.fallback_data = {
            'nodes': {},
            'messages': [],
            'apps': []
        }
    
    def _init_connection_pool(self):
        """Initialize MySQL connection pool"""
        try:
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
                is_mod BOOLEAN DEFAULT FALSE,
                last_verified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                status ENUM('available', 'unavailable', 'verifying') DEFAULT 'available',
                UNIQUE KEY unique_node_app (node_id, app_token),
                INDEX idx_node_id (node_id),
                INDEX idx_is_mod (is_mod)
            )
            """
        ]
        
        for table_sql in tables:
            self.execute(table_sql)
        
        # Add is_mod column if it doesn't exist (for existing databases)
        try:
            self.execute("""
                ALTER TABLE app_availability 
                ADD COLUMN IF NOT EXISTS is_mod BOOLEAN DEFAULT FALSE
            """)
        except:
            pass  # Column might already exist
    
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
                
                self.error_count = 0
                return True
                
            except Exception as e:
                self._handle_error(f"Execute error: {e}")
                return False
                
            finally:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()
    
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
                
                self.error_count = 0
                return result
                
            except Exception as e:
                self._handle_error(f"Query error: {e}")
                return None
                
            finally:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()
    
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
        return True
    
    def _query_fallback(self, query: str, params: tuple = None, fetch_one: bool = False) -> Optional[Any]:
        """Fallback query for when database is unavailable"""
        logger.debug(f"Fallback query: {query[:50]}...")
        
        if "mesh_nodes" in query.lower():
            nodes = list(self.fallback_data['nodes'].values())
            return nodes[0] if fetch_one and nodes else nodes
        elif "chat_messages" in query.lower():
            return self.fallback_data['messages']
        elif "app_availability" in query.lower():
            # Ensure fallback apps have is_mod field
            apps = []
            for app in self.fallback_data['apps']:
                if 'is_mod' not in app:
                    app['is_mod'] = False
                apps.append(app)
            return apps
        
        return None if fetch_one else []
    
    def is_available(self) -> bool:
        """Check if database is available"""
        return not self.fallback_mode
    
    def close(self):
        """Close database connections"""
        if self.pool:
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
        
        try:
            with open(target_app.file_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{target_app.name}.{"py" if target_app.is_mod else "exe"}"')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('X-App-Hash', target_app.file_hash)
            self.send_header('X-App-Token', target_app.app_token)
            self.send_header('X-Is-Mod', str(target_app.is_mod))
            self.end_headers()
            
            self.wfile.write(content)
            
            target_app.downloads += 1
            self.app_manager.save_apps()
            
            logger.info(f"{'Mod' if target_app.is_mod else 'App'} downloaded: {target_app.name} (token: {app_token})")
            
        except Exception as e:
            self.send_error(500, f"Download failed: {e}")
    
    def handle_hash_verification(self, params):
        """Handle MD5 hash verification requests"""
        app_token = params.get('token', [None])[0] or params.get('app_token', [None])[0]
        
        if not app_token:
            self.send_error(400, "Missing app token")
            return
        
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
                'is_mod': target_app.is_mod,
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
            'apps_available': len([app for app in self.app_manager.get_apps() if not app.is_mod]),
            'mods_available': len([app for app in self.app_manager.get_apps() if app.is_mod]),
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
                'is_mod': app.is_mod
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
                    'size_match': current_size == app.file_size if file_exists else False,
                    'is_mod': app.is_mod
                })
            
            debug_data = {
                'total_apps': len([app for app in self.app_manager.get_apps() if not app.is_mod]),
                'total_mods': len([app for app in self.app_manager.get_apps() if app.is_mod]),
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
            
            if updated_count > 0:
                self.app_manager.save_apps()
            
            response_data = {
                'success': True,
                'updated_count': updated_count,
                'total_items': len(self.app_manager.get_apps()),
                'errors': errors
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data, indent=2).encode())
            
            logger.info(f"Hash refresh completed: {updated_count} items updated")
            
        except Exception as e:
            self.send_error(500, f"Hash refresh failed: {e}")
    
    def _calculate_md5_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file"""
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
        
        pc = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            if line.endswith(':'):
                labels[line[:-1]] = pc
            else:
                pc += 1
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';') or line.endswith(':'):
                continue
            
            parts = line.split()
            instruction = {
                'op': parts[0],
                'args': parts[1:] if len(parts) > 1 else []
            }
            
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
    """Enhanced app manager with mod support and usage tracking"""
    
    def __init__(self, data_dir: str = "monsterapps_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.registry_file = self.data_dir / "apps.json"
        self.usage_db = self.data_dir / "usage.db"
        self.upload_dir = self.data_dir / CONFIG['UPLOAD_PATH']
        self.apps_dir = self.data_dir / CONFIG['APPS_DIR']
        self.mods_dir = self.data_dir / CONFIG['MODS_DIR']
        self.backups_dir = self.data_dir / CONFIG['BACKUPS_DIR']
        
        for directory in [self.upload_dir, self.apps_dir, self.mods_dir, self.backups_dir]:
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
                        
                logger.info(f"Loaded {len(self.apps)} items successfully")
                        
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
        
        logger.info("Validating file hashes...")
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
            logger.info(f"Updated {updated_count} hashes")
            self.save_apps()
        else:
            logger.info("All hashes are up to date")
    
    def save_apps(self):
        """Save apps to registry file"""
        try:
            with open(self.registry_file, 'w') as f:
                json.dump({aid: app.to_dict() for aid, app in self.apps.items()}, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving apps: {e}")
    
    def add_app(self, file_path: str, name: str = None, category: str = "Utilities", 
                company: str = "Unknown", is_mod: bool = False) -> Optional[AppInfo]:
        """Add new app or mod"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            file_size = os.path.getsize(file_path)
            file_hash = self._calculate_hash(file_path)
            app_token = secrets.token_hex(16)
            
            # Check if already exists
            for existing_app in self.apps.values():
                if existing_app.file_path == file_path and existing_app.is_mod == is_mod:
                    logger.info(f"Item '{name}' from {file_path} already registered.")
                    return existing_app
            
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
                is_mod=is_mod
            )
            
            self.apps[app.app_id] = app
            self.save_apps()
            
            target_dir = self.mods_dir if is_mod else self.apps_dir
            self._prepare_for_hosting(app, target_dir)
            
            self._init_app_usage(app.app_id)
            
            logger.info(f"Added {'mod' if is_mod else 'app'}: {app.name}")
            return app
            
        except Exception as e:
            logger.error(f"Error adding {'mod' if is_mod else 'app'}: {e}")
            return None
    
    def _prepare_for_hosting(self, app: AppInfo, target_dir: Path):
        """Prepare app for network hosting"""
        try:
            file_ext = Path(app.file_path).suffix
            hosted_filename = f"{app.app_id}{file_ext}"
            hosted_path = target_dir / hosted_filename
            
            if Path(app.file_path).resolve() != hosted_path.resolve():
                shutil.copy2(app.file_path, hosted_path)
                logger.info(f"Copied {app.name} to hosting path: {hosted_path}")
            else:
                logger.info(f"{app.name} already in hosting path: {hosted_path}")

            app.file_path = str(hosted_path)
            app.uploaded = True
            self.save_apps()
            
        except Exception as e:
            logger.error(f"Hosting preparation failed for {app.name}: {e}")
    
    def launch_app(self, app_id: str, callback=None, gui_instance=None) -> bool:
        """Launch application or load mod"""
        if app_id not in self.apps:
            logger.warning(f"Attempted to launch non-existent item with ID: {app_id}")
            return False
        
        app = self.apps[app_id]
        
        if not os.path.exists(app.file_path):
            messagebox.showerror("Launch Error", f"File not found: {app.file_path}")
            logger.error(f"Cannot launch {app.name}: file not found at {app.file_path}")
            return False

        if app.is_mod:
            # Load mod directly into client process
            return self._load_mod(app, gui_instance)
        
        # Launch application as separate process
        try:
            start_time = time.time()
            self._record_launch(app_id)
            
            if app.file_path.lower().endswith('.py'):
                subprocess.Popen([sys.executable, app.file_path])
            elif app.file_path.lower().endswith(('.exe', '.bat', '.com')):
                subprocess.Popen([app.file_path])
            elif sys.platform == "win32":
                os.startfile(app.file_path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", app.file_path])
            else:
                subprocess.Popen(["xdg-open", app.file_path])
            
            if callback:
                threading.Thread(target=self._track_usage_session, 
                               args=(app_id, start_time, callback), daemon=True).start()
            
            logger.info(f"Launched application: {app.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to launch application '{app.name}': {e}", exc_info=True)
            messagebox.showerror("Launch Error", f"Failed to launch application '{app.name}': {e}")
            return False
    
    def _load_mod(self, app: AppInfo, gui_instance) -> bool:
        """Load mod directly into client process with FULL access"""
        logger.info(f"Loading mod: {app.name} from {app.file_path}")
        
        # Optional backup creation (user can decline)
        if messagebox.askyesno(
            "Mod Loading",
            f"'{app.name}' is a mod that will modify the client directly.\n\n"
            "Would you like to create a backup first?\n"
            "(Recommended but optional)"
        ):
            if not self._create_client_backup():
                if not messagebox.askyesno("Backup Failed", "Backup creation failed. Continue loading mod anyway?"):
                    return False

        mod_name = Path(app.file_path).stem
        try:
            # Load the mod module with NO RESTRICTIONS
            spec = importlib.util.spec_from_file_location(mod_name, app.file_path)
            if spec is None or spec.loader is None:
                messagebox.showerror("Mod Load Error", f"Could not load mod: {app.name}")
                logger.error(f"Could not load mod spec for: {app.name}")
                return False

            module = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = module
            
            # Execute the module with FULL access to everything
            spec.loader.exec_module(module)

            # Call init_mod if it exists
            if hasattr(module, 'init_mod') and callable(module.init_mod):
                logger.info(f"Calling init_mod for {app.name}")
                
                # Create FULL access API
                mod_api = DirectModAPI(gui_instance, self, logger)
                module.init_mod(mod_api)
                
                messagebox.showinfo("Mod Loaded", f"Mod '{app.name}' loaded successfully with full access!")
                self._record_launch(app.app_id)
                return True
            else:
                # Even without init_mod, the module is loaded and can do anything
                messagebox.showinfo("Mod Loaded", f"Mod '{app.name}' loaded (no init_mod function found)!")
                self._record_launch(app.app_id)
                return True

        except Exception as e:
            messagebox.showerror("Mod Load Error", f"Failed to load mod '{app.name}': {e}")
            logger.error(f"Failed to load mod '{app.name}': {e}", exc_info=True)
            return False
    
    def _create_client_backup(self) -> bool:
        """Create backup of current client directory"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"client_backup_{timestamp}"
            backup_path = self.backups_dir / backup_name
            
            current_script_dir = Path(sys.argv[0]).parent.resolve()
            
            shutil.copytree(current_script_dir, backup_path, 
                            ignore=shutil.ignore_patterns('*.pyc', '__pycache__', 
                                                          self.data_dir.name,
                                                          self.backups_dir.name))
            
            logger.info(f"Client backup created: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}", exc_info=True)
            return False
    
    @safe_thread_wrapper
    def _track_usage_session(self, app_id: str, start_time: float, callback):
        """Track app usage session"""
        import time
        time.sleep(5)
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
            logger.error(f"Usage tracking error for {app_id}: {e}", exc_info=True)
    
    def _record_launch(self, app_id: str):
        """Record app launch"""
        try:
            conn = sqlite3.connect(self.usage_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO app_usage (app_id, launch_count, last_used)
                VALUES (?, COALESCE((SELECT launch_count FROM app_usage WHERE app_id = ?), 0) + 1, ?)
            ''', (app_id, app_id, time.time()))
            
            conn.commit()
            conn.close()
            
            if app_id in self.apps:
                self.apps[app_id].launch_count += 1
                self.apps[app_id].last_used = time.time()
                
        except Exception as e:
            logger.error(f"Launch recording error for {app_id}: {e}", exc_info=True)
    
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
            logger.error(f"Usage initialization error for {app_id}: {e}", exc_info=True)
    
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
        if app.is_mod:
            badges.add("🔧 Mod")
        else:
            badges.add("📱 Application")
        
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
            logger.error(f"Stats retrieval error for {app_id}: {e}", exc_info=True)
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
            'is_mod': app.is_mod,
            'created_at': app.created_at
        }
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}", exc_info=True)
            return ""
    
    def get_apps(self) -> List[AppInfo]:
        """Get all apps and mods"""
        return list(self.apps.values())
    
    def get_applications(self) -> List[AppInfo]:
        """Get only applications (not mods)"""
        return [app for app in self.apps.values() if not app.is_mod]
    
    def get_mods(self) -> List[AppInfo]:
        """Get only mods"""
        return [app for app in self.apps.values() if app.is_mod]
    
    def remove_app(self, app_id: str) -> bool:
        """Remove app from registry and delete its hosted file"""
        if app_id in self.apps:
            app = self.apps[app_id]
            file_to_delete = Path(app.file_path)
            
            if file_to_delete.exists() and (file_to_delete.parent == self.apps_dir or file_to_delete.parent == self.mods_dir):
                try:
                    os.remove(file_to_delete)
                    logger.info(f"Deleted hosted file for {app.name}: {file_to_delete}")
                except Exception as e:
                    logger.error(f"Error deleting hosted file for {app.name}: {e}", exc_info=True)
            else:
                logger.warning(f"File for {app.name} not found at expected path: {file_to_delete}")

            del self.apps[app_id]
            self.save_apps()
            logger.info(f"Removed {'mod' if app.is_mod else 'app'} '{app.name}' (ID: {app_id})")
            return True
        return False

# ===========================
# MOD LOADER CLASS
# ===========================

class ModLoader:
    """Manages the discovery and registration of mods"""
    
    def __init__(self, app_manager: EnhancedAppManager):
        self.app_manager = app_manager
        self.mods_dir = app_manager.mods_dir
        logger.info(f"ModLoader initialized. Mods directory: {self.mods_dir}")

    def scan_for_new_mods(self) -> List[AppInfo]:
        """Scan for new Python files that could be mods"""
        newly_registered_mods = []
        
        registered_mod_paths = {app.file_path for app in self.app_manager.get_mods()}
        
        for potential_mod_file in self.mods_dir.iterdir():
            if potential_mod_file.is_file() and potential_mod_file.suffix.lower() == '.py':
                if str(potential_mod_file) not in registered_mod_paths:
                    logger.info(f"ModLoader: Found new mod file: {potential_mod_file.name}")
                    
                    added_app_info = self.app_manager.add_app(
                        file_path=str(potential_mod_file),
                        name=potential_mod_file.stem,
                        category="Mod",
                        company="Community Mod",
                        is_mod=True
                    )
                    if added_app_info:
                        newly_registered_mods.append(added_app_info)
                        logger.info(f"ModLoader: Registered new mod '{added_app_info.name}'")
                    else:
                        logger.warning(f"ModLoader: Failed to register mod from {potential_mod_file.name}")
                else:
                    logger.debug(f"ModLoader: Mod '{potential_mod_file.name}' already registered.")
            else:
                logger.debug(f"ModLoader: Skipping non-Python file: {potential_mod_file.name}")
                
        return newly_registered_mods

    def get_installed_mods(self) -> List[AppInfo]:
        """Returns a list of all installed mods"""
        return self.app_manager.get_mods()

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
            logger.error(f"Node registration error: {e}", exc_info=True)
        
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
                        logger.warning(f"Error processing node row: {e}", exc_info=True)
                        continue
                
                return nodes
            
        except Exception as e:
            logger.error(f"Error getting online nodes: {e}", exc_info=True)
        
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
            logger.error(f"Heartbeat update error: {e}", exc_info=True)
        
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
            logger.error(f"Chat message send error: {e}", exc_info=True)
        
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
                        logger.warning(f"Error processing message row: {e}", exc_info=True)
                        continue
                
                return messages
            
        except Exception as e:
            logger.error(f"Error getting chat messages: {e}", exc_info=True)
        
        messages = []
        since_time = datetime.min
        
        if since_timestamp:
            try:
                if isinstance(since_timestamp, str):
                    since_time = datetime.strptime(since_timestamp, '%Y-%m-%d %H:%M:%S')
                else:
                    since_time = since_timestamp
            except ValueError:
                logger.warning(f"Invalid since_timestamp format: {since_timestamp}")
                since_time = datetime.min
        
        for msg in self.fallback_messages:
            if (msg['receiver_id'] == self.auth.node_id or msg['type'] == 'broadcast') and \
               msg['sender_id'] != self.auth.node_id and \
               msg['timestamp'] > since_time:
                messages.append(msg)
        
        return messages[-50:]
    
    def register_app_availability(self, app: AppInfo, download_url: str) -> bool:
        """Register app/mod availability for network sharing"""
        try:
            # Log what we're registering
            logger.info(f"Registering {app.name} - Type: {'MOD' if app.is_mod else 'APP'} (is_mod={app.is_mod})")
            
            success = self.db.execute("""
                INSERT INTO app_availability (node_id, app_token, app_name, app_category, 
                                            file_size, file_hash, download_url, is_mod)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    app_name = VALUES(app_name),
                    download_url = VALUES(download_url),
                    is_mod = VALUES(is_mod),
                    last_verified = CURRENT_TIMESTAMP
            """, (
                self.auth.node_id, app.app_token, app.name, app.category,
                app.file_size, app.file_hash, download_url, int(app.is_mod)
            ))
            
            if success:
                logger.info(f"Successfully registered {app.name} as {'MOD' if app.is_mod else 'APP'}")
            else:
                logger.error(f"Failed to register {app.name}")
                # Fallback storage
                if self.db.fallback_mode:
                    app_data = {
                        'node_id': self.auth.node_id,
                        'username': self.auth.username,
                        'node_status': 'online',
                        'app_token': app.app_token,
                        'app_name': app.name,
                        'category': app.category,
                        'file_size': app.file_size,
                        'file_hash': app.file_hash,
                        'download_url': download_url,
                        'last_verified': datetime.now(),
                        'app_status': 'available',
                        'is_mod': app.is_mod,
                        'available': True
                    }
                    self.db.fallback_data['apps'].append(app_data)
                    logger.info(f"Registered {app.name} as {'MOD' if app.is_mod else 'APP'} in fallback mode")
                    return True
            
            return success
            
        except Exception as e:
            logger.error(f"App/Mod registration error for {app.name}: {e}", exc_info=True)
            return False
    
    def get_available_apps(self) -> List[Dict]:
        """Get available apps from network"""
        try:
            rows = self.db.query("""
                SELECT aa.node_id, mn.username, mn.status, aa.app_token, aa.app_name, 
                       aa.app_category, aa.file_size, aa.file_hash, aa.download_url,
                       aa.last_verified, aa.status as app_status, COALESCE(aa.is_mod, FALSE) as is_mod
                FROM app_availability aa
                JOIN mesh_nodes mn ON aa.node_id = mn.node_id
                WHERE mn.last_heartbeat > NOW() - INTERVAL 300 SECOND
                AND aa.status = 'available'
                ORDER BY aa.is_mod DESC, aa.app_name, mn.username
            """)
            
            if rows is not None:
                apps = []
                for row in rows:
                    try:
                        (node_id, username, node_status, app_token, app_name, 
                         category, file_size, file_hash, download_url, last_verified, 
                         app_status, is_mod) = row
                        
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
                            # FIX: Ensure is_mod is correctly converted to boolean
                            'is_mod': bool(int(is_mod)) if is_mod is not None else False,
                            'available': True  # Always true for online nodes
                        })
                    except Exception as e:
                        logger.warning(f"Error processing app row: {e}", exc_info=True)
                        continue
                
                return apps
            
        except Exception as e:
            logger.error(f"Error getting available apps: {e}", exc_info=True)
        
        return []

# ===========================
# ENHANCED AUTHENTICATION
# ===========================

class EnhancedAuth:
    """Enhanced authentication with node registration"""
    
    def __init__(self):
        try:
            self.node_id = f"node_{secrets.token_hex(16)}"
            self.username = f"User_{secrets.token_hex(4)}"
            self.master_key = bytes.fromhex('50a12602f01a0dadf29070af27acb1fb1234567890abcdef1234567890abcdef12')
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
            logger.error(f"Auth initialization error: {e}", exc_info=True)
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
            logger.error(f"Token generation error: {e}", exc_info=True)
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
            logger.error(f"Auth headers error: {e}", exc_info=True)
            return {}
    
    @safe_thread_wrapper
    def register_with_portal(self) -> bool:
        """Register node with portal for live status"""
        if not HTTP_AVAILABLE or not CONFIG['ENABLE_PORTAL']:
            logger.info("Portal registration skipped")
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
            
        except Exception as e:
            logger.error(f"Portal registration failed: {e}", exc_info=True)
            return False

# ===========================
# DIRECT MOD API - FULL ACCESS
# ===========================

class DirectModAPI:
    """
    Direct Mod API with FULL access to the client.
    Mods can modify anything they want through this API.
    """
    
    def __init__(self, gui_instance, app_manager: EnhancedAppManager, logger_instance: logging.Logger):
        # DIRECT ACCESS - no restrictions
        self.gui = gui_instance  # Full GUI access (for backward compatibility)
        self.app_manager = app_manager  # Full app manager access
        self.logger = logger_instance  # Logger access
        
        # Give mods access to the main tkinter root and notebook
        if gui_instance:
            self.root = gui_instance.root
            self.notebook = gui_instance.notebook
    
    def add_gui_tab(self, tab_title: str, content_widget: tk.Widget = None, tab_id: str = None):
        """
        Add a new tab to the main GUI.
        Mods can pass a fully constructed widget.
        """
        try:
            if content_widget is not None:
                # Add the widget directly as a tab
                self.notebook.add(content_widget, text=tab_title)
                self.notebook.select(content_widget)
                self.logger.info(f"Added mod tab: '{tab_title}'")
                return True
            else:
                # Create empty frame for mod to populate
                new_frame = tk.Frame(self.notebook, bg='#1e293b')
                self.notebook.add(new_frame, text=tab_title)
                self.notebook.select(new_frame)
                self.logger.info(f"Added empty mod tab: '{tab_title}'")
                return new_frame
                
        except Exception as e:
            self.logger.error(f"Error adding mod tab '{tab_title}': {e}", exc_info=True)
            return False
    
    def send_broadcast_message(self, message: str):
        """Send a broadcast message through the chat system"""
        try:
            if hasattr(self.gui, 'discovery'):
                success = self.gui.discovery.send_chat_message(message, None, 'broadcast')
                if success:
                    # Also display locally
                    self.gui.add_chat_message("You (Broadcast)", message, "sent")
                return success
            return False
        except Exception as e:
            self.logger.error(f"Error sending broadcast message: {e}", exc_info=True)
            return False
    
    def get_installed_apps_info(self) -> List[Dict[str, Any]]:
        """Get information about all installed apps and mods"""
        try:
            return [app.to_dict() for app in self.app_manager.get_apps()]
        except Exception as e:
            self.logger.error(f"Error getting apps info: {e}", exc_info=True)
            return []
    
    def get_network_nodes(self) -> List[Dict[str, Any]]:
        """Get information about connected network nodes"""
        try:
            if hasattr(self.gui, 'connected_nodes'):
                return [asdict(node) for node in self.gui.connected_nodes.values()]
            return []
        except Exception as e:
            self.logger.error(f"Error getting network nodes: {e}", exc_info=True)
            return []
    
    def modify_gui_element(self, element_name: str, property_name: str, new_value):
        """Directly modify GUI elements - DANGEROUS but allowed"""
        try:
            if hasattr(self.gui, element_name):
                element = getattr(self.gui, element_name)
                if hasattr(element, property_name):
                    setattr(element, property_name, new_value)
                    self.logger.info(f"Modified {element_name}.{property_name} = {new_value}")
                    return True
                else:
                    element.config(**{property_name: new_value})
                    self.logger.info(f"Configured {element_name}.{property_name} = {new_value}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Error modifying GUI element: {e}", exc_info=True)
            return False
    
    def execute_in_gui_thread(self, func, *args, **kwargs):
        """Execute a function in the GUI thread"""
        try:
            self.root.after(0, lambda: func(*args, **kwargs))
            return True
        except Exception as e:
            self.logger.error(f"Error executing in GUI thread: {e}", exc_info=True)
            return False
    
    def log_mod_message(self, level: str, message: str):
        """Log a message from the mod"""
        try:
            # Remove emojis from log messages to prevent encoding issues
            safe_message = message.encode('ascii', 'ignore').decode('ascii')
            if level == 'info':
                self.logger.info(f"[MOD] {safe_message}")
            elif level == 'warning':
                self.logger.warning(f"[MOD] {safe_message}")
            elif level == 'error':
                self.logger.error(f"[MOD] {safe_message}")
            else:
                self.logger.debug(f"[MOD] {safe_message}")
        except Exception as e:
            # Fallback logging without the problematic message
            self.logger.error(f"[MOD] Logging error: {e}")
    
    # FULL ACCESS PROPERTIES - Mods can access anything
    @property
    def full_gui_access(self):
        """Give mods complete access to the GUI instance"""
        return self.gui
    
    @property
    def full_app_manager_access(self):
        """Give mods complete access to the app manager"""
        return self.app_manager
    
    @property
    def tkinter_root(self):
        """Direct access to tkinter root"""
        return self.root
    
    @property
    def main_notebook(self):
        """Direct access to main notebook"""
        return self.notebook

# ===========================
# ENHANCED GUI
# ===========================

class EnhancedMonsterAppsGUI:
    """Enhanced GUI with direct mod support"""
    
    def __init__(self):
        try:
            self.root = tk.Tk()
            self.root.title("MonsterApps Enhanced - P2P App Distribution with Direct Mod Access")
            self.root.geometry("1400x900")
            self.root.configure(bg='#0f172a')
            
            # Enhanced styling
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#4CAF50')
            style.configure('Mod.TButton', background='#FF6B35', foreground='white')
            style.configure('App.TButton', background='#4CAF50', foreground='white')
            
            # Initialize components
            self.auth = EnhancedAuth()
            self.app_manager = EnhancedAppManager()
            self.mod_loader = ModLoader(self.app_manager)
            self.discovery = SimpleNodeDiscovery(self.auth)
            self.web_server = AppWebServer(self.app_manager, self.auth)
            
            # State
            self.connected_nodes = {}
            self.chat_messages = []
            self.last_chat_check = time.time()
            self.selected_app = None
            self.service_errors = []
            
            # Setup GUI
            self.setup_gui()
            self.setup_menu()
            
            # Start services
            threading.Thread(target=self.start_services_safe, daemon=True).start()
            
            # Schedule updates
            self.root.after(5000, self.schedule_updates)
            
            logger.info("GUI initialized successfully with direct mod access")
            
        except Exception as e:
            logger.error(f"GUI initialization error: {e}", exc_info=True)
            messagebox.showerror("Startup Error", f"Failed to initialize application: {e}")
            sys.exit(1)
    
    def setup_gui(self):
        """Setup enhanced GUI with multiple panels"""
        try:
            # Main container with notebook
            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Applications Panel
            apps_frame = tk.Frame(self.notebook, bg='#1e293b')
            self.notebook.add(apps_frame, text="📱 Applications")
            self.setup_apps_panel(apps_frame)
            
            # Mods Panel
            mods_frame = tk.Frame(self.notebook, bg='#1e293b')
            self.notebook.add(mods_frame, text="🔧 Mods")
            self.setup_mods_panel(mods_frame)
            
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
            logger.error(f"GUI setup error: {e}", exc_info=True)
            raise
    
    def setup_apps_panel(self, parent):
        """Setup applications panel"""
        try:
            # Header
            header = tk.Frame(parent, bg='#1e293b')
            header.pack(fill='x', padx=10, pady=5)
            
            tk.Label(header, text="📱 Applications", font=('Arial', 20, 'bold'),
                    fg='#4CAF50', bg='#1e293b').pack(side='left')
            
            # Controls
            controls = tk.Frame(header, bg='#1e293b')
            controls.pack(side='right')
            
            tk.Button(controls, text="➕ Add Application", command=self.add_app_dialog,
                     bg='#4CAF50', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=2)
            
            tk.Button(controls, text="🔄 Refresh", command=self.refresh_apps,
                     bg='#2196F3', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=2)
            
            # Apps container
            apps_container = tk.Frame(parent, bg='#1e293b')
            apps_container.pack(fill='both', expand=True, padx=10, pady=5)
            
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
            
            def _on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            canvas.bind("<MouseWheel>", _on_mousewheel)
            
        except Exception as e:
            logger.error(f"Apps panel setup error: {e}", exc_info=True)

    def setup_mods_panel(self, parent):
        """Setup mods panel"""
        try:
            # Header
            header = tk.Frame(parent, bg='#1e293b')
            header.pack(fill='x', padx=10, pady=5)
            
            tk.Label(header, text="🔧 Client Mods (Direct Access)", font=('Arial', 20, 'bold'),
                    fg='#FF6B35', bg='#1e293b').pack(side='left')
            
            # Controls
            controls = tk.Frame(header, bg='#1e293b')
            controls.pack(side='right')
            
            tk.Button(controls, text="➕ Add Mod", command=self.add_mod_dialog,
                     bg='#FF6B35', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=2)
            
            tk.Button(controls, text="🔍 Scan for Mods", command=self.scan_for_new_mods,
                     bg='#2196F3', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=2)
            
            tk.Button(controls, text="🔄 Refresh", command=self.refresh_mods,
                     bg='#2196F3', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=2)
            
            # Mods container
            mods_container = tk.Frame(parent, bg='#1e293b')
            mods_container.pack(fill='both', expand=True, padx=10, pady=5)
            
            canvas = tk.Canvas(mods_container, bg='#1e293b', highlightthickness=0)
            scrollbar = ttk.Scrollbar(mods_container, orient='vertical', command=canvas.yview)
            self.mods_scroll_frame = tk.Frame(canvas, bg='#1e293b')
            
            self.mods_scroll_frame.bind(
                '<Configure>',
                lambda e: canvas.configure(scrollregion=canvas.bbox('all'))
            )
            
            canvas.create_window((0, 0), window=self.mods_scroll_frame, anchor='nw')
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side='left', fill='both', expand=True)
            scrollbar.pack(side='right', fill='y')
            
            self.mods_canvas = canvas
            
            def _on_mousewheel_mods(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            canvas.bind("<MouseWheel>", _on_mousewheel_mods)

            self.refresh_mods()
            
        except Exception as e:
            logger.error(f"Mods panel setup error: {e}", exc_info=True)
    
    def setup_store_panel(self, parent):
        """Setup app store panel"""
        try:
            # Header
            header = tk.Frame(parent, bg='#1e293b')
            header.pack(fill='x', padx=10, pady=5)
            
            tk.Label(header, text="🛒 MonsterApps Store", font=('Arial', 20, 'bold'),
                    fg='#4CAF50', bg='#1e293b').pack(side='left')
            
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
            
            tk.Label(search_frame, text="Category:", fg='white', bg='#1e293b').pack(side='left', padx=(10,0))
            self.category_var = tk.StringVar(value="All")
            category_combo = ttk.Combobox(search_frame, textvariable=self.category_var, width=15)
            category_combo['values'] = ('All', 'Games', 'Utilities', 'Development', 'Graphics', 'Network', 'Business', 'Mod')
            category_combo.pack(side='left', padx=5)
            category_combo.bind('<<ComboboxSelected>>', self.on_category_change)
            
            # Store items container
            store_container = tk.Frame(parent, bg='#1e293b')
            store_container.pack(fill='both', expand=True, padx=10, pady=5)
            
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
            
            def _on_store_mousewheel(event):
                store_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            store_canvas.bind("<MouseWheel>", _on_store_mousewheel)
            
        except Exception as e:
            logger.error(f"Store panel setup error: {e}", exc_info=True)
    
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
Web Server: http://192.168.1.58:{CONFIG['WEBSERVER_PORT']}
Client Token: {self.auth.client_token[:16]}..."""
            
            tk.Label(info_frame, text=node_info, fg='#cccccc', bg='#1e293b', 
                    justify='left', font=('Consolas', 10)).pack(padx=10, pady=10)
            
            # Connected nodes
            nodes_frame = tk.LabelFrame(parent, text="Connected Nodes", fg='white', bg='#1e293b')
            nodes_frame.pack(fill='both', expand=True, padx=10, pady=5)
            
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
            logger.error(f"Network panel setup error: {e}", exc_info=True)
    
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
            logger.error(f"Chat panel setup error: {e}", exc_info=True)
    
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
            logger.error(f"CPU panel setup error: {e}", exc_info=True)
    
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
            logger.error(f"Status bar setup error: {e}", exc_info=True)

    def setup_menu(self):
        """Setup application menu"""
        try:
            menubar = tk.Menu(self.root)
            self.root.config(menu=menubar)
            
            # File menu
            file_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="File", menu=file_menu)
            file_menu.add_command(label="Add Application", command=self.add_app_dialog)
            file_menu.add_command(label="Add Mod", command=self.add_mod_dialog)
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
            tools_menu.add_separator()
            tools_menu.add_command(label="Scan for New Mods", command=self.scan_for_new_mods)
            
            # Help menu
            help_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Help", menu=help_menu)
            help_menu.add_command(label="About", command=self.show_about)
            help_menu.add_command(label="CPU Instructions", command=self.show_cpu_help)
            
        except Exception as e:
            logger.error(f"Menu setup error: {e}", exc_info=True)

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
                    
                    # Register all apps and mods with their correct type
                    for app in self.app_manager.get_apps():
                        download_url = f"http://{local_ip}:{CONFIG['WEBSERVER_PORT']}/grab?ack={app.app_token}"
                        # Pass the full AppInfo object to preserve is_mod status
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
            logger.error(f"Service startup error: {e}", exc_info=True)
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
            logger.error(f"Service status update error: {e}", exc_info=True)
    
    def update_portal_status(self, status: str, color: str):
        """Update portal status"""
        try:
            self.network_status_label.config(text=f"Portal: {status}", fg=color)
        except Exception as e:
            logger.error(f"Portal status update error: {e}", exc_info=True)
    
    def show_service_error(self, error: str):
        """Show service error in GUI"""
        try:
            self.status_label.config(text=f"Service error: {error}")
            logger.error(f"Service error displayed: {error}")
        except Exception as e:
            logger.error(f"Error showing service error: {e}", exc_info=True)
    
    def schedule_updates(self):
        """Schedule periodic updates with error handling"""
        try:
            self.refresh_nodes_safe()
            self.check_chat_messages_safe()
            self.refresh_apps_safe()
            self.refresh_mods_safe()
            
            # Update heartbeat
            threading.Thread(target=self.update_heartbeat_safe, daemon=True).start()
            
            # Schedule next update
            self.root.after(5000, self.schedule_updates)
            
        except Exception as e:
            logger.error(f"Update scheduling error: {e}", exc_info=True)
            self.root.after(10000, self.schedule_updates)
    
    @safe_thread_wrapper
    def update_heartbeat_safe(self):
        """Update heartbeat safely"""
        try:
            apps_count = len(self.app_manager.get_apps())
            self.discovery.update_heartbeat(apps_count)
        except Exception as e:
            logger.error(f"Heartbeat update error: {e}", exc_info=True)

    # ===========================
    # APP PANEL METHODS
    # ===========================
    
    def create_app_card(self, app: AppInfo, parent_frame):
        """Create enhanced app/mod card"""
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
            app_type_text = "🔧 MOD" if app.is_mod else "📱 APP"
            type_color = '#FF6B35' if app.is_mod else '#4CAF50'
            
            tk.Label(name_frame, text=app_type_text, fg=type_color, bg='#2d3748', 
                    font=('Arial', 8, 'bold')).pack(anchor='w')
            
            tk.Label(name_frame, text=app.name, fg='white', bg='#2d3748',
                    font=('Arial', 14, 'bold')).pack(anchor='w')
            
            tk.Label(name_frame, text=f"v{app.version} by {app.company}", 
                    fg='#a0aec0', bg='#2d3748', font=('Arial', 9)).pack(anchor='w')
            
            # Launch button
            button_text = "⚙️ Load Mod" if app.is_mod else "▶️ Launch"
            
            launch_btn = tk.Button(header, text=button_text,
                                  bg=type_color, fg='white', font=('Arial', 10, 'bold'),
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
                
                for badge in app.badges[:3]:
                    badge_label = tk.Label(badges_frame, text=badge, fg='#ffd700', bg='#1a202c',
                                         font=('Arial', 8), padx=3, pady=1)
                    badge_label.pack(side='left', padx=(0, 2))
            
            # Description
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
                    logger.error(f"Context menu error: {e}", exc_info=True)
            
            card.bind("<Button-3>", show_context_menu)
            
            return card
            
        except Exception as e:
            logger.error(f"App card creation error: {e}", exc_info=True)
            return None
    
    def create_store_item(self, app_data, parent_frame):
        """Create store item with availability status - matching app card styling"""
        try:
            # Determine if it's a mod or app
            is_mod = app_data.get('is_mod', False)
            
            # Main card frame - same as create_app_card
            card = tk.Frame(parent_frame, bg='#2d3748', relief='raised', bd=2)
            card.pack(fill='x', padx=5, pady=5)
            
            # Header with app name and type
            header = tk.Frame(card, bg='#2d3748')
            header.pack(fill='x', padx=10, pady=(10, 5))
            
            # App icon and name
            name_frame = tk.Frame(header, bg='#2d3748')
            name_frame.pack(side='left', fill='x', expand=True)
            
            # App type indicator - matching exact style from app cards
            app_type_text = "🔧 MOD" if is_mod else "📱 APP"
            type_color = '#FF6B35' if is_mod else '#4CAF50'
            
            tk.Label(name_frame, text=app_type_text, fg=type_color, bg='#2d3748', 
                    font=('Arial', 8, 'bold')).pack(anchor='w')
            
            tk.Label(name_frame, text=app_data['app_name'], fg='white', bg='#2d3748',
                    font=('Arial', 14, 'bold')).pack(anchor='w')
            
            provider_text = f"From: {app_data['username']} | {app_data['category']}"
            tk.Label(name_frame, text=provider_text, 
                    fg='#a0aec0', bg='#2d3748', font=('Arial', 9)).pack(anchor='w')
            
            # Download button with proper color
            download_btn = tk.Button(header, text="⬇️ Download",
                                  bg=type_color, fg='white', font=('Arial', 10, 'bold'),
                                  command=lambda: self.download_app_from_store(app_data))
            download_btn.pack(side='right', padx=(10, 0))
            
            # Stats row
            stats_frame = tk.Frame(card, bg='#2d3748')
            stats_frame.pack(fill='x', padx=10, pady=5)
            
            # Network status and file info
            stats_text = f"🟢 Online | 💾 {self._format_size(app_data['file_size'])}"
            if app_data.get('downloads', 0) > 0:
                stats_text += f" | ⬇️ {app_data['downloads']} downloads"
            
            tk.Label(stats_frame, text=stats_text, fg='#a0aec0', bg='#2d3748',
                    font=('Arial', 9)).pack(side='left')
            
            # Description (if available, otherwise use category)
            desc_text = f"Network shared {app_data['category'].lower()}"
            if is_mod:
                desc_text = "Client modification - loads directly into MonsterApps"
            
            desc_label = tk.Label(card, text=desc_text, fg='#e2e8f0', bg='#2d3748',
                                font=('Arial', 9), wraplength=400, justify='left')
            desc_label.pack(fill='x', padx=10, pady=(0, 10))
                    
        except Exception as e:
            logger.error(f"Store item creation error: {e}", exc_info=True)
    
    def refresh_apps_safe(self):
        """Refresh apps display safely"""
        try:
            self.root.after(0, self.refresh_apps)
        except Exception as e:
            logger.error(f"Apps refresh scheduling error: {e}", exc_info=True)
    
    def refresh_apps(self):
        """Refresh the applications display"""
        try:
            # Clear existing app cards
            for widget in self.apps_scroll_frame.winfo_children():
                widget.destroy()
            
            # Create new app cards (only applications)
            apps = self.app_manager.get_applications()
            if not apps:
                tk.Label(self.apps_scroll_frame, text="No applications installed\nClick 'Add Application' to get started!",
                        fg='#a0aec0', bg='#1e293b', font=('Arial', 12), justify='center').pack(pady=50)
            else:
                for app in sorted(apps, key=lambda x: x.name):
                    self.create_app_card(app, self.apps_scroll_frame)
            
            # Update canvas scroll region
            self.apps_scroll_frame.update_idletasks()
            self.apps_canvas.configure(scrollregion=self.apps_canvas.bbox("all"))
            
        except Exception as e:
            logger.error(f"Apps refresh error: {e}", exc_info=True)

    def refresh_mods_safe(self):
        """Refresh mods display safely"""
        try:
            self.root.after(0, self.refresh_mods)
        except Exception as e:
            logger.error(f"Mods refresh scheduling error: {e}", exc_info=True)

    def refresh_mods(self):
        """Refresh the mods display"""
        try:
            # Clear existing mod cards
            for widget in self.mods_scroll_frame.winfo_children():
                widget.destroy()
            
            # Create new mod cards
            mods = self.app_manager.get_mods()
            if not mods:
                info_frame = tk.Frame(self.mods_scroll_frame, bg='#1e293b')
                info_frame.pack(pady=50)
                
                tk.Label(info_frame, text="⚠️ WARNING: DIRECT MOD ACCESS", 
                        fg='#FF6B35', bg='#1e293b', font=('Arial', 14, 'bold')).pack(pady=5)
                tk.Label(info_frame, text="Mods have FULL access to modify the client.\nThey can break the client - this is intentional for maximum flexibility.",
                        fg='#a0aec0', bg='#1e293b', font=('Arial', 11), justify='center').pack(pady=5)
                tk.Label(info_frame, text="No mods installed.\nAdd mod files or click 'Scan for Mods'!",
                        fg='#a0aec0', bg='#1e293b', font=('Arial', 12), justify='center').pack(pady=10)
            else:
                # Warning header
                warning_frame = tk.Frame(self.mods_scroll_frame, bg='#FF6B35', relief='raised', bd=2)
                warning_frame.pack(fill='x', padx=5, pady=5)
                
                tk.Label(warning_frame, text="⚠️ MODS HAVE DIRECT CLIENT ACCESS - CAN MODIFY ANYTHING", 
                        fg='white', bg='#FF6B35', font=('Arial', 12, 'bold')).pack(pady=5)
                
                for mod_app in sorted(mods, key=lambda x: x.name):
                    self.create_app_card(mod_app, self.mods_scroll_frame)
            
            # Update canvas scroll region
            self.mods_scroll_frame.update_idletasks()
            self.mods_canvas.configure(scrollregion=self.mods_canvas.bbox("all"))
            
        except Exception as e:
            logger.error(f"Mods refresh error: {e}", exc_info=True)

    def refresh_store(self):
        """Refresh the store display"""
        try:
            # Clear existing store items
            for widget in self.store_scroll_frame.winfo_children():
                widget.destroy()
            
            # Show loading message
            loading_label = tk.Label(self.store_scroll_frame, text="🔄 Loading applications and mods from network...",
                                   fg='#ffa500', bg='#1e293b', font=('Arial', 12))
            loading_label.pack(pady=20)
            
            # Fetch apps in background
            threading.Thread(target=self._fetch_store_apps, daemon=True).start()
            
        except Exception as e:
            logger.error(f"Store refresh error: {e}", exc_info=True)
    
    @safe_thread_wrapper
    def _fetch_store_apps(self):
        """Fetch apps from network stores"""
        try:
            available_apps = self.discovery.get_available_apps()
            
            # Update GUI in main thread
            self.root.after(0, lambda: self._display_store_apps(available_apps))
            
        except Exception as e:
            logger.error(f"Store fetch error: {e}", exc_info=True)
            self.root.after(0, lambda: self._show_store_error(str(e)))
    
    def _display_store_apps(self, apps):
        """Display apps in store"""
        try:
            # Clear loading message
            for widget in self.store_scroll_frame.winfo_children():
                widget.destroy()
            
            if not apps:
                tk.Label(self.store_scroll_frame, text="No applications or mods available in network\nConnect to more nodes to see content!",
                        fg='#a0aec0', bg='#1e293b', font=('Arial', 12), justify='center').pack(pady=50)
            else:
                # Debug logging
                logger.info(f"Displaying {len(apps)} items in store")
                
                # Separate apps and mods
                mods = []
                applications = []
                
                for app in apps:
                    is_mod = app.get('is_mod', False)
                    logger.debug(f"Store item: {app['app_name']} - is_mod={is_mod} (type: {type(is_mod)})")
                    
                    if is_mod:
                        mods.append(app)
                    else:
                        applications.append(app)
                
                logger.info(f"Found {len(mods)} mods and {len(applications)} apps")
                
                # Display mods section if any
                if mods:
                    mod_header = tk.Frame(self.store_scroll_frame, bg='#1e293b')
                    mod_header.pack(fill='x', padx=5, pady=(10, 5))
                    
                    tk.Label(mod_header, text=f"🔧 Available Mods ({len(mods)})",
                            fg='#FF6B35', bg='#1e293b', font=('Arial', 16, 'bold')).pack(anchor='w')
                    
                    for mod in sorted(mods, key=lambda x: x['app_name']):
                        if self._should_show_app(mod):
                            self.create_store_item(mod, self.store_scroll_frame)
                
                # Display apps by category
                if applications:
                    categorized = {}
                    for app in applications:
                        category = app['category']
                        if category not in categorized:
                            categorized[category] = []
                        categorized[category].append(app)
                    
                    if mods:
                        # Add separator between mods and apps
                        separator = tk.Frame(self.store_scroll_frame, bg='#4CAF50', height=2)
                        separator.pack(fill='x', padx=20, pady=10)
                    
                    # Apps section header
                    apps_header = tk.Frame(self.store_scroll_frame, bg='#1e293b')
                    apps_header.pack(fill='x', padx=5, pady=(10, 5))
                    
                    tk.Label(apps_header, text=f"📱 Available Applications",
                            fg='#4CAF50', bg='#1e293b', font=('Arial', 16, 'bold')).pack(anchor='w')
                    
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
            logger.error(f"Store display error: {e}", exc_info=True)
    
    def _should_show_app(self, app):
        """Check if app should be shown based on filters"""
        try:
            # Search filter
            search_term = self.search_var.get().lower()
            if search_term and search_term not in app['app_name'].lower() and search_term not in app['category'].lower():
                return False
            
            # Category filter
            category_filter = self.category_var.get()
            if category_filter != "All":
                if app.get('is_mod', False) and category_filter == "Mod":
                    return True
                elif not app.get('is_mod', False) and category_filter == app['category']:
                    return True
                else:
                    return False
            
            return True
        except Exception as e:
            logger.error(f"App filter error: {e}", exc_info=True)
            return True
    
    def _show_store_error(self, error):
        """Show store error message"""
        try:
            for widget in self.store_scroll_frame.winfo_children():
                widget.destroy()
            
            tk.Label(self.store_scroll_frame, text=f"❌ Error loading store:\n{error}",
                    fg='#f44336', bg='#1e293b', font=('Arial', 12), justify='center').pack(pady=50)
        except Exception as e:
            logger.error(f"Store error display error: {e}", exc_info=True)

    # ===========================
    # EVENT HANDLERS
    # ===========================
    
    def add_app_dialog(self):
        """Show add application dialog"""
        self._show_add_dialog(is_mod=False)
    
    def add_mod_dialog(self):
        """Show add mod dialog"""
        self._show_add_dialog(is_mod=True)
    
    def _show_add_dialog(self, is_mod=False):
        """Show app/mod add dialog"""
        try:
            dialog_title = "Add Mod" if is_mod else "Add Application"
            
            file_path = filedialog.askopenfilename(
                title=f"Select {dialog_title}",
                filetypes=[
                    ("Python files", "*.py") if is_mod else ("Executable files", "*.exe *.app"),
                    ("Java files", "*.jar"),
                    ("All files", "*.*")
                ]
            )
            
            if file_path:
                dialog = tk.Toplevel(self.root)
                dialog.title(dialog_title)
                dialog.geometry("500x500")
                dialog.configure(bg='#1e293b')
                dialog.transient(self.root)
                dialog.grab_set()
                
                # Header
                header_color = '#FF6B35' if is_mod else '#4CAF50'
                tk.Label(dialog, text=f"{'🔧' if is_mod else '📱'} {dialog_title}", 
                        font=('Arial', 16, 'bold'), fg=header_color, bg='#1e293b').pack(pady=20)
                
                # Form
                form_frame = tk.Frame(dialog, bg='#1e293b')
                form_frame.pack(fill='both', expand=True, padx=20, pady=10)
                
                # Name
                tk.Label(form_frame, text="Name:", fg='white', bg='#1e293b').pack(anchor='w')
                name_entry = tk.Entry(form_frame, width=50, font=('Arial', 11))
                name_entry.pack(fill='x', pady=(0, 10))
                name_entry.insert(0, Path(file_path).stem)
                
                # Company
                tk.Label(form_frame, text="Company/Developer:", fg='white', bg='#1e293b').pack(anchor='w')
                company_entry = tk.Entry(form_frame, width=50, font=('Arial', 11))
                company_entry.pack(fill='x', pady=(0, 10))
                company_entry.insert(0, "Mod Author" if is_mod else "Local Developer")
                
                # Category
                tk.Label(form_frame, text="Category:", fg='white', bg='#1e293b').pack(anchor='w')
                category_var = tk.StringVar(value="Mod" if is_mod else "Utilities")
                category_combo = ttk.Combobox(form_frame, textvariable=category_var, width=47)
                if is_mod:
                    category_combo['values'] = ('Mod', 'Client Tool', 'Plugin', 'Utility')
                else:
                    category_combo['values'] = ('Games', 'Utilities', 'Development', 'Graphics', 'Network', 'Business')
                category_combo.pack(fill='x', pady=(0, 10))
                
                # Description
                tk.Label(form_frame, text="Description:", fg='white', bg='#1e293b').pack(anchor='w')
                desc_text = scrolledtext.ScrolledText(form_frame, height=6, wrap=tk.WORD)
                desc_text.pack(fill='x', pady=(0, 10))
                desc_text.insert('1.0', f"{'Mod' if is_mod else 'Application'} added from {file_path}")
                
                # Warning for mods
                if is_mod:
                    warning_frame = tk.Frame(form_frame, bg='#FF6B35', relief='raised', bd=2)
                    warning_frame.pack(fill='x', pady=10)
                    
                    tk.Label(warning_frame, text="⚠️ WARNING: DIRECT CLIENT ACCESS", 
                            font=('Arial', 12, 'bold'), fg='white', bg='#FF6B35').pack(pady=5)
                    tk.Label(warning_frame, text="This mod will have FULL access to modify the client GUI and functionality.\nIt can break the client - this is intentional for maximum flexibility.\nA backup will be offered before loading.",
                            fg='white', bg='#FF6B35', wraplength=400, justify='center').pack(pady=(0, 5))
                
                # Buttons
                button_frame = tk.Frame(form_frame, bg='#1e293b')
                button_frame.pack(fill='x', pady=20)
                
                def add_item():
                    try:
                        name = name_entry.get().strip()
                        company = company_entry.get().strip()
                        category = category_var.get()
                        description = desc_text.get('1.0', tk.END).strip()
                        
                        if name:
                            added_app = self.app_manager.add_app(file_path, name, category, company, is_mod)
                            if added_app:
                                messagebox.showinfo("Success", f"{dialog_title} added successfully!")
                                dialog.destroy()
                                if is_mod:
                                    self.refresh_mods()
                                else:
                                    self.refresh_apps()
                                
                                # Register with network - pass the actual app object
                                local_ip = self._get_local_ip()
                                download_url = f"http://{local_ip}:{CONFIG['WEBSERVER_PORT']}/grab?ack={added_app.app_token}"
                                # Make sure to pass the AppInfo object which has the correct is_mod value
                                self.discovery.register_app_availability(added_app, download_url)
                            else:
                                messagebox.showerror("Error", f"Failed to add {dialog_title.lower()}. It might already exist.")
                        else:
                            messagebox.showerror("Error", "Name is required")
                    except Exception as e:
                        logger.error(f"Add item error: {e}", exc_info=True)
                        messagebox.showerror("Error", f"Failed to add {dialog_title.lower()}: {e}")
                
                button_color = '#FF6B35' if is_mod else '#4CAF50'
                tk.Button(button_frame, text=f"Add {dialog_title}", command=add_item,
                         bg=button_color, fg='white', font=('Arial', 12, 'bold')).pack(side='left')
                
                tk.Button(button_frame, text="Cancel", command=dialog.destroy,
                         bg='#6c757d', fg='white', font=('Arial', 12)).pack(side='right')
                         
        except Exception as e:
            logger.error(f"Add dialog error: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to open add dialog: {e}")
    
    def launch_app(self, app_id: str):
        """Launch application or load mod"""
        try:
            app = self.app_manager.apps.get(app_id)
            if not app:
                messagebox.showerror("Launch Error", "Item not found.")
                return

            success = self.app_manager.launch_app(app_id, self.on_app_usage_update, gui_instance=self)
            if success:
                item_type = "mod" if app.is_mod else "application"
                self.status_label.config(text=f"{'Loaded' if app.is_mod else 'Launched'}: {app.name}")
                if app.is_mod:
                    # Refresh the mods display since the mod might have modified the GUI
                    self.root.after(1000, self.refresh_mods)
            else:
                item_type = "mod" if app.is_mod else "application"
                messagebox.showerror("Launch Error", f"Failed to {'load' if app.is_mod else 'launch'} {app.name}. Check logs for details.")
        except Exception as e:
            logger.error(f"Launch error: {e}", exc_info=True)
            messagebox.showerror("Launch Error", f"Failed to launch item: {e}")

    def on_app_usage_update(self, app_id: str, duration: float):
        """Handle app usage update"""
        try:
            app = self.app_manager.apps.get(app_id)
            if app:
                self.status_label.config(text=f"Session ended: {app.name} ({duration:.1f}s)")
                if app.is_mod:
                    self.refresh_mods()
                else:
                    self.refresh_apps()
        except Exception as e:
            logger.error(f"Usage update error: {e}", exc_info=True)

    def scan_for_new_mods(self):
        """Trigger mod loader to scan for new mods"""
        try:
            new_mods = self.mod_loader.scan_for_new_mods()
            if new_mods:
                messagebox.showinfo("Mod Scan Complete", f"Found and registered {len(new_mods)} new mods!")
                self.refresh_mods()
            else:
                messagebox.showinfo("Mod Scan Complete", "No new mods found in the mods directory.")
        except Exception as e:
            logger.error(f"Error during mod scan: {e}", exc_info=True)
            messagebox.showerror("Mod Scan Error", f"Failed to scan for new mods: {e}")

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
            logger.error(f"Node refresh error: {e}", exc_info=True)
    
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
                
                last_seen_dt = datetime.fromtimestamp(node.last_seen)
                now = datetime.now()
                delta = now - last_seen_dt
                
                if delta.total_seconds() < 60:
                    last_seen_str = f"{int(delta.total_seconds())}s ago"
                elif delta.total_seconds() < 3600:
                    last_seen_str = f"{int(delta.total_seconds() / 60)}m ago"
                elif delta.total_seconds() < 86400:
                    last_seen_str = f"{int(delta.total_seconds() / 3600)}h ago"
                else:
                    last_seen_str = last_seen_dt.strftime('%Y-%m-%d %H:%M')

                self.nodes_tree.insert('', 'end', node.node_id,
                                     text=node.node_id[:12] + "...",
                                     values=(node.username, f"{status_icon} {node.status.title()}", 
                                            node.apps_count, chat_status, last_seen_str))
        except Exception as e:
            logger.error(f"Nodes display update error: {e}", exc_info=True)
    
    def _update_chat_targets_safe(self):
        """Update chat target dropdown safely"""
        try:
            targets = ['Broadcast']
            for node in self.connected_nodes.values():
                if node.chat_enabled:
                    targets.append(f"{node.username} ({node.node_id[:8]})")
            
            current_selection = self.chat_target_var.get()
            self.chat_target_combo['values'] = targets
            if current_selection in targets:
                self.chat_target_var.set(current_selection)
            else:
                self.chat_target_var.set('Broadcast')
        except Exception as e:
            logger.error(f"Chat targets update error: {e}", exc_info=True)
    
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
                    self.notebook.select(self.notebook.index("💬 Chat"))
                    self.chat_entry.focus()
        except Exception as e:
            logger.error(f"Node double-click error: {e}", exc_info=True)

    # ===========================
    # CHAT SYSTEM
    # ===========================
    
    @safe_thread_wrapper
    def check_chat_messages_safe(self):
        """Check chat messages with error handling"""
        try:
            since_timestamp_dt = datetime.fromtimestamp(self.last_chat_check, tz=timezone.utc)
            since_timestamp_str = since_timestamp_dt.strftime('%Y-%m-%d %H:%M:%S')
            
            messages = self.discovery.get_chat_messages(since_timestamp_str)
            
            if messages:
                for msg in messages:
                    self.root.after(0, lambda m=msg: self._display_chat_message_safe(m))
                self.last_chat_check = time.time()
                
        except Exception as e:
            logger.error(f"Chat check error: {e}", exc_info=True)
    
    def _display_chat_message_safe(self, message):
        """Display chat message with error handling"""
        try:
            msg_type = message['type']
            sender = message['username']
            content = message['content']
            timestamp = message['timestamp']
            
            if isinstance(timestamp, datetime):
                timestamp_str = timestamp.strftime('%H:%M:%S')
            elif isinstance(timestamp, str):
                timestamp_str = timestamp.split(' ')[-1][:8]
            else:
                timestamp_str = "Unknown Time"
            
            if msg_type == 'broadcast':
                self.add_chat_message(f"{sender} (Broadcast)", content, "broadcast", timestamp_str)
            else:
                self.add_chat_message(sender, content, "received", timestamp_str)
        except Exception as e:
            logger.error(f"Chat display error: {e}", exc_info=True)
    
    def send_chat_message(self, event=None):
        """Send chat message"""
        try:
            message = self.chat_entry.get().strip()
            if not message:
                return
            
            target_display_name = self.chat_target_var.get()
            
            if target_display_name == "Broadcast":
                message_type = "broadcast"
                target_node_id = None
                display_target = "Broadcast"
            else:
                message_type = "direct"
                target_node_id_prefix = target_display_name.split('(')[-1].split(')')[0]
                target_node_id = None
                for node_id, node_info in self.connected_nodes.items():
                    if node_id.startswith(target_node_id_prefix):
                        target_node_id = node_id
                        break
                
                if not target_node_id:
                    messagebox.showerror("Chat Error", "Selected recipient not found or offline.")
                    return
                display_target = target_display_name.split(' (')[0]
            
            success = self.discovery.send_chat_message(message, target_node_id, message_type)
            
            if success:
                if message_type == "broadcast":
                    self.add_chat_message("You (Broadcast)", message, "sent")
                else:
                    self.add_chat_message(f"You → {display_target}", message, "sent")
                
                self.chat_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Chat Error", "Failed to send message.")
                
        except Exception as e:
            logger.error(f"Send chat message error: {e}", exc_info=True)
            messagebox.showerror("Chat Error", f"Failed to send message: {e}")
    
    def add_chat_message(self, sender: str, message: str, msg_type: str = "received", timestamp: str = None):
        """Add message to chat display"""
        try:
            if not timestamp:
                timestamp = datetime.now().strftime('%H:%M:%S')
            
            self.chat_text.config(state='normal')
            
            colors = {
                "system": "#ffa500",
                "broadcast": "#4CAF50",
                "direct": "#2196F3",
                "sent": "#FF9800",
                "received": "#e2e8f0"
            }
            
            color = colors.get(msg_type, "#e2e8f0")
            
            self.chat_text.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
            
            line_start = self.chat_text.index("end-2c linestart")
            line_end = self.chat_text.index("end-2c lineend")
            
            tag_name = f"msg_{msg_type}_{int(time.time() * 1000)}"
            self.chat_text.tag_add(tag_name, line_start, line_end)
            self.chat_text.tag_config(tag_name, foreground=color)
            
            self.chat_text.config(state='disabled')
            self.chat_text.see(tk.END)
            
        except Exception as e:
            logger.error(f"Add chat message error: {e}", exc_info=True)

    # ===========================
    # CPU EMULATOR METHODS
    # ===========================
    
    def run_cpu_program(self):
        """Run CPU program"""
        try:
            code = self.cpu_code_text.get('1.0', tk.END).strip()
            
            bytecode = self.cpu.assemble(code)
            
            self.cpu.load_program(bytecode)
            cycles = self.cpu.run(max_cycles=1000)
            
            self.update_cpu_display()
            self.status_label.config(text=f"CPU program executed ({cycles} cycles)")
            
        except Exception as e:
            logger.error(f"CPU run error: {e}", exc_info=True)
            messagebox.showerror("CPU Error", f"Execution failed: {e}")
    
    def step_cpu(self):
        """Step CPU one instruction"""
        try:
            if not hasattr(self.cpu, 'program') or not self.cpu.program:
                code = self.cpu_code_text.get('1.0', tk.END).strip()
                if not code:
                    messagebox.showwarning("CPU Warning", "No assembly code to load.")
                    return
                bytecode = self.cpu.assemble(code)
                self.cpu.load_program(bytecode)
            
            if self.cpu.running:
                if self.cpu.step():
                    self.update_cpu_display()
                    self.status_label.config(text="CPU stepped one instruction")
                else:
                    self.status_label.config(text="CPU execution completed")
            else:
                self.status_label.config(text="CPU is halted. Reset to run again.")
                
        except Exception as e:
            logger.error(f"CPU step error: {e}", exc_info=True)
            messagebox.showerror("CPU Error", f"Step failed: {e}")
    
    def reset_cpu(self):
        """Reset CPU state"""
        try:
            self.cpu = CPU8BitEmulator()
            self.update_cpu_display()
            self.status_label.config(text="CPU reset")
        except Exception as e:
            logger.error(f"CPU reset error: {e}", exc_info=True)
    
    def update_cpu_display(self):
        """Update CPU state display"""
        try:
            state = self.cpu.get_state()
            
            for reg, value in state['registers'].items():
                self.cpu_reg_labels[reg].config(text=str(value))
            
            self.cpu_state_labels['PC'].config(text=str(state['pc']))
            self.cpu_state_labels['SP'].config(text=str(state['sp']))
            
            for flag, value in state['flags'].items():
                self.cpu_flag_labels[flag].config(
                    text="1" if value else "0",
                    fg='#4CAF50' if value else '#f44336'
                )
            
            self.cpu_memory_text.config(state='normal')
            self.cpu_memory_text.delete('1.0', tk.END)
            
            memory_view = ""
            for i in range(0, 16, 4):
                row = f"0x{i:02X}: "
                for j in range(4):
                    addr = i + j
                    if addr < len(self.cpu.memory):
                        row += f"{self.cpu.memory[addr]:02X} "
                    else:
                        row += "?? "
                memory_view += row + "\n"
            
            self.cpu_memory_text.insert('1.0', memory_view)
            self.cpu_memory_text.config(state='disabled')
            
        except Exception as e:
            logger.error(f"CPU display update error: {e}", exc_info=True)

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
            if hasattr(self, 'store_scroll_frame'):
                self.root.after(100, self.refresh_store)
        except Exception as e:
            logger.error(f"Search change error: {e}", exc_info=True)
    
    def on_category_change(self, event):
        """Handle category filter change"""
        try:
            self.refresh_store()
        except Exception as e:
            logger.error(f"Category change error: {e}", exc_info=True)
    
    def download_app_from_store(self, app_data):
        """Download app from store"""
        try:
            download_url = app_data['download_url']
            is_mod = app_data.get('is_mod', False) # This should now be a correct boolean
            
            self.status_label.config(text=f"Downloading: {app_data['app_name']}...")
            self.root.update_idletasks()
            
            response = requests.get(download_url, timeout=30)
            if response.status_code == 200:
                received_hash = hashlib.md5(response.content).hexdigest()
                expected_hash = app_data['file_hash']
                
                if received_hash == expected_hash:
                    # Get appropriate extension
                    extension = '.py' if is_mod else '.exe'
                    filename = f"{app_data['app_name']}{extension}"
                    # Correctly determine target directory based on is_mod
                    file_path = (self.app_manager.mods_dir if is_mod else self.app_manager.apps_dir) / filename
                    
                    with open(file_path, 'wb') as f:
                        f.write(response.content)
                    
                    added_app = self.app_manager.add_app(
                        str(file_path), 
                        app_data['app_name'], 
                        app_data['category'],
                        app_data.get('company', 'Downloaded'),
                        is_mod=is_mod # Pass the correct boolean value
                    )
                    
                    if added_app:
                        item_type = "mod" if is_mod else "application"
                        messagebox.showinfo("Success", f"Downloaded and installed {item_type}: {app_data['app_name']}")
                        if is_mod:
                            self.refresh_mods()
                            self.notebook.select(self.notebook.index("🔧 Mods"))
                        else:
                            self.refresh_apps()
                            self.notebook.select(self.notebook.index("📱 Applications"))
                    else:
                        messagebox.showwarning("Warning", f"Downloaded '{app_data['app_name']}' but failed to register it.")

                else:
                    messagebox.showerror("Error", "File verification failed - corrupt download.")
            else:
                messagebox.showerror("Error", f"Download failed: HTTP {response.status_code}")
                
            self.status_label.config(text="Ready")
        except Exception as e:
            logger.error(f"Download error: {e}", exc_info=True)
            messagebox.showerror("Download Error", f"Failed to download: {e}")
            self.status_label.config(text="Download failed")
    
    def open_portal(self):
        """Open web portal"""
        try:
            portal_url = CONFIG['PORTAL_URL']
            auth_params = urllib.parse.urlencode(self.auth.get_auth_headers())
            full_url = f"{portal_url}?{auth_params}"
            webbrowser.open(full_url)
        except Exception as e:
            logger.error(f"Open portal error: {e}", exc_info=True)
            messagebox.showerror("Portal Error", f"Failed to open portal: {e}")
    
    def clear_chat(self):
        """Clear chat display"""
        try:
            self.chat_text.config(state='normal')
            self.chat_text.delete('1.0', tk.END)
            self.chat_text.config(state='disabled')
            self.add_chat_message("System", "Chat cleared", "system")
        except Exception as e:
            logger.error(f"Clear chat error: {e}", exc_info=True)
    
    def show_about(self):
        """Show about dialog"""
        try:
            about_text = f"""MonsterApps Enhanced Client - Direct Mod Access
Version: 2024.1 Advanced

🚀 Features:
• P2P App & Mod Distribution
• MySQL-based Node Discovery  
• Real-time Network Chat
• 8-bit CPU Emulator & Assembler
• Direct Mod Access (Mods can modify anything!)
• Usage Tracking & Badges

⚠️ MOD WARNING:
Mods have FULL access to modify the client.
They can break the client - this is by design.

🔧 Your Node:
• ID: {self.auth.node_id}
• Username: {self.auth.username}
• Web Server: Port {CONFIG['WEBSERVER_PORT']}
• Applications: {len(self.app_manager.get_applications())}
• Mods: {len(self.app_manager.get_mods())}

Visit: {CONFIG['PORTAL_URL']}"""
            
            messagebox.showinfo("About MonsterApps", about_text)
        except Exception as e:
            logger.error(f"Show about error: {e}", exc_info=True)
    
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
• JNZ addr          - Jump if not zero
• CMP reg, value    - Compare and set flags

SYSTEM:
• HALT              - Stop execution
• NOP               - No operation

REGISTERS: A, B, C, D (8-bit each)
MEMORY: 256 bytes (0-255)
STACK: Grows downward from address 255"""
            
            messagebox.showinfo("CPU Instruction Set", help_text)
        except Exception as e:
            logger.error(f"Show CPU help error: {e}", exc_info=True)
    
    def edit_app_details(self, app_id: str):
        """Edit app details dialog"""
        try:
            messagebox.showinfo("Feature", "Edit details dialog would open here")
        except Exception as e:
            logger.error(f"Edit details error: {e}", exc_info=True)
    
    def show_detailed_stats(self, app_id: str):
        """Show detailed app statistics"""
        try:
            stats = self.app_manager.get_app_stats(app_id)
            if stats:
                item_type = "Mod" if stats['is_mod'] else "Application"
                stats_text = f"""{item_type} Statistics for {stats['name']}:

Type: {item_type}
Launches: {stats['launch_count']}
Usage Time: {self._format_time(stats['total_usage_time'])}
Downloads: {stats['downloads']}
Rating: {stats['rating']:.1f}/5.0
Badges: {', '.join(stats['badges']) if stats['badges'] else 'None'}
Created: {datetime.fromtimestamp(stats['created_at']).strftime('%Y-%m-%d %H:%M')}"""
                messagebox.showinfo(f"Stats: {stats['name']}", stats_text)
            else:
                messagebox.showwarning("Stats Error", "Could not retrieve statistics.")
        except Exception as e:
            logger.error(f"Show detailed stats error: {e}", exc_info=True)
    
    def share_app_to_network(self, app_id: str):
        """Share app to network"""
        try:
            if app_id not in self.app_manager.apps:
                messagebox.showerror("Share Error", "Item not found.")
                return
            
            app = self.app_manager.apps[app_id]

            local_ip = self._get_local_ip()
            download_url = f"http://{local_ip}:{CONFIG['WEBSERVER_PORT']}/grab?ack={app.app_token}"
            
            if self.discovery.register_app_availability(app, download_url):
                item_type = "mod" if app.is_mod else "application"
                messagebox.showinfo("Success", f"'{app.name}' ({item_type}) is now shared on the network!")
            else:
                messagebox.showerror("Error", "Failed to share to network.")
                
        except Exception as e:
            logger.error(f"Share app error: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to share: {e}")
    
    def remove_app(self, app_id: str):
        """Remove app/mod with confirmation"""
        try:
            if app_id not in self.app_manager.apps:
                messagebox.showerror("Remove Error", "Item not found.")
                return
            
            app = self.app_manager.apps[app_id]
            
            item_type = "mod" if app.is_mod else "application"
            result = messagebox.askyesno("Confirm Removal", 
                                       f"Are you sure you want to remove the {item_type} '{app.name}'?\n\n"
                                       "This will delete the file from the managed directory.")
            
            if result:
                if self.app_manager.remove_app(app_id):
                    messagebox.showinfo("Removed", f"'{app.name}' ({item_type}) has been removed.")
                    if app.is_mod:
                        self.refresh_mods()
                    else:
                        self.refresh_apps()
                else:
                    messagebox.showerror("Error", f"Failed to remove {item_type}.")
        except Exception as e:
            logger.error(f"Remove error: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to remove item: {e}")
    
    def generate_invite_link(self):
        """Generate network invite link"""
        try:
            invite_link = f"{CONFIG['PORTAL_URL']}?invite={self.auth.client_token[:16]}"
            messagebox.showinfo("Invite Link", f"Share this link:\n{invite_link}")
        except Exception as e:
            logger.error(f"Generate invite link error: {e}", exc_info=True)
    
    def show_network_status(self):
        """Show detailed network status"""
        try:
            status_text = f"""Network Status:

Connected Nodes: {len(self.connected_nodes)}
Database: {'Connected' if self.discovery.db.is_available() else 'Fallback Mode'}
Web Server: Running on port {CONFIG['WEBSERVER_PORT']}
Applications Shared: {len(self.app_manager.get_applications())}
Mods Shared: {len(self.app_manager.get_mods())}"""
            messagebox.showinfo("Network Status", status_text)
        except Exception as e:
            logger.error(f"Show network status error: {e}", exc_info=True)
    
    def create_backup(self):
        """Create client backup"""
        try:
            backup_created = self.app_manager._create_client_backup()
            if backup_created:
                messagebox.showinfo("Backup Created", "Client backup created successfully!")
            else:
                messagebox.showerror("Error", "Failed to create backup.")
        except Exception as e:
            logger.error(f"Create backup error: {e}", exc_info=True)
            messagebox.showerror("Backup Error", f"Backup failed: {e}")
    
    def restore_backup(self):
        """Restore from backup"""
        try:
            messagebox.showinfo("Feature", "Backup restore functionality would be implemented here.")
        except Exception as e:
            logger.error(f"Restore backup error: {e}", exc_info=True)
    
    def on_closing(self):
        """Handle application closing with proper cleanup"""
        try:
            if messagebox.askyesno("Exit", "Exit MonsterApps Enhanced Client?"):
                logger.info("Application shutting down...")
                
                try:
                    if hasattr(self, 'web_server') and self.web_server.server_thread and self.web_server.server_thread.is_alive():
                        self.web_server.stop()
                        self.web_server.server_thread.join(timeout=5)
                    
                    if hasattr(self, 'discovery') and self.discovery.db:
                        try:
                            self.discovery.db.execute(
                                "UPDATE mesh_nodes SET status = 'offline' WHERE node_id = %s", 
                                (self.auth.node_id,)
                            )
                        except Exception as db_e:
                            logger.error(f"Failed to set node offline: {db_e}")
                        self.discovery.db.close()
                    
                    logger.info("Services stopped successfully")
                    
                except Exception as e:
                    logger.error(f"Error stopping services: {e}", exc_info=True)
                
                self.root.destroy()
                sys.exit(0)
                
        except Exception as e:
            logger.error(f"Shutdown error: {e}", exc_info=True)
            self.root.destroy()
            sys.exit(1)

def main():
    """Main application entry point"""
    try:
        logger.info("Starting Enhanced MonsterApps Client with Direct Mod Access...")
        
        if not MYSQL_AVAILABLE:
            logger.warning("MySQL not available - limited functionality")
        
        if not CRYPTO_AVAILABLE:
            logger.warning("Cryptography not available - using fallback")
        
        # Create data directories
        for directory in ['monsterapps_data', 
                         os.path.join('monsterapps_data', CONFIG['APPS_DIR']), 
                         os.path.join('monsterapps_data', CONFIG['MODS_DIR']), 
                         os.path.join('monsterapps_data', CONFIG['BACKUPS_DIR']),
                         os.path.join('monsterapps_data', CONFIG['UPLOAD_PATH'])]:
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
                pass
        
        sys.excepthook = handle_exception
        
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
