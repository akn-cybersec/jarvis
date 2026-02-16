#!/usr/bin/env python3
"""
JARVIS - Just A Rather Very Intelligent System
Kali Linux Optimized AI Personal Assistant with Async App Launching
Security-focused assistant for penetration testing and system management
Enhanced with tool installation, better UI, and hacker vibes
"""

import os
import json
import datetime
import subprocess
import platform
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional, Any
import pickle
import random
import re
import shutil
import getpass
import threading
import time
import urllib.parse
import psutil
import socket
import netifaces
import sys

# ==================== KALI CONFIGURATION ====================
class Config:
    ASSISTANT_NAME = "JARVIS"
    USER_NAME = "kaizen"  # Your Kali username
    HOSTNAME = "dragon"    # Your hostname
    DATA_FILE = os.path.expanduser("~/.jarvis_kali_memory.pkl")
    HISTORY_FILE = os.path.expanduser("~/.jarvis_kali_history.json")
    VERSION = "2.0.0-KALI-H4X0R"
    
    # Kali-specific directories
    KALI_TOOLS_DIRS = [
        "/usr/share",
        "/usr/bin",
        "/usr/sbin",
        "/opt",
        "~/tools",
        "~/git",
        "~/Desktop",
        "~/Downloads",
    ]
    
    # Indexed directories for file search
    INDEXED_DIRS = [
        os.path.expanduser("~"),
        "/etc",
        "/var/log",
        "/usr/share/wordlists",
        "/usr/share/seclists",
        f"/home/{USER_NAME}/Desktop",
        f"/home/{USER_NAME}/Downloads",
        f"/home/{USER_NAME}/Documents",
    ]
    
    INDEXED_DIRS = [d for d in INDEXED_DIRS if d and os.path.exists(os.path.expanduser(d))]
    
    # Kali Linux application paths and tools
    APP_PATHS = {
        # Browsers
        'firefox': ['firefox', 'firefox-esr'],
        'chrome': ['google-chrome', 'google-chrome-stable', 'chromium'],
        'chromium': ['chromium', 'chromium-browser'],
        'brave': ['brave-browser'],
        
        # Terminals
        'terminal': ['gnome-terminal', 'konsole', 'xfce4-terminal', 'mate-terminal'],
        'tmux': ['tmux'],
        'screen': ['screen'],
        
        # Text editors
        'vim': ['vim', 'vim.gtk3', 'vim.tiny'],
        'nano': ['nano'],
        'gedit': ['gedit'],
        'code': ['code', 'codium'],
        'vscode': ['code'],
        
        # File managers
        'nautilus': ['nautilus'],
        'thunar': ['thunar'],
        'pcmanfm': ['pcmanfm'],
        'dolphin': ['dolphin'],
        
        # System tools
        'htop': ['htop'],
        'top': ['gnome-system-monitor', 'ksysguard'],
        'calculator': ['gnome-calculator', 'kcalc', 'qalculate-gtk'],
        
        # Security tools - Pentesting Suite
        'nmap': ['nmap'],
        'wireshark': ['wireshark', 'wireshark-gtk'],
        'burpsuite': ['burpsuite'],
        'metasploit': ['msfconsole'],
        'sqlmap': ['sqlmap'],
        'hydra': ['hydra'],
        'john': ['john'],
        'aircrack': ['aircrack-ng'],
        'bettercap': ['bettercap'],
        'beef': ['beef-xss'],
        'zap': ['zaproxy'],
        'maltego': ['maltego'],
        'nessus': ['nessus'],
        'openvas': ['gvm'],
        
        # Network tools
        'netdiscover': ['netdiscover'],
        'masscan': ['masscan'],
        'zenmap': ['zenmap'],
        'responder': ['responder'],
        'mitmproxy': ['mitmproxy'],
        
        # Exploitation tools
        'searchsploit': ['searchsploit'],
        'msfconsole': ['msfconsole'],
        'msfvenom': ['msfvenom'],
        'armitage': ['armitage'],
        
        # Password tools
        'hashcat': ['hashcat'],
        'cewl': ['cewl'],
        'crunch': ['crunch'],
        
        # Web tools
        'gobuster': ['gobuster'],
        'dirb': ['dirb'],
        'dirbuster': ['dirbuster'],
        'nikto': ['nikto'],
        'whatweb': ['whatweb'],
        'wpscan': ['wpscan'],
        'joomscan': ['joomscan'],
        
        # Wireless tools
        'wifite': ['wifite'],
        'kismet': ['kismet'],
        'reaver': ['reaver'],
        'bully': ['bully'],
        
        # Forensics tools
        'autopsy': ['autopsy'],
        'sleuthkit': ['tsk_recover'],
        'foremost': ['foremost'],
        'binwalk': ['binwalk'],
        
        # Reverse engineering
        'ghidra': ['ghidra'],
        'radare2': ['radare2'],
        'gdb': ['gdb'],
        'edb': ['edb-debugger'],
        
        # Social engineering
        'setoolkit': ['setoolkit'],
        'gophish': ['gophish'],
        
        # Reporting
        'faraday': ['faraday'],
        'dradis': ['dradis'],
        
        # Entertainment
        'spotify': ['spotify'],
        'vlc': ['vlc'],
        'discord': ['discord'],
        'telegram': ['telegram-desktop'],
        
        # Productivity
        'obsidian': ['obsidian'],
        'notion': ['notion'],
    }
    
    # Installable tools (apt packages)
    INSTALLABLE_TOOLS = {
        'nmap': 'nmap',
        'wireshark': 'wireshark',
        'burpsuite': 'burpsuite',
        'metasploit': 'metasploit-framework',
        'sqlmap': 'sqlmap',
        'hydra': 'hydra',
        'john': 'john',
        'aircrack': 'aircrack-ng',
        'bettercap': 'bettercap',
        'beef': 'beef-xss',
        'zap': 'zaproxy',
        'gobuster': 'gobuster',
        'nikto': 'nikto',
        'wpscan': 'wpscan',
        'dirb': 'dirb',
        'hashcat': 'hashcat',
        'cewl': 'cewl',
        'crunch': 'crunch',
        'netdiscover': 'netdiscover',
        'masscan': 'masscan',
        'responder': 'responder',
        'wifite': 'wifite',
        'kismet': 'kismet',
        'reaver': 'reaver',
        'bully': 'bully',
        'foremost': 'foremost',
        'binwalk': 'binwalk',
        'radare2': 'radare2',
        'gdb': 'gdb',
        'seclists': 'seclists',  # Wordlists
        'chrome': 'google-chrome-stable',
        'firefox': 'firefox-esr',
        'vlc': 'vlc',
        'spotify': 'spotify-client',
        'discord': 'discord',
        'telegram': 'telegram-desktop',
        'code': 'code',  # VSCode
        'git': 'git',
        'python3': 'python3',
        'python3-pip': 'python3-pip',
        'docker': 'docker.io',
        'docker-compose': 'docker-compose',
    }

# ==================== KALI UTILITIES ====================
class KaliUtils:
    @staticmethod
    def is_kali() -> bool:
        """Check if running on Kali Linux"""
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    if 'kali' in content:
                        return True
            
            kali_indicators = [
                '/usr/share/kali-defaults',
                '/etc/kali-motd',
                '/usr/bin/nmap',
                '/usr/bin/msfconsole',
            ]
            
            for indicator in kali_indicators:
                if os.path.exists(indicator):
                    return True
                    
        except:
            pass
        
        return False
    
    @staticmethod
    def check_root() -> bool:
        """Check if running as root"""
        try:
            return os.geteuid() == 0
        except:
            return False
    
    @staticmethod
    def get_network_interfaces() -> List[Dict]:
        """Get network interface information"""
        interfaces = []
        try:
            for iface in netifaces.interfaces():
                iface_info = {'name': iface}
                
                addrs = netifaces.ifaddresses(iface)
                
                if netifaces.AF_INET in addrs:
                    iface_info['ipv4'] = addrs[netifaces.AF_INET][0]['addr']
                    iface_info['netmask'] = addrs[netifaces.AF_INET][0].get('netmask', '')
                
                if netifaces.AF_INET6 in addrs:
                    iface_info['ipv6'] = addrs[netifaces.AF_INET6][0]['addr']
                
                if netifaces.AF_LINK in addrs:
                    iface_info['mac'] = addrs[netifaces.AF_LINK][0]['addr']
                
                if iface != 'lo' or len(interfaces) == 0:
                    interfaces.append(iface_info)
                    
        except:
            pass
            
        return interfaces
    
    @staticmethod
    def get_system_resources() -> Dict:
        """Get system resource usage"""
        resources = {}
        
        try:
            resources['cpu_percent'] = psutil.cpu_percent(interval=1)
            resources['cpu_count'] = psutil.cpu_count()
            resources['cpu_freq'] = psutil.cpu_freq().current if psutil.cpu_freq() else None
            
            mem = psutil.virtual_memory()
            resources['memory_total'] = mem.total
            resources['memory_available'] = mem.available
            resources['memory_percent'] = mem.percent
            resources['memory_used'] = mem.used
            
            disk = psutil.disk_usage('/')
            resources['disk_total'] = disk.total
            resources['disk_used'] = disk.used
            resources['disk_free'] = disk.free
            resources['disk_percent'] = disk.percent
            
            net = psutil.net_io_counters()
            resources['net_sent'] = net.bytes_sent
            resources['net_recv'] = net.bytes_recv
            
        except:
            pass
            
        return resources
    
    @staticmethod
    def check_tool_installed(tool_name: str) -> bool:
        """Check if a security tool is installed"""
        # Check common paths
        paths = [
            f"/usr/bin/{tool_name}",
            f"/usr/sbin/{tool_name}",
            f"/opt/{tool_name}/{tool_name}",
            f"/usr/share/{tool_name}/{tool_name}",
            f"/home/kaizen/.local/bin/{tool_name}",
        ]
        
        for path in paths:
            if os.path.exists(path):
                return True
        
        # Check with which command
        try:
            result = subprocess.run(['which', tool_name], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return True
        except:
            pass
            
        return False
    
    @staticmethod
    def install_tool(tool_name: str) -> bool:
        """Install a tool using apt"""
        if tool_name not in Config.INSTALLABLE_TOOLS:
            return False
        
        package = Config.INSTALLABLE_TOOLS[tool_name]
        
        try:
            # Update package list first
            subprocess.run(['sudo', 'apt', 'update'], check=False)
            
            # Install the package
            result = subprocess.run(['sudo', 'apt', 'install', '-y', package], 
                                  capture_output=True, text=True)
            
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def get_wordlist_paths() -> List[str]:
        """Get common wordlist paths in Kali"""
        wordlists = []
        base_paths = [
            "/usr/share/wordlists",
            "/usr/share/seclists",
            "/usr/share/dirb/wordlists",
            "/usr/share/nmap/nselib/data",
            "/usr/share/sqlmap/data/txt",
        ]
        
        for base in base_paths:
            if os.path.exists(base):
                wordlists.append(base)
                
        return wordlists
    
    @staticmethod
    def open_folder(path: str = None) -> bool:
        """Open a folder in file manager"""
        if path is None:
            path = f"/home/{Config.USER_NAME}"
        elif path.startswith("~"):
            path = os.path.expanduser(path)
        elif not path.startswith("/"):
            path = f"/home/{Config.USER_NAME}/{path}"
        
        try:
            if os.path.exists(path):
                subprocess.Popen(['nautilus', path])
                return True
            else:
                return False
        except:
            try:
                subprocess.Popen(['thunar', path])
                return True
            except:
                return False

# ==================== MEMORY SYSTEM ====================
class Memory:
    def __init__(self):
        self.data_file = Config.DATA_FILE
        self.memory = self.load_memory()
        
    def load_memory(self) -> Dict:
        """Load memory from file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            print(f"[-] Note: Could not load memory: {e}")
        
        return self.default_memory()
    
    def default_memory(self) -> Dict:
        """Create default memory structure for Kali"""
        return {
            'user_preferences': {
                'favorite_tools': [],
                'favorite_apps': [],
                'work_mode': 'pentest',
                'project_paths': {},
                'target_networks': [],
                'aliases': {
                    'code': 'vscode',
                    'editor': 'vim',
                    'browser': 'firefox',
                    'terminal': 'terminal',
                    'scanner': 'nmap',
                    'exploit': 'metasploit',
                    'crack': 'john',
                    'webscan': 'nikto',
                    'wifi': 'aircrack',
                    'recon': 'nmap',
                    'enum': 'enum4linux',
                    'dirbust': 'gobuster',
                    'revshell': 'msfvenom',
                    'hack': 'metasploit',
                    'pwn': 'metasploit',
                },
            },
            'security_context': {
                'current_target': None,
                'recent_scan_results': [],
                'saved_wordlists': [],
                'custom_scripts': [],
            },
            'conversation_history': [],
            'file_index': {},
            'learned_commands': {},
            'system_info': self.get_system_info(),
            'created': datetime.datetime.now().isoformat(),
            'last_updated': datetime.datetime.now().isoformat(),
        }
    
    def get_system_info(self) -> Dict:
        """Get Kali Linux system information"""
        info = {
            'os': platform.system(),
            'os_version': platform.release(),
            'platform': platform.platform(),
            'username': get_username(),
            'hostname': Config.HOSTNAME,
            'home_dir': get_home_directory(),
            'python_version': platform.python_version(),
            'jarvis_version': Config.VERSION,
            'is_kali': KaliUtils.is_kali(),
            'is_root': KaliUtils.check_root(),
            'architecture': platform.machine(),
        }
        
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            info['kali_version'] = line.split('=')[1].strip().strip('"')
                            break
        except:
            info['kali_version'] = 'Unknown'
        
        info['interfaces'] = KaliUtils.get_network_interfaces()
        info['resources'] = KaliUtils.get_system_resources()
        
        return info
    
    def save(self):
        """Save memory to file"""
        self.memory['last_updated'] = datetime.datetime.now().isoformat()
        try:
            with open(self.data_file, 'wb') as f:
                pickle.dump(self.memory, f)
        except Exception as e:
            print(f"[-] Could not save memory: {e}")
    
    def remember(self, key: str, value: Any):
        """Remember something"""
        keys = key.split('.')
        data = self.memory
        for k in keys[:-1]:
            if k not in data:
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value
        self.save()
    
    def recall(self, key: str, default=None) -> Any:
        """Recall something from memory"""
        keys = key.split('.')
        data = self.memory
        for k in keys:
            if isinstance(data, dict) and k in data:
                data = data[k]
            else:
                return default
        return data
    
    def add_conversation(self, user_input: str, response: str):
        """Add conversation to history"""
        self.memory['conversation_history'].append({
            'timestamp': datetime.datetime.now().isoformat(),
            'user': user_input,
            'jarvis': response,
        })
        if len(self.memory['conversation_history']) > 100:
            self.memory['conversation_history'] = self.memory['conversation_history'][-100:]
        self.save()

# ==================== APPLICATION MANAGER ====================
class AppManager:
    def __init__(self, memory: Memory):
        self.memory = memory
        
    def find_application(self, app_name: str) -> Optional[str]:
        """Find an application in Kali Linux"""
        app_name = app_name.strip().lower()
        
        aliases = self.memory.recall('user_preferences.aliases', {})
        if app_name in aliases:
            app_name = aliases[app_name]
        
        if app_name in Config.APP_PATHS:
            for app_cmd in Config.APP_PATHS[app_name]:
                try:
                    result = subprocess.run(['which', app_cmd], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        return result.stdout.strip()
                except:
                    pass
                
                if os.path.exists(app_cmd):
                    return app_cmd
        
        return None
    
    def launch_application_async(self, app_name: str) -> bool:
        """Launch an application asynchronously"""
        app_name = app_name.strip().lower()
        
        if app_name in ['firefox', 'chrome', 'chromium', 'browser', 'brave']:
            return self.launch_browser_async()
        
        if app_name in ['youtube', 'yt']:
            return self.launch_browser_async("https://youtube.com")
        
        if app_name in ['github', 'gh']:
            return self.launch_browser_async("https://github.com")
        
        if app_name in ['hackthebox', 'htb']:
            return self.launch_browser_async("https://www.hackthebox.com")
        
        if app_name in ['tryhackme', 'thm']:
            return self.launch_browser_async("https://tryhackme.com")
        
        app_path = self.find_application(app_name)
        
        if app_path:
            def launch():
                try:
                    gui_apps = ['firefox', 'chrome', 'chromium', 'code', 'gedit', 
                              'nautilus', 'thunar', 'wireshark', 'burpsuite',
                              'spotify', 'vlc', 'discord', 'telegram-desktop']
                    
                    if any(gui in app_path for gui in gui_apps) or app_name in gui_apps:
                        subprocess.Popen([app_path])
                    else:
                        terminal = self.find_application('terminal')
                        if terminal:
                            subprocess.Popen([terminal, '-e', app_path])
                        else:
                            subprocess.Popen([app_path], shell=True)
                            
                except Exception as e:
                    print(f"[-] Error launching app: {e}")
            
            thread = threading.Thread(target=launch)
            thread.daemon = True
            thread.start()
            
            favs = self.memory.recall('user_preferences.favorite_tools', [])
            if app_name not in favs and app_name in Config.APP_PATHS:
                favs.append(app_name)
                self.memory.remember('user_preferences.favorite_tools', favs)
            
            return True
        
        return False
    
    def launch_browser_async(self, url: str = None) -> bool:
        """Launch web browser asynchronously"""
        def launch():
            try:
                if url:
                    webbrowser.open(url)
                else:
                    webbrowser.open('https://www.google.com')
            except Exception as e:
                print(f"[-] Error launching browser: {e}")
        
        thread = threading.Thread(target=launch)
        thread.daemon = True
        thread.start()
        return True
    
    def launch_security_tool_async(self, tool_name: str, args: str = "") -> bool:
        """Launch security tool with arguments"""
        return KaliUtils.launch_security_tool_async(tool_name, args)
    
    def install_tool_async(self, tool_name: str) -> bool:
        """Install a tool asynchronously"""
        if tool_name not in Config.INSTALLABLE_TOOLS:
            return False
        
        def install():
            try:
                terminal = self.find_application('terminal')
                package = Config.INSTALLABLE_TOOLS[tool_name]
                
                if terminal:
                    cmd = f"{terminal} -e 'sudo apt update && sudo apt install -y {package}'"
                    subprocess.Popen(cmd, shell=True)
                else:
                    subprocess.Popen(['xterm', '-e', f'sudo apt update && sudo apt install -y {package}'])
            except Exception as e:
                print(f"[-] Error installing tool: {e}")
        
        thread = threading.Thread(target=install)
        thread.daemon = True
        thread.start()
        return True

# ==================== COMMAND PARSER ====================
class CommandParser:
    def __init__(self, memory: Memory):
        self.memory = memory
        self.patterns = self.load_patterns()
        
    def load_patterns(self) -> Dict[str, Dict]:
        """Load command patterns for Kali"""
        patterns = {
            # Basic commands
            'greeting': {
                'patterns': ['hello', 'hi', 'hey', 'greetings', 'good morning', 'good afternoon', 'good evening', 'what\'s good', 'yo', 'sup', 'hi dragon', 'hello dragon'],
                'action': 'greet',
            },
            'conversation': {
                'patterns': ['how are you', 'how are you doing', 'what\'s up', 'sup', 'how is it going', 'what\'s happening', 'how\'s life'],
                'action': 'conversation',
            },
            'time_date': {
                'patterns': ['time', 'what time is it', 'date', 'what day is it', 'current time', 'what\'s the date'],
                'action': 'time_date',
            },
            'help': {
                'patterns': ['help', 'commands', 'what can you do', 'help me', 'show commands', 'list commands', 'what do you got'],
                'action': 'help',
            },
            'exit': {
                'patterns': ['exit', 'quit', 'goodbye', 'bye', 'shutdown', 'see ya', 'later', 'peace'],
                'action': 'exit',
            },
            'thank_you': {
                'patterns': ['thank you', 'thanks', 'thx', 'appreciate it', 'good look', 'props'],
                'action': 'thank_you',
            },
            
            # App launching
            'open_app': {
                'patterns': ['open (.*)', 'launch (.*)', 'start (.*)', 'run (.*)', 'fire up (.*)'],
                'action': 'open_app',
            },
            
            # Tool installation
            'install_tool': {
                'patterns': ['install (.*)', 'download (.*)', 'get (.*)', 'setup (.*)'],
                'action': 'install_tool',
            },
            
            # Kali security tools
            'scan_network': {
                'patterns': ['scan network (.*)', 'nmap (.*)', 'network scan (.*)', 'scan subnet (.*)', 'recon (.*)'],
                'action': 'scan_network',
            },
            'web_scan': {
                'patterns': ['scan website (.*)', 'nikto (.*)', 'web scan (.*)', 'scan web (.*)', 'vuln scan (.*)'],
                'action': 'web_scan',
            },
            'directory_scan': {
                'patterns': ['dirbust (.*)', 'gobuster (.*)', 'directory scan (.*)', 'dir search (.*)', 'find dirs (.*)'],
                'action': 'directory_scan',
            },
            'wpscan': {
                'patterns': ['scan wordpress (.*)', 'wpscan (.*)', 'wordpress scan (.*)', 'wp hack (.*)'],
                'action': 'wpscan',
            },
            'sqlmap': {
                'patterns': ['sql injection (.*)', 'sqlmap (.*)', 'test sql (.*)', 'sqli (.*)'],
                'action': 'sqlmap',
            },
            'crack_hash': {
                'patterns': ['crack hash (.*)', 'hashcat (.*)', 'john (.*)', 'password crack (.*)', 'crack password (.*)'],
                'action': 'crack_hash',
            },
            'exploit': {
                'patterns': ['search exploit (.*)', 'searchsploit (.*)', 'find exploit (.*)', 'exploit db (.*)'],
                'action': 'search_exploit',
            },
            'msfconsole': {
                'patterns': ['start metasploit', 'launch metasploit', 'open metasploit', 'msfconsole', 'fire up metasploit'],
                'action': 'msfconsole',
            },
            'wireshark': {
                'patterns': ['open wireshark', 'launch wireshark', 'start wireshark', 'packet analyzer', 'sniff packets'],
                'action': 'wireshark',
            },
            'burpsuite': {
                'patterns': ['open burpsuite', 'launch burpsuite', 'start burpsuite', 'burp', 'web proxy'],
                'action': 'burpsuite',
            },
            'hydra': {
                'patterns': ['hydra (.*)', 'brute force (.*)', 'password attack (.*)', 'crack login (.*)'],
                'action': 'hydra',
            },
            'aircrack': {
                'patterns': ['aircrack (.*)', 'wifi crack (.*)', 'wireless attack (.*)', 'hack wifi (.*)'],
                'action': 'aircrack',
            },
            
            # System commands
            'system_info': {
                'patterns': ['system info', 'system information', 'computer info', 'specs', 'kali info', 'what\'s my setup', 'dragon info'],
                'action': 'system_info',
            },
            'network_info': {
                'patterns': ['network info', 'network interfaces', 'show interfaces', 'ip config', 'ifconfig', 'ip a'],
                'action': 'network_info',
            },
            'processes': {
                'patterns': ['show processes', 'running processes', 'ps', 'htop', 'what\'s running'],
                'action': 'show_processes',
            },
            'resources': {
                'patterns': ['system resources', 'cpu usage', 'memory usage', 'disk usage', 'resource monitor'],
                'action': 'show_resources',
            },
            'check_root': {
                'patterns': ['check root', 'am i root', 'root status', 'privileges', 'do i have root'],
                'action': 'check_root',
            },
            
            # File commands
            'list_files': {
                'patterns': ['list files', 'show files', 'directory', 'ls', 'dir', 'what\'s here', 'show current dir'],
                'action': 'list_files',
            },
            'open_folder': {
                'patterns': ['open folder (.*)', 'open directory (.*)', 'show folder (.*)', 'browse to (.*)'],
                'action': 'open_folder',
            },
            'wordlists': {
                'patterns': ['show wordlists', 'list wordlists', 'wordlist paths', 'wordlists', 'where are wordlists'],
                'action': 'show_wordlists',
            },
            
            # Web search
            'web_search': {
                'patterns': ['search web for (.*)', 'google (.*)', 'browse (.*)', 'search for (.*)', 'look up (.*)'],
                'action': 'web_search',
            },
            
            # Target management
            'set_target': {
                'patterns': ['set target (.*)', 'target set (.*)', 'current target (.*)', 'new target (.*)'],
                'action': 'set_target',
            },
            'show_target': {
                'patterns': ['show target', 'current target', 'target status', 'what\'s the target'],
                'action': 'show_target',
            },
            
            # Reporting
            'generate_report': {
                'patterns': ['generate report (.*)', 'create report (.*)', 'save results (.*)', 'make report (.*)'],
                'action': 'generate_report',
            },
            
            # Jokes and fun
            'joke': {
                'patterns': ['tell me a joke', 'joke', 'make me laugh', 'say something funny'],
                'action': 'joke',
            },
            'hack_phrase': {
                'patterns': ['hack the planet', 'hack', 'pwn', 'own', 'root', 'dragon hack'],
                'action': 'hack_phrase',
            },
        }
        
        return patterns
    
    def parse(self, user_input: str) -> Dict:
        """Parse user input and return command"""
        user_input = user_input.lower().strip()
        
        for cmd_name, cmd_info in self.patterns.items():
            for pattern in cmd_info['patterns']:
                if pattern == user_input:
                    return {
                        'action': cmd_info['action'],
                        'params': {},
                        'confidence': 1.0,
                    }
        
        for cmd_name, cmd_info in self.patterns.items():
            for pattern in cmd_info['patterns']:
                if '(' in pattern and ')' in pattern:
                    pattern_regex = pattern.replace('(.*)', '(.*)')
                    match = re.match(pattern_regex, user_input)
                    if match:
                        query = match.group(1).strip()
                        return {
                            'action': cmd_info['action'],
                            'params': {'query': query},
                            'confidence': 0.9,
                        }
        
        conversational_phrases = [
            (r'how.*you', 'conversation'),
            (r'what.*up', 'conversation'),
            (r'good.*(morning|afternoon|evening|day)', 'greet'),
            (r'thank.*', 'thank_you'),
            (r'nmap.*', 'scan_network'),
            (r'scan.*', 'scan_network'),
            (r'crack.*', 'crack_hash'),
            (r'exploit.*', 'search_exploit'),
            (r'hack.*', 'hack_phrase'),
            (r'joke.*', 'joke'),
            (r'funny.*', 'joke'),
        ]
        
        for pattern, action in conversational_phrases:
            if re.search(pattern, user_input, re.IGNORECASE):
                if 'scan' in action and ' ' in user_input:
                    parts = user_input.split(' ', 1)
                    if len(parts) > 1:
                        return {
                            'action': action,
                            'params': {'query': parts[1].strip()},
                            'confidence': 0.8,
                        }
                return {
                    'action': action,
                    'params': {},
                    'confidence': 0.8,
                }
        
        return {
            'action': 'unknown',
            'params': {'query': user_input},
            'confidence': 0.1,
        }

# ==================== RESPONSE GENERATOR ====================
class ResponseGenerator:
    def __init__(self, memory: Memory, app_manager: AppManager):
        self.memory = memory
        self.app_manager = app_manager
        
    def generate_response(self, command: Dict) -> str:
        """Generate response based on command"""
        action = command['action']
        params = command['params']
        
        handler_map = {
            'greet': self.greet,
            'conversation': self.conversation,
            'time_date': self.time_date,
            'help': self.help,
            'exit': self.exit_command,
            'thank_you': self.thank_you,
            'open_app': lambda: self.open_app(params.get('query', '')),
            'install_tool': lambda: self.install_tool(params.get('query', '')),
            'scan_network': lambda: self.scan_network(params.get('query', '')),
            'web_scan': lambda: self.web_scan(params.get('query', '')),
            'directory_scan': lambda: self.directory_scan(params.get('query', '')),
            'wpscan': lambda: self.wpscan(params.get('query', '')),
            'sqlmap': lambda: self.sqlmap(params.get('query', '')),
            'crack_hash': lambda: self.crack_hash(params.get('query', '')),
            'search_exploit': lambda: self.search_exploit(params.get('query', '')),
            'msfconsole': self.msfconsole,
            'wireshark': self.wireshark,
            'burpsuite': self.burpsuite,
            'hydra': lambda: self.hydra(params.get('query', '')),
            'aircrack': lambda: self.aircrack(params.get('query', '')),
            'system_info': self.system_info,
            'network_info': self.network_info,
            'show_processes': self.show_processes,
            'show_resources': self.show_resources,
            'check_root': self.check_root,
            'list_files': self.list_files,
            'open_folder': lambda: self.open_folder(params.get('query', '')),
            'show_wordlists': self.show_wordlists,
            'web_search': lambda: self.web_search(params.get('query', '')),
            'set_target': lambda: self.set_target(params.get('query', '')),
            'show_target': self.show_target,
            'generate_report': lambda: self.generate_report(params.get('query', '')),
            'joke': self.joke,
            'hack_phrase': self.hack_phrase,
        }
        
        if action in handler_map:
            return handler_map[action]()
        else:
            return self.handle_unknown(params.get('query', ''))
    
    def greet(self) -> str:
        """Generate greeting"""
        hour = datetime.datetime.now().hour
        if hour < 12:
            greeting = "Good morning"
        elif hour < 18:
            greeting = "Good afternoon"
        else:
            greeting = "Good evening"
        
        root_status = "🛡️ ROOT" if KaliUtils.check_root() else "🔒 USER"
        
        dragon_phrases = [
            f"{greeting}, {Config.USER_NAME}! [{root_status}] The dragon awakens... Ready to hack the planet?",
            f"{greeting}! I'm {Config.ASSISTANT_NAME} on Kali. Dragon systems nominal.",
            f"{greeting}, {Config.USER_NAME} [{root_status}] on dragon. What's our target today? Time to pwn some boxes!",
            f"Hey {Config.USER_NAME}! [{root_status}] The dragon is breathing fire! Ready to break some stuff?",
            f"Yo {Config.USER_NAME}! Dragon here. Ready to unleash some payloads?",
            f"{greeting}, kaizen@dragon. All systems go for some pentesting!",
        ]
        return random.choice(dragon_phrases)
    
    def conversation(self) -> str:
        """Handle conversational queries"""
        responses = [
            f"Running smooth on Kali, {Config.USER_NAME}! CPU at {psutil.cpu_percent()}%. The dragon is ready for some pentesting!",
            "All security tools operational. The dragon's fire is hot!",
            f"System ready. Memory usage is optimal. What's our next move on dragon, {Config.USER_NAME}?",
            "I'm feeling hacky today! Let's find some vulnerabilities on the dragon's network.",
            "Just chilling in the terminal, waiting for your commands. Got any targets for the dragon?",
            "Dragon online and breathing fire! Ready to hack!",
        ]
        return random.choice(responses)
    
    def thank_you(self) -> str:
        """Respond to thank you"""
        responses = [
            f"Always happy to help with your security assessments, {Config.USER_NAME}. Stay dangerous on dragon!",
            "My pleasure! Remember, with great power comes great root access on dragon.",
            "Glad I could assist with your penetration testing! The dragon approves!",
            "No problem! Now go pwn some boxes on dragon!",
            "You're welcome! The dragon is always here to help.",
        ]
        return random.choice(responses)
    
    def time_date(self) -> str:
        """Time and date response"""
        now = datetime.datetime.now()
        response = f"🕐 Dragon Time: {now.strftime('%I:%M:%S %p')}\n"
        response += f"📅 Date: {now.strftime('%A, %B %d, %Y')}"
        
        try:
            uptime = psutil.boot_time()
            boot_time = datetime.datetime.fromtimestamp(uptime)
            uptime_str = str(datetime.datetime.now() - boot_time).split('.')[0]
            response += f"\n⏱️  Dragon uptime: {uptime_str}"
        except:
            pass
            
        return response
    
    def open_app(self, app_name: str) -> str:
        """Open application response"""
        if not app_name:
            return "What do you want me to open, boss?"
        
        app_name = app_name.strip().lower()
        
        # Handle special cases
        if app_name in ['youtube', 'yt']:
            self.app_manager.launch_browser_async("https://youtube.com")
            return "🎥 Opening YouTube on dragon... Time for some hacking tutorials!"
        
        if app_name in ['github', 'gh']:
            self.app_manager.launch_browser_async("https://github.com")
            return "🐙 Opening GitHub on dragon... Go steal some code!"
        
        if app_name in ['hackthebox', 'htb']:
            self.app_manager.launch_browser_async("https://www.hackthebox.com")
            return "🎯 Opening HackTheBox on dragon... Time to pwn!"
        
        if app_name in ['tryhackme', 'thm']:
            self.app_manager.launch_browser_async("https://tryhackme.com")
            return "🛡️ Opening TryHackMe on dragon... Learn to hack!"
        
        if self.app_manager.launch_application_async(app_name):
            return f"🚀 Launching {app_name} on dragon in the background..."
        else:
            suggestions = {
                'nmap': 'Try "scan network 192.168.1.0/24"',
                'msf': 'Try "start metasploit" or "msfconsole"',
                'burp': 'Try "open burpsuite"',
                'wireshark': 'Try "open wireshark"',
                'john': 'Try "crack hash [hash]"',
                'hashcat': 'Try "crack hash [hash]"',
                'gobuster': 'Try "dirbust [url]"',
                'nikto': 'Try "scan website [url]"',
                'sqlmap': 'Try "sql injection [url]"',
            }
            
            if app_name in suggestions:
                return f"❌ Could not launch '{app_name}' on dragon. {suggestions[app_name]}"
            
            return f"❌ Could not launch '{app_name}' on dragon. Want me to install it? Try 'install {app_name}'"
    
    def install_tool(self, tool_name: str) -> str:
        """Install a tool"""
        if not tool_name:
            return "What tool should I install on dragon?"
        
        tool_name = tool_name.strip().lower()
        
        if tool_name in Config.INSTALLABLE_TOOLS:
            if KaliUtils.check_tool_installed(tool_name):
                return f"✅ {tool_name} is already installed on dragon! Try 'open {tool_name}' to use it."
            
            if self.app_manager.install_tool_async(tool_name):
                return f"📦 Installing {tool_name} on dragon in a new terminal. This might take a minute..."
            else:
                return f"❌ Could not install {tool_name} on dragon. Make sure you have internet and sudo access."
        else:
            return f"❌ I don't know how to install '{tool_name}' on dragon. Check the name and try again."
    
    def scan_network(self, target: str) -> str:
        """Network scan with nmap"""
        if not target:
            target = "192.168.1.0/24"
        
        def run_scan():
            try:
                cmd = f"gnome-terminal -- nmap -sV -sC -O {target}"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error running nmap: {e}")
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return f"🔍 Starting Nmap scan on {target} from dragon... Let's find some open ports!"
    
    def web_scan(self, target: str) -> str:
        """Web vulnerability scan with nikto"""
        if not target:
            return "Please specify a target URL (e.g., scan website https://example.com)"
        
        def run_web_scan():
            try:
                cmd = f"gnome-terminal -- nikto -h {target}"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error running nikto: {e}")
        
        thread = threading.Thread(target=run_web_scan)
        thread.daemon = True
        thread.start()
        
        return f"🌐 Starting Nikto web scan on {target} from dragon... Looking for vulnerabilities!"
    
    def directory_scan(self, target: str) -> str:
        """Directory busting with gobuster"""
        if not target:
            return "Please specify a target URL (e.g., dirbust https://example.com)"
        
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/dirb/wordlists/common.txt"
        
        def run_dirbust():
            try:
                cmd = f"gnome-terminal -- gobuster dir -u {target} -w {wordlist}"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error running gobuster: {e}")
        
        thread = threading.Thread(target=run_dirbust)
        thread.daemon = True
        thread.start()
        
        return f"📁 Starting directory scan on {target} from dragon... Finding hidden paths!"
    
    def wpscan(self, target: str) -> str:
        """WordPress scan with wpscan"""
        if not target:
            return "Please specify a WordPress target URL"
        
        def run_wpscan():
            try:
                cmd = f"gnome-terminal -- wpscan --url {target} -e vp,vt,u,dbe"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error running wpscan: {e}")
        
        thread = threading.Thread(target=run_wpscan)
        thread.daemon = True
        thread.start()
        
        return f"🔐 Scanning WordPress site {target} from dragon... Finding those vulnerable plugins!"
    
    def sqlmap(self, target: str) -> str:
        """SQL injection test with sqlmap"""
        if not target:
            return "Please specify a target URL with parameter"
        
        def run_sqlmap():
            try:
                cmd = f"gnome-terminal -- sqlmap -u {target} --batch"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error running sqlmap: {e}")
        
        thread = threading.Thread(target=run_sqlmap)
        thread.daemon = True
        thread.start()
        
        return f"💉 Testing SQL injection on {target} from dragon... Time to dump some databases!"
    
    def crack_hash(self, hash_info: str) -> str:
        """Crack hash with john/hashcat"""
        if not hash_info:
            return "Please specify hash or hash file to crack"
        
        def run_hashcat():
            try:
                cmd = f"gnome-terminal -- hashcat -a 3 -m 0 {hash_info}"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error running hashcat: {e}")
        
        thread = threading.Thread(target=run_hashcat)
        thread.daemon = True
        thread.start()
        
        return f"🔑 Starting password cracking on {hash_info} on dragon... Hope it's not 'password123'!"
    
    def search_exploit(self, query: str) -> str:
        """Search for exploits with searchsploit"""
        if not query:
            return "Please specify what to search for (e.g., search exploit apache 2.4.49)"
        
        def run_searchsploit():
            try:
                cmd = f"gnome-terminal -- searchsploit {query}"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error running searchsploit: {e}")
        
        thread = threading.Thread(target=run_searchsploit)
        thread.daemon = True
        thread.start()
        
        return f"🎯 Searching exploits for {query} on dragon... Let's find a 0day!"
    
    def msfconsole(self) -> str:
        """Launch Metasploit Framework"""
        def run_msf():
            try:
                cmd = "gnome-terminal -- msfconsole"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error launching msfconsole: {e}")
        
        thread = threading.Thread(target=run_msf)
        thread.daemon = True
        thread.start()
        
        return "💀 Launching Metasploit Framework on dragon... Time to get some shells!"
    
    def wireshark(self) -> str:
        """Launch Wireshark"""
        if not KaliUtils.check_root():
            return "⚠️ Wireshark may need root privileges for live capture. Try running JARVIS as root on dragon."
        
        def run_wireshark():
            try:
                cmd = "wireshark"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error launching Wireshark: {e}")
        
        thread = threading.Thread(target=run_wireshark)
        thread.daemon = True
        thread.start()
        
        return "📡 Launching Wireshark packet analyzer on dragon... Let's see what's on the wire!"
    
    def burpsuite(self) -> str:
        """Launch Burp Suite"""
        def run_burp():
            try:
                cmd = "burpsuite"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error launching Burp Suite: {e}")
        
        thread = threading.Thread(target=run_burp)
        thread.daemon = True
        thread.start()
        
        return "🕷️ Launching Burp Suite on dragon... Time to intercept some requests!"
    
    def hydra(self, target: str) -> str:
        """Launch Hydra brute force"""
        if not target:
            return "Please specify target (e.g., hydra ssh://192.168.1.100)"
        
        def run_hydra():
            try:
                cmd = f"gnome-terminal -- hydra -h"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error launching hydra: {e}")
        
        thread = threading.Thread(target=run_hydra)
        thread.daemon = True
        thread.start()
        
        return "🔐 Opening Hydra help in terminal on dragon. Configure your attack parameters and crack those passwords!"
    
    def aircrack(self, target: str) -> str:
        """Launch Aircrack-ng suite"""
        def run_aircrack():
            try:
                cmd = "gnome-terminal -- aircrack-ng"
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                print(f"[-] Error launching aircrack: {e}")
        
        thread = threading.Thread(target=run_aircrack)
        thread.daemon = True
        thread.start()
        
        return "📶 Launching Aircrack-ng wireless tools on dragon... Time to break some WiFi!"
    
    def system_info(self) -> str:
        """System information response"""
        info = self.memory.recall('system_info', {})
        
        response = "🤖 Dragon System Information\n"
        response += "="*40 + "\n"
        response += f"📀 Distribution: {info.get('kali_version', 'Kali Linux')}\n"
        response += f"💻 Kernel: {info.get('os_version', 'Unknown')}\n"
        response += f"👤 User: {info.get('username', 'Unknown')}@dragon\n"
        response += f"🛡️  Privileges: {'ROOT' if info.get('is_root') else 'USER'}\n"
        response += f"🏠 Home: {info.get('home_dir', 'Unknown')}\n"
        response += f"🏷️  Hostname: dragon\n"
        response += f"🐍 Python: {info.get('python_version', 'Unknown')}\n"
        
        return response
    
    def network_info(self) -> str:
        """Network interface information"""
        interfaces = KaliUtils.get_network_interfaces()
        
        if not interfaces:
            return "❌ Could not retrieve network information on dragon."
        
        response = "🌐 Dragon Network Interfaces\n"
        response += "="*40 + "\n"
        
        for iface in interfaces:
            response += f"📶 Interface: {iface.get('name', 'Unknown')}\n"
            if 'ipv4' in iface:
                response += f"   IPv4: {iface['ipv4']}\n"
            if 'netmask' in iface:
                response += f"   Netmask: {iface['netmask']}\n"
            if 'mac' in iface:
                response += f"   MAC: {iface['mac']}\n"
            if 'ipv6' in iface:
                response += f"   IPv6: {iface['ipv6']}\n"
            response += "\n"
        
        return response
    
    def show_processes(self) -> str:
        """Show running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except:
                    pass
            
            processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
            
            response = "📊 Dragon Top Processes (CPU %)\n"
            response += "="*40 + "\n"
            
            for proc in processes[:10]:
                if proc['cpu_percent'] and proc['cpu_percent'] > 0:
                    response += f"⚙️  {proc['name'][:20]:20} CPU: {proc['cpu_percent']:.1f}% MEM: {proc['memory_percent']:.1f}%\n"
            
            return response
        except:
            return "❌ Could not retrieve process information on dragon."
    
    def show_resources(self) -> str:
        """Show system resource usage"""
        resources = KaliUtils.get_system_resources()
        
        response = "💻 Dragon System Resources\n"
        response += "="*40 + "\n"
        
        response += f"🔄 CPU Usage: {resources.get('cpu_percent', 'N/A')}% ({resources.get('cpu_count', 'N/A')} cores)\n"
        
        if 'memory_total' in resources:
            mem_total = resources['memory_total'] / (1024**3)
            mem_used = resources['memory_used'] / (1024**3)
            mem_percent = resources.get('memory_percent', 0)
            response += f"🧠 Memory: {mem_used:.1f}GB / {mem_total:.1f}GB ({mem_percent:.1f}%)\n"
        
        if 'disk_total' in resources:
            disk_total = resources['disk_total'] / (1024**3)
            disk_used = resources['disk_used'] / (1024**3)
            disk_free = resources['disk_free'] / (1024**3)
            response += f"💾 Disk: {disk_used:.1f}GB / {disk_total:.1f}GB (Free: {disk_free:.1f}GB)\n"
        
        if 'net_sent' in resources:
            net_sent = resources['net_sent'] / (1024**2)
            net_recv = resources['net_recv'] / (1024**2)
            response += f"📡 Network: ↑ {net_sent:.1f}MB ↓ {net_recv:.1f}MB\n"
        
        return response
    
    def check_root(self) -> str:
        """Check root status"""
        if KaliUtils.check_root():
            return "🛡️ You are running as ROOT on dragon. All tools and commands have full system access. Time to pwn!"
        else:
            return "🔒 You are running as a regular USER on dragon. Some tools may need root. Use 'sudo' if needed."
    
    def list_files(self) -> str:
        """List files in current directory"""
        current_dir = os.getcwd()
        
        try:
            items = os.listdir(current_dir)
        except PermissionError:
            return "❌ Permission denied to list this directory on dragon."
        
        if not items:
            return f"📁 Directory '{current_dir}' is empty on dragon."
        
        dirs = []
        files = []
        
        for item in sorted(items):
            full_path = os.path.join(current_dir, item)
            if os.path.isdir(full_path):
                dirs.append(item)
            else:
                files.append(item)
        
        response = f"📁 Current Directory on dragon: {current_dir}\n\n"
        
        if dirs:
            response += "📂 Directories:\n"
            for d in dirs[:10]:
                response += f"  📁 {d}/\n"
        
        if files:
            if dirs:
                response += "\n"
            response += "📄 Files:\n"
            for f in files[:10]:
                if os.access(os.path.join(current_dir, f), os.X_OK):
                    response += f"  ⚙️  {f}*\n"
                else:
                    response += f"  📄 {f}\n"
        
        total = len(dirs) + len(files)
        shown = len(dirs[:10]) + len(files[:10])
        if total > shown:
            response += f"\n📊 Showing {shown} of {total} items on dragon"
        
        return response
    
    def open_folder(self, folder_path: str) -> str:
        """Open a folder"""
        if not folder_path:
            folder_path = f"/home/{Config.USER_NAME}"
        
        if KaliUtils.open_folder(folder_path):
            return f"📂 Opening folder on dragon: {folder_path}"
        else:
            return f"❌ Could not open folder on dragon: {folder_path}. Does it exist?"
    
    def show_wordlists(self) -> str:
        """Show available wordlists"""
        wordlist_paths = KaliUtils.get_wordlist_paths()
        
        if not wordlist_paths:
            return "📚 No common wordlist directories found on dragon. Try installing seclists: sudo apt install seclists"
        
        response = "📚 Dragon Wordlists\n"
        response += "="*40 + "\n"
        
        for path in wordlist_paths:
            try:
                items = os.listdir(path)
                files = [f for f in items[:5] if os.path.isfile(os.path.join(path, f))]
                response += f"📁 {path}:\n"
                for f in files:
                    file_path = os.path.join(path, f)
                    size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    size_mb = size / (1024**2)
                    response += f"   📄 {f} ({size_mb:.1f}MB)\n"
                if len(items) > 5:
                    response += f"   ... and {len(items)-5} more files\n"
                response += "\n"
            except:
                response += f"📁 {path}: (access denied or empty)\n\n"
        
        return response
    
    def web_search(self, query: str) -> str:
        """Web search response"""
        if not query:
            return "What would you like me to search for on dragon?"
        
        encoded_query = urllib.parse.quote(query)
        
        def launch_search():
            try:
                subprocess.Popen(['firefox', f'https://www.google.com/search?q={encoded_query}'])
            except:
                webbrowser.open(f'https://www.google.com/search?q={encoded_query}')
        
        thread = threading.Thread(target=launch_search)
        thread.daemon = True
        thread.start()
        
        return f"🌐 Searching for '{query}' on dragon... Google is your friend!"
    
    def set_target(self, target: str) -> str:
        """Set current target"""
        if not target:
            return "Please specify a target for dragon."
        
        self.memory.remember('security_context.current_target', target)
        
        try:
            ip = socket.gethostbyname(target.split('/')[0])
            target_info = f"{target} ({ip})"
        except:
            target_info = target
        
        return f"🎯 Target set to: {target_info} on dragon. Let's pwn it!"
    
    def show_target(self) -> str:
        """Show current target"""
        target = self.memory.recall('security_context.current_target', None)
        
        if target:
            return f"🎯 Current target on dragon: {target}"
        else:
            return "🎯 No target currently set on dragon. Use 'set target [ip/url]' to get started."
    
    def generate_report(self, report_name: str) -> str:
        """Generate a report template"""
        if not report_name:
            report_name = f"pentest_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        report_dir = os.path.expanduser(f"~/Reports")
        os.makedirs(report_dir, exist_ok=True)
        
        report_path = os.path.join(report_dir, f"{report_name}.md")
        
        try:
            with open(report_path, 'w') as f:
                f.write(f"# Penetration Test Report - Dragon\n")
                f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Tester:** {Config.USER_NAME}@dragon\n")
                f.write(f"**Target:** {self.memory.recall('security_context.current_target', 'Not specified')}\n\n")
                f.write("## Executive Summary\n\n")
                f.write("## Scope\n\n")
                f.write("## Methodology\n\n")
                f.write("## Findings\n\n")
                f.write("### Critical\n\n")
                f.write("### High\n\n")
                f.write("### Medium\n\n")
                f.write("### Low\n\n")
                f.write("## Recommendations\n\n")
            
            return f"📄 Report template created at: {report_path} on dragon"
        except Exception as e:
            return f"❌ Could not create report on dragon: {e}"
    
    def joke(self) -> str:
        """Tell a hacking joke"""
        jokes = [
            "Why do hackers wear black? Because they're in a darknet!",
            "What's a hacker's favorite game? Pwn-tendo!",
            "Why did the hacker cross the road? To get to the other site!",
            "How many hackers does it take to change a lightbulb? None, they just exploit the darkness!",
            "Why was the hacker cold? He left his Windows open!",
            "What's a hacker's favorite music? Ransom-ware!",
            "Why do hackers love nature? Because of all the bugs!",
            "What's a hacker's favorite drink? SQL injection!",
            "Why did the dragon learn hacking? To breathe firewalls!",
            "What's a dragon's favorite tool? Nmap - it scales networks!",
        ]
        return random.choice(jokes)
    
    def hack_phrase(self) -> str:
        """Hacker phrases"""
        phrases = [
            "HACK THE PLANET! 🔥 - Dragon style!",
            "Time to pwn some noobs on dragon! 💀",
            "Root or die trying on dragon! 🛡️",
            "I'm in. The dragon has landed! 🎯",
            "Access granted. Let's own this box on dragon! 💻",
            "The matrix has you... dragon is here! 🔐",
            "Root access obtained on dragon! 🏴‍�",
            "Let the hacking begin on dragon! 🚀",
            "Dragon breathing fire on the target! 🔥",
            "kaizen@dragon has entered the chat! 💀",
        ]
        return random.choice(phrases)
    
    def help(self) -> str:
        """Help response for Kali"""
        response = f"🤖 {Config.ASSISTANT_NAME} v{Config.VERSION} (Kali H4X0R Edition) on dragon\n"
        response += "="*60 + "\n\n"
        
        response += "🎯 Security Tools:\n"
        response += "  • Network: scan network [target], nmap [target]\n"
        response += "  • Web: scan website [url], nikto [url], dirbust [url]\n"
        response += "  • WordPress: scan wordpress [url], wpscan [url]\n"
        response += "  • SQL: sql injection [url], sqlmap [url]\n"
        response += "  • Password: crack hash [hash], hashcat, john\n"
        response += "  • Exploits: search exploit [query], searchsploit\n"
        response += "  • Frameworks: start metasploit, open burpsuite, open wireshark\n"
        response += "  • Wireless: aircrack, wifite\n\n"
        
        response += "💻 System Commands:\n"
        response += "  • system info, network info, show processes\n"
        response += "  • show resources, check root\n"
        response += "  • list files, show wordlists\n"
        response += "  • open folder [path] - browse directories\n\n"
        
        response += "📦 Tool Management:\n"
        response += "  • install [tool] - download and install tools\n"
        response += "  • open [app] - launch applications\n"
        response += "  • open youtube/github/hackthebox - quick access\n\n"
        
        response += "⚙️  General:\n"
        response += "  • set target [ip/url]\n"
        response += "  • generate report [name]\n"
        response += "  • search web for [query]\n"
        response += "  • joke - for laughs\n"
        response += "  • help - show this menu\n"
        response += "  • exit - quit JARVIS\n\n"
        
        if KaliUtils.check_root():
            response += "🛡️ Running as ROOT on dragon - Full capabilities enabled\n"
        else:
            response += "🔒 Running as USER on dragon - Some tools need root\n"
        
        response += "💡 Type 'open [tool]' to launch any security tool\n"
        response += "💡 Type 'install [tool]' to get new tools\n"
        response += "\nHACK THE PLANET! 🔥 - Dragon out!"
        
        return response
    
    def exit_command(self) -> str:
        """Exit response"""
        responses = [
            f"👋 Exiting JARVIS on dragon. Stay dangerous, {Config.USER_NAME}!",
            "🛑 Shutting down dragon. Remember to document your findings!",
            f"🚀 See you next time on dragon. {Config.ASSISTANT_NAME} out!",
            "👋 Peace out from dragon! Don't forget to rm -rf your tracks!",
            "🔥 Dragon going to sleep. Hack the planet!",
        ]
        return random.choice(responses)
    
    def handle_unknown(self, query: str) -> str:
        """Handle unknown commands"""
        for tool in Config.APP_PATHS.keys():
            if tool in query.lower():
                return f"💡 Did you mean to open '{tool}' on dragon? Try: open {tool} or install {tool}"
        
        for tool in Config.INSTALLABLE_TOOLS.keys():
            if tool in query.lower():
                return f"💡 Want to install '{tool}' on dragon? Try: install {tool}"
        
        terms = {
            'recon': 'Try: scan network [target] or nmap [target]',
            'enum': 'Try: enum4linux [target] or nmap -sV [target]',
            'reverse shell': 'Try: msfvenom -p linux/x86/shell_reverse_tcp',
            'vulnerability': 'Try: search exploit [software]',
            'sql': 'Try: sql injection [url]',
            'xss': 'Try: nikto -h [url] or burpsuite',
            'wifi': 'Try: aircrack or wifite',
            'password': 'Try: crack hash [hash] or hydra',
            'exploit': 'Try: search exploit [term]',
            'wordlist': 'Try: show wordlists',
            'dragon': 'I am dragon! Ready to hack!',
        }
        
        for term, suggestion in terms.items():
            if term in query.lower():
                return f"🤔 For {term} on dragon: {suggestion}"
        
        responses = [
            f"🤔 Command not recognized on dragon. Try 'help' for Kali security commands.",
            f"💡 Not sure what '{query}' means on dragon. 'help' shows all available tools.",
            f"❓ '{query}'? Never heard of it on dragon. Try 'help' to see what I can do.",
            f"🐉 Dragon doesn't understand '{query}'. Try 'help'!",
        ]
        return random.choice(responses)

# ==================== UTILITY FUNCTIONS ====================
def get_username() -> str:
    """Get username in a cross-platform way"""
    try:
        username = getpass.getuser()
        if username:
            return username
        username = os.getenv('USER') or os.getenv('USERNAME') or os.getenv('LOGNAME')
        if username:
            return username
        return "User"
    except:
        return "User"

def get_home_directory() -> str:
    """Get home directory"""
    home = os.path.expanduser("~")
    if home and os.path.exists(home):
        return home
    return os.path.abspath(".")

def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

# ==================== MAIN JARVIS CLASS ====================
class JARVIS:
    def __init__(self):
        clear_screen()
        self.print_banner()
        
        print(f"🚀 Initializing {Config.ASSISTANT_NAME} on dragon...")
        
        if KaliUtils.is_kali():
            print("✅ Kali Linux detected on dragon - Let's hack!")
        else:
            print("⚠️  Not running on Kali Linux - some features may not work")
        
        if KaliUtils.check_root():
            print("🛡️  Running with ROOT privileges on dragon - Full power!")
        else:
            print("🔒 Running as USER on dragon (some tools need root)")
        
        self.memory = Memory()
        self.app_manager = AppManager(self.memory)
        self.parser = CommandParser(self.memory)
        self.response_gen = ResponseGenerator(self.memory, self.app_manager)
        
        print(f"✅ {Config.ASSISTANT_NAME} v{Config.VERSION} ready on dragon")
        print(f"👤 Welcome, {Config.USER_NAME}@dragon")
        print("🎯 Security tools launch in background - no freezing")
        print("💡 Type 'help' for penetration testing commands")
        print("="*60)
    
    def print_banner(self):
        """Print the JARVIS banner"""
        banner = r"""
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠞⠛⠉⠉⠉⠉⠉⠉⠉⠉⠉⠛⠻⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⣰⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⡀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⣼⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣧⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⢸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡇⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠸⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠇⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠏⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠙⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⢶⣶⣶⣶⣶⡶⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    
    ██╗ █████╗ ██████╗ ██╗   ██╗██╗███████╗    ██╗  ██╗ █████╗ ██╗  ██╗ ██████╗ ██████╗ 
    ██║██╔══██╗██╔══██╗██║   ██║██║██╔════╝    ╚██╗██╔╝██╔══██╗██║  ██║██╔═══██╗██╔══██╗
    ██║███████║██████╔╝██║   ██║██║███████╗     ╚███╔╝ ███████║███████║██║   ██║██████╔╝
    ██║██╔══██║██╔══██╗██║   ██║██║╚════██║     ██╔██╗ ██╔══██║██╔══██║██║   ██║██╔══██╗
    ██║██║  ██║██║  ██║╚██████╔╝██║███████║    ██╔╝ ██╗██║  ██║██║  ██║╚██████╔╝██║  ██║
    ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
    
                            🔥 DRAGON EDITION 🔥
    """
        print(banner)
        print(f"\n{Config.ASSISTANT_NAME} v{Config.VERSION} - Kali Linux Security Assistant on dragon")
        print("Penetration Testing • Vulnerability Assessment • Security Operations")
        print("="*60)
    
    def process_command(self, user_input: str) -> str:
        """Process a user command and return response"""
        if not user_input.strip():
            return "Please enter a command for dragon."
        
        command = self.parser.parse(user_input)
        response = self.response_gen.generate_response(command)
        
        self.memory.add_conversation(user_input, response)
        
        return response
    
    def run_interactive(self):
        """Run in interactive mode"""
        print("\n" + "="*60)
        print(f"💬 {Config.ASSISTANT_NAME} Kali Interactive Mode on dragon")
        print("Type 'help' for commands, 'exit' to quit")
        print("="*60)
        
        while True:
            try:
                user_input = input(f"\n{Config.USER_NAME}@dragon> ").strip()
                
                if not user_input:
                    continue
                
                response = self.process_command(user_input)
                print(f"\n{Config.ASSISTANT_NAME}> {response}")
                
                if user_input.lower() in ['exit', 'quit', 'goodbye', 'bye', 'peace']:
                    print("\n💾 Saving memory and tools configuration on dragon...")
                    self.memory.save()
                    break
                    
            except KeyboardInterrupt:
                print(f"\n\n{Config.ASSISTANT_NAME}> ⏹️ Interrupted on dragon. Peace out!")
                self.memory.save()
                break
            except Exception as e:
                print(f"\n{Config.ASSISTANT_NAME}> ❌ Error on dragon: {e}")

# ==================== MAIN EXECUTION ====================
def main():
    """Main entry point"""
    # Check for root
    if not KaliUtils.check_root():
        print("⚠️  Not running as root on dragon. Some security tools may require elevated privileges.")
        print("   Consider running: sudo python3 jarvis_kali.py\n")
        time.sleep(2)
    
    # Initialize JARVIS
    jarvis = JARVIS()
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        command = " ".join(sys.argv[1:])
        response = jarvis.process_command(command)
        print(f"\n{Config.ASSISTANT_NAME}> {response}")
    else:
        jarvis.run_interactive()

if __name__ == "__main__":
    main()