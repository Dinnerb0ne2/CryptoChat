# -*- coding: utf-8 -*-
# Copyright 2025(C) CryptoChat Dinnerb0ne<tomma_2022@outlook.com>
#
#    Copyright 2025 [Dinnberb0ne & T0ast101]
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0 
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# date: 2025-09-13
# version: 1.2.2
# description: A simple chat application with encryption and room features.
# LICENSE: Apache-2.0

import os
import sys
import json
from datetime import datetime

# Import RSA class AND _export_pem helper from your custom crypto.py
from lib.crypto   import RSA, _export_pem
from lib.server   import ChatServer
from lib.client   import ChatClient
from lib.rooms    import RoomManager 


class ChatApplication:
    def __init__(self):
        # Verify user accepted End User License Agreement
        self.check_eula()
        # Load configuration from chat.properties
        self.load_config()
        # Initialize encryption system (RSA)
        self.setup_crypto()

        # Initialize ban management (IP/user bans)
        self.bans_file   = 'bans.json'
        self.banned_ips  = set()
        self.banned_users = set()
        self.load_bans()

        # Initialize room management (load room configs)
        self.rooms           = {}
        self.current_room    = None
        self.room_config_dir = self.config.get('room_config', './room_config/')
        self.load_rooms()

        # Initialize chat history storage
        self.chat_history = [] 

        # Initialize Server or Client mode
        if self.config['mode'] == 'server':
            # Map admin commands to their handler methods
            self.admin_commands = {
                'kick': self.kick_user,
                'ban': self.ban_user,
                'unban': self.unban_user,
                'check': self.check_user,
                'listbans': self.list_bans,
                'rooms': self.list_rooms,
                'stop': self.stop_server,
                'help': self.show_admin_help,
                'setpassword': self.set_password,
                'hashpassword': self.hash_password,
                'roompassword': self.set_room_password,
                'save': self.save_chat_history
            }
            self.server_inst = ChatServer(self)
        else:
            # Initialize client-side components
            self.chat_history = []
            self.client_inst = ChatClient(self.config)

    # Compatibility Wrappers: Forward calls to server/client/room manager
    # (Maintains support for old code that may call these methods directly)
    def list_rooms(self, args):
        """List all available chat rooms (forwards to server)"""
        return self.server_inst.list_rooms(args) if hasattr(self, 'server_inst') else None

    def stop_server(self, args):
        """Shut down the server (forwards to server)"""
        return self.server_inst.stop_server(args) if hasattr(self, 'server_inst') else sys.exit(0)

    def load_config(self):
        """Load and parse configuration from chat.properties"""
        # Default config values (used if file is missing or keys are unset)
        default_config = {
            'mode': 'server',
            'ip': 'localhost',
            'port': '25566',
            'encrypt_algorithm': 'RSA',
            'key_length': '2048',
            'nickname': '',
            'motd': '',
            'max_users': '20',
            'pubkey_file': 'public_key.pem',
            'key_file': 'private_key.pem',
            'enable_rooms': 'false',
            'room_config': './room_config/',
            'enable_hash': 'false',
            'hash_type': 'sha256',
            'enable_password': 'false',
            'enable_autosave': 'false',
            'autosave_delay': '300',
            'enable_console': 'true',
            'enable_webui': 'false',
            'webui_port': '25567'
        }

        # Create default chat.properties if it doesn't exist
        if not os.path.exists('chat.properties'):
            with open('chat.properties', 'w', encoding='utf-8') as f:
                for key, value in default_config.items():
                    f.write(f"{key}={value}\n")

        # Load config from file
        self.config = {}
        with open('chat.properties', 'r', encoding='utf-8') as f:
            for line in f:
                if '=' in line and not line.strip().startswith('#'):  # Skip comments
                    key, value = line.strip().split('=', 1)
                    self.config[key] = value

        # Convert config values to correct data types (str → int/bool)
        self.config['port'] = int(self.config['port'])
        self.config['key_length'] = int(self.config['key_length'])
        self.config['enable_rooms'] = self.config['enable_rooms'].lower() == 'true'
        self.config['max_users'] = int(self.config['max_users'])
        self.config['enable_hash'] = self.config['enable_hash'].lower() == 'true'
        self.config['enable_password'] = self.config['enable_password'].lower() == 'true'
        self.config['enable_autosave'] = self.config['enable_autosave'].lower() == 'true'
        self.config['autosave_delay'] = int(self.config.get('autosave_delay', default_config['autosave_delay']))
        
        # WebUI config validation (ensure at least one interface is enabled)
        self.config['enable_console'] = self.config.get('enable_console', 'true').lower() == 'true'
        self.config['enable_webui'] = self.config.get('enable_webui', 'true').lower() == 'true'
        self.config['webui_port'] = int(self.config.get('webui_port', default_config['webui_port']))
        
        # Enforce config rule: cannot disable both console and WebUI
        if not self.config['enable_console'] and not self.config['enable_webui']:
            raise ValueError("CONFIG ERROR: enable_console and enable_webui cannot both be false")

    def load_rooms(self):
        """Load room configurations via RoomManager (forwards to room manager)"""
        self.room_mgr = RoomManager(self.room_config_dir, self.config['enable_hash'])
        self.rooms = self.room_mgr.list_rooms()  # Maintain backward compatibility with old code
        if self.rooms:
            print(f"Loaded rooms: {list(self.rooms.keys())}")
        else:
            print("Room feature is disabled")

    def save_room_bans(self, room_name):
        self.room_mgr.save_room_bans(room_name)
        
    def load_room_password_hash(self, room_name):
        return self.room_mgr.load_room_password_hash(room_name)
        
    def save_room_password_hash(self, room_name, pwd_hash):
        self.room_mgr.save_room_password_hash(room_name, pwd_hash)

    # Server Admin Command Wrappers
    def kick_user(self, args):
        return self.server_inst.kick_user(args) if hasattr(self, 'server_inst') else None
        
    def ban_user(self, args):
        return self.server_inst.ban_user(args) if hasattr(self, 'server_inst') else None
        
    def unban_user(self, args):
        return self.server_inst.unban_user(args) if hasattr(self, 'server_inst') else None
        
    def check_user(self, args):
        return self.server_inst.check_user(args) if hasattr(self, 'server_inst') else None
        
    def list_bans(self, args):
        return self.server_inst.list_bans(args) if hasattr(self, 'server_inst') else None
        
    def show_admin_help(self, args):
        return self.server_inst.show_admin_help(args) if hasattr(self, 'server_inst') else None
        
    def set_password(self, args):
        return self.server_inst.set_password(args) if hasattr(self, 'server_inst') else None
        
    def hash_password(self, args):
        return self.server_inst.hash_password(args) if hasattr(self, 'server_inst') else None
        
    def set_room_password(self, args):
        return self.server_inst.set_room_password(args) if hasattr(self, 'server_inst') else None
        
    def save_chat_history(self):
        return self.server_inst.save_chat_history() if hasattr(self, 'server_inst') else None
        
    def auto_save_chat_history(self):
        return self.server_inst.auto_save_chat_history() if hasattr(self, 'server_inst') else None

    # Authentication/Validation Wrappers
    def verify_password(self, pwd):
        return self.server_inst.verify_password(pwd) if hasattr(self, 'server_inst') else True
        
    def verify_room_password(self, room, pwd):
        return self.room_mgr.verify_room_password(room, pwd)
        
    def is_valid_ip(self, ip):
        return self.server_inst.is_valid_ip(ip) if hasattr(self, 'server_inst') else True
        
    def hash_password_value(self, pwd):
        return self.server_inst.hash_password_value(pwd) if hasattr(self, 'server_inst') else pwd

    def format_message(self, data):
        return self.server_inst.format_message(data) if hasattr(self, 'server_inst') else str(data)
        
    def get_motd(self, room=None):
        return self.server_inst.get_motd(room) if hasattr(self, 'server_inst') else self.config['motd']
        
    def handle_admin_command(self, cmd):
        return self.server_inst.handle_admin_command(cmd) if hasattr(self, 'server_inst') else None

    def run_server(self):           pass
    def start_admin_console(self):  pass
    def run_client(self):           pass

    def handle_command(self, cmd):
        return self.client_inst.handle_command(cmd) if hasattr(self, 'client_inst') else None
        
    def send_message(self, msg):
        return self.client_inst.send_message(msg) if hasattr(self, 'client_inst') else None
        
    def receive_messages(self):
        return self.client_inst.receive_messages() if hasattr(self, 'client_inst') else None

    def check_eula(self):
        """Enforce EULA acceptance (create file if missing, validate acceptance)"""
        if not os.path.exists('eula.txt'):
            # Create EULA file with English terms (matches original intent)
            with open('eula.txt', 'w', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()}\neula=false\n"
                        "This software is provided 'as is' without any express or implied warranty,\n"
                        "including but not limited to warranties of merchantability, fitness for a particular purpose,\n"
                        "accuracy, completeness, or non-infringement of third-party rights.\n"
                        "\n"
                        "The software developers, providers, and all related parties are not liable for any\n"
                        "direct, indirect, incidental, special, or consequential damages arising from use or\n"
                        "inability to use this software—regardless of legal theory (contract, tort, etc.) or\n"
                        "whether the possibility of damages was disclosed.\n"
                        "\n"
                        "Users are solely responsible for all legal consequences of improper software use,\n"
                        "including civil disputes, administrative penalties, or criminal offenses—even if such\n"
                        "use stems from software vulnerabilities, defects, or design flaws.\n")
            print("EULA acceptance required: Open 'eula.txt' and change 'eula=false' to 'eula=true'")
            sys.exit(0)
        
        # Check if EULA is accepted
        with open('eula.txt', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if len(lines) < 2 or 'eula=true' not in lines[1].strip():
                print("EULA not accepted: Open 'eula.txt' and set 'eula=true'")
                sys.exit(0)

    def setup_crypto(self):
        """Initialize RSA encryption (generate keys if missing, load existing keys)"""
        algo = self.config['encrypt_algorithm'].upper()
        key_length = self.config['key_length']
        private_key_path = self.config['key_file']
        public_key_path = self.config['pubkey_file']

        # Generate new RSA keys if they don't exist
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            print(f"Generating new {algo} key pair ({key_length} bits)...")
            if algo == 'RSA':
                private_key_obj = RSA.generate(key_length)
                private_key_pem = RSA.export_key(private_key_obj)
                public_key_obj = RSA.publickey(private_key_obj)
                public_key_pem = _export_pem(public_key_obj, kind="PUBLIC")            
            else:
                # Reject unsupported encryption algorithms
                raise ValueError(f"Unsupported encryption algorithm: {algo} (only RSA is supported)")

            # Save generated keys to files
            with open(private_key_path, 'wb') as f:
                f.write(private_key_pem)
            with open(public_key_path, 'wb') as f:
                f.write(public_key_pem)
            print(f"RSA keys saved to:\n- Private: {private_key_path}\n- Public: {public_key_path}")

        # Load existing keys from files (for runtime use)
        with open(private_key_path, 'rb') as f:
            self.private_key = f.read()
        with open(public_key_path, 'rb') as f:
            self.public_key = f.read()

    def load_bans(self):
        """Load banned IPs and users from bans.json (recovers previous bans)"""
        if os.path.exists(self.bans_file):
            try:
                with open(self.bans_file, 'r', encoding='utf-8') as f:
                    ban_data = json.load(f)
                    self.banned_ips = set(ban_data.get('ips', []))
                    self.banned_users = set(ban_data.get('users', []))
                print(f"Loaded {len(self.banned_ips)} banned IP(s) and {len(self.banned_users)} banned user(s)")
            except Exception as e:
                print(f"Warning: Failed to load ban list - {str(e)} (starting with empty ban list)")

    def save_bans(self):
        """Save current bans to bans.json (persists bans between restarts)"""
        try:
            with open(self.bans_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'ips': list(self.banned_ips),
                    'users': list(self.banned_users)
                }, f, indent=2)
        except Exception as e:
            print(f"Error: Failed to save ban list - {str(e)}")


if __name__ == '__main__':
    # Start the CryptoChat application
    ChatApplication()