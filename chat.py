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
# version: 1.2.0
# description: A simple chat application with encryption and room features.
# LICENSE: Apache-2.0

import os
import sys
import json
from datetime import datetime

from lib.crypto   import RSA
from lib.server   import ChatServer
from lib.client   import ChatClient
from lib.rooms    import RoomManager 


class ChatApplication:
    def __init__(self):
        self.check_eula()
        self.load_config()
        self.setup_crypto()


        self.bans_file   = 'bans.json'
        self.banned_ips  = set()
        self.banned_users= set()
        self.load_bans()

        self.rooms           = {}
        self.current_room    = None
        self.room_config_dir = self.config.get('room_config', './room_config/')
        self.load_rooms()

        self.chat_history = []

        if self.config['mode'] == 'server':
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
            self.chat_history = []
            self.client_inst = ChatClient(self)

    # ------------------------------------------------------------------
    #  以下所有方法仅做“转发”或“轻量包装”，保证旧代码任意调用点不爆炸
    # ------------------------------------------------------------------
    def list_rooms(self, args):
        """List Available Rooms（转发）"""
        return self.server_inst.list_rooms(args) if hasattr(self, 'server_inst') else None

    def stop_server(self, args):
        """Stop Server（转发）"""
        return self.server_inst.stop_server(args) if hasattr(self, 'server_inst') else sys.exit(0)

    def load_config(self):
        """Load Configuration File（与原实现 1:1）"""
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
            'autosave_delay': '300'
        }

        if not os.path.exists('chat.properties'):
            with open('chat.properties', 'w', encoding='utf-8') as f:
                for key, value in default_config.items():
                    f.write(f"{key}={value}\n")

        self.config = {}
        with open('chat.properties', 'r', encoding='utf-8') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    self.config[key] = value

        # 类型转换保持原样
        self.config['port'] = int(self.config['port'])
        self.config['key_length'] = int(self.config['key_length'])
        self.config['enable_rooms'] = self.config['enable_rooms'].lower() == 'true'
        self.config['max_users'] = int(self.config['max_users'])
        self.config['enable_hash'] = self.config['enable_hash'].lower() == 'true'
        self.config['enable_password'] = self.config['enable_password'].lower() == 'true'
        self.config['enable_autosave'] = self.config['enable_autosave'].lower() == 'true'
        self.config['autosave_delay'] = int(self.config.get('autosave_delay', default_config['autosave_delay']))

    def load_rooms(self):
        """Load Room Configurations（直接转发给 RoomManager）"""
        self.room_mgr = RoomManager(self.room_config_dir, self.config['enable_hash'])
        self.rooms = self.room_mgr.rooms          # 保持旧字段存在
        print(f"Loaded rooms: {list(self.rooms.keys())}") if self.rooms else print("Room feature is disabled")

    # 其余所有旧方法，一律“原样包装”——只负责转发或空壳，保证旧扩展点不炸
    def load_room_bans(self, room_name):  self.room_mgr.load_room_bans(room_name)
    def save_room_bans(self, room_name):  self.room_mgr.save_room_bans(room_name)
    def load_room_password_hash(self, room_name): self.room_mgr.load_room_password_hash(room_name)
    def save_room_password_hash(self, room_name, pwd_hash): self.room_mgr.save_room_password_hash(room_name, pwd_hash)
    def kick_user(self, args):      return self.server_inst.kick_user(args)      if hasattr(self, 'server_inst') else None
    def ban_user(self, args):       return self.server_inst.ban_user(args)       if hasattr(self, 'server_inst') else None
    def unban_user(self, args):     return self.server_inst.unban_user(args)     if hasattr(self, 'server_inst') else None
    def check_user(self, args):     return self.server_inst.check_user(args)     if hasattr(self, 'server_inst') else None
    def list_bans(self, args):      return self.server_inst.list_bans(args)      if hasattr(self, 'server_inst') else None
    def show_admin_help(self, args):return self.server_inst.show_admin_help(args)if hasattr(self, 'server_inst') else None
    def set_password(self, args):   return self.server_inst.set_password(args)   if hasattr(self, 'server_inst') else None
    def hash_password(self, args):  return self.server_inst.hash_password(args)  if hasattr(self, 'server_inst') else None
    def set_room_password(self, args):return self.server_inst.set_room_password(args)if hasattr(self, 'server_inst') else None
    def save_chat_history(self):    return self.server_inst.save_chat_history()  if hasattr(self, 'server_inst') else None
    def auto_save_chat_history(self):return self.server_inst.auto_save_chat_history()if hasattr(self, 'server_inst') else None
    def verify_password(self, pwd): return self.server_inst.verify_password(pwd)  if hasattr(self, 'server_inst') else True
    def verify_room_password(self, room, pwd): return self.room_mgr.verify_room_password(room, pwd)
    def is_valid_ip(self, ip):      return self.server_inst.is_valid_ip(ip)      if hasattr(self, 'server_inst') else True
    def hash_password_value(self, pwd):return self.server_inst.hash_password_value(pwd)if hasattr(self, 'server_inst') else pwd
    def format_message(self, data): return self.server_inst.format_message(data)  if hasattr(self, 'server_inst') else str(data)
    def get_motd(self, room=None):  return self.server_inst.get_motd(room)        if hasattr(self, 'server_inst') else self.config['motd']
    def handle_admin_command(self, cmd):return self.server_inst.handle_admin_command(cmd)if hasattr(self, 'server_inst') else None
    def run_server(self):           pass   # 已改由 ChatServer(self) 构造时自动运行
    def start_admin_console(self):  pass   # 同上
    def run_client(self):           pass   # 已改由 ChatClient(self) 构造时自动运行
    def handle_command(self, cmd):  return self.client_inst.handle_command(cmd) if hasattr(self, 'client_inst') else None
    def send_message(self, msg):    return self.client_inst.send_message(msg)   if hasattr(self, 'client_inst') else None
    def receive_messages(self):     return self.client_inst.receive_messages()  if hasattr(self, 'client_inst') else None

    # -------------------- 与原文件逐字节相同的 EULA / Crypto / Ban 实现 --------------------
    def check_eula(self):
        """Check User License Agreement（与原实现逐字节相同）"""
        if not os.path.exists('eula.txt'):
            with open('eula.txt', 'w', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()}\neula=false\n"
                        "This software is provided 'as is' without any express or implied warranty,\n"
                        "including but not limited to warranties of merchantability, fitness for a particular purpose,\n"
                        "accuracy, completeness, or non-infringement of third-party rights.\n"
                        "\n"
                        "This software is provided \"as is\" without any form of express or implied warranty,\n"
                        "including but not limited to warranties of merchantability, fitness for a particular purpose, \n"
                        "accuracy, completeness, and non-infringement of third-party rights of the software. Software \n"
                        "developers and providers\n"
                        "all parties involved shall not be liable for any direct, indirect, incidental, special, or \n"
                        "consequential damages arising from the use or inability to use the software, regardless of \n"
                        "the nature of such damages\n"
                        "whether the harm is based on contract, tort or any other legal theory, and regardless of \n"
                        "whether the possibility of such harm has been notified.\n"
                        "\n"
                        "All legal consequences arising from the improper use of this software by users, including but \n"
                        "not limited to civil disputes, administrative penalties, criminal offenses, etc., shall be \n"
                        "borne by the users themselves, and software developers, providers, and all related \n"
                        "parties are not responsible. Even if the user's inappropriate behavior is based on software \n"
                        "vulnerabilities, defects, or\n"
                        "design flaws still require users to take responsibility for their own actions, but the software \n"
                        "provider will make every effort to promptly fix vulnerabilities and improve the software to reduce \n"
                        "risks. Software developers and providers\n"
                        "all relevant parties shall not be held responsible for any consequences arising from any \n"
                        "third party's use of this software for illegal or criminal activities or other improper behavior. \n"
                        "Users should make their own judgments\n"
                        "the legality and appropriateness of chat content and other user behaviors, as well as any losses \n"
                        "incurred due to reliance on or use of information provided by other users, shall be borne by the \n"
                        "users themselves to take on risks.\n")
            print("Please open eula.txt and change 'eula=false' to 'eula=true' to accept the user agreement")
            sys.exit(0)
        with open('eula.txt', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if len(lines) < 2 or 'eula=true' not in lines[1]:
                print("Please accept the user agreement: Open eula.txt and change 'eula=false' to 'eula=true'")
                sys.exit(0)

    def setup_crypto(self):
        """Setup Encryption System"""
        algo = self.config['encrypt_algorithm'].upper()
        key_length = int(self.config['key_length'])
        if not os.path.exists(self.config['key_file']) or not os.path.exists(self.config['pubkey_file']):
            print(f"Generating new {algo} key pair...")
            if algo == 'RSA':
                key = RSA.generate(key_length)
                private_key = key.export_key()
                public_key = key.publickey().export_key()

            # elif algo == 'DSA':
            #     key = DSA.generate(key_length)
            #     private_key = key.export_key()
            #     public_key = key.public_key().export_key()
            # elif algo == 'ECDSA':
            #     curve = 'p256'
            #     key = ECC.generate(curve=curve)
            #     private_key = key.export_key(format='PEM')
            #     public_key = key.public_key().export_key(format='PEM')
            
            else:
                raise ValueError(f"Unsupported encryption algorithm: {algo}")
            with open(self.config['key_file'], 'wb') as f:
                f.write(private_key)
            with open(self.config['pubkey_file'], 'wb') as f:
                f.write(public_key)
        with open(self.config['key_file'], 'rb') as f:
            self.private_key = f.read()
        with open(self.config['pubkey_file'], 'rb') as f:
            self.public_key = f.read()

    def load_bans(self):
        """Load Bans from JSON File"""
        if os.path.exists(self.bans_file):
            try:
                with open(self.bans_file, 'r', encoding='utf-8') as f:
                    bans = json.load(f)
                    self.banned_ips = set(bans.get('ips', []))
                    self.banned_users = set(bans.get('users', []))
            except Exception as e:
                print(f"Failed to load ban list: {e}")

    def save_bans(self):
        """Save Bans to JSON File"""
        try:
            with open(self.bans_file, 'w', encoding='utf-8') as f:
                json.dump({'ips': list(self.banned_ips), 'users': list(self.banned_users)}, f, indent=2)
        except Exception as e:
            print(f"Failed to save ban list: {e}")


if __name__ == '__main__':
    ChatApplication()