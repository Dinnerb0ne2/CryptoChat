import os
import threading
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Set, Tuple, Optional

class ChatWebServer:
    def __init__(self, client, port: int = 25567):
        self.client = client  # 关联ChatClient实例
        self.port = port
        self.web_root = os.path.join(os.path.dirname(__file__), '../web')
        self.message_queue: List[dict] = []  # 消息队列
        self.clients: Set[str] = set()  # 客户端ID集合
        self.lock = threading.Lock()  # 线程锁
        
        # 启动HTTP服务器
        self.start_http_server()

    def start_http_server(self):
        server_address = ('0.0.0.0', self.port)
        httpd = HTTPServer(server_address, self._get_request_handler())
        
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        print(f"WebUI running at http://localhost:{self.port}")

    def _get_request_handler(self):
        server = self  # 保存当前实例引用
        
        class RequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed_path = urlparse(self.path)
                
                if parsed_path.path == '/api/messages':
                    self._handle_messages_request(parsed_path.query)
                    return
                
                self._handle_static_file_request(parsed_path.path)

            def do_POST(self):
                parsed_path = urlparse(self.path)
                
                if parsed_path.path == '/api/send':
                    self._handle_send_request()
                    return
                
                # 404 Not Found!
                self.send_error(404)

            def _handle_static_file_request(self, path: str):
                if path == '/':
                    path = '/index.html'
                
                file_path = os.path.join(server.web_root, path[1:])
                
                if not os.path.exists(file_path) or not os.path.isfile(file_path):
                    self.send_error(404)
                    return
                
                mime_type = self._get_mime_type(file_path)
                
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    self.send_response(200)
                    self.send_header('Content-Type', mime_type)
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                except Exception as e:
                    self.send_error(500, str(e))

            def _handle_messages_request(self, query: str):
                params = parse_qs(query)
                last_id = int(params.get('last_id', [0])[0])
                
                start_time = time.time()
                new_messages = []
                
                while time.time() - start_time < 6:  # 6秒超时
                    with server.lock:
                        new_messages = [msg for msg in server.message_queue 
                                      if msg.get('id', 0) > last_id]
                        
                        if new_messages:
                            break
                    
                    # 4 tick
                    time.sleep(0.25)
                
                response = {
                    'messages': new_messages,
                    'last_id': max((msg.get('id', 0) for msg in new_messages), default=last_id)
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))

            def _handle_send_request(self,):
                # 请求
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                
                try:
                    data = json.loads(post_data)
                    
                    if not data or 'type' not in data or 'content' not in data:
                        self.send_error(400, 'Invalid request data')
                        return
                    
                    result = {'success': True}
                    
                    if data['type'] == 'message':
                        # 发送聊天消息
                        server.client.send_message(data['content'])
                    elif data['type'] == 'command':
                        # 执行客户端命令
                        command_result = server.client.handle_command(data['content'])
                        result['command_result'] = command_result
                    else:
                        result['success'] = False
                        result['error'] = 'Unknown message type'
                    
                    # 发送响应
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps(result).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    self.send_error(400, 'Invalid JSON')
                except Exception as e:
                    self.send_error(500, str(e))

            def _get_mime_type(self, file_path: str) -> str:
                if file_path.endswith('.html'):
                    return 'text/html'
                elif file_path.endswith('.css'):
                    return 'text/css'
                elif file_path.endswith('.js'):
                    return 'text/javascript'
                elif file_path.endswith('.json'):
                    return 'application/json'
                else:
                    return 'application/octet-stream'

            # 禁用默认日志输出
            def log_message(self, format, *args):
                return
        
        return RequestHandler

    def broadcast_to_web(self, message: dict):
        with self.lock:
            message_id = len(self.message_queue) + 1
            message_with_id = {**message, 'id': message_id, 'timestamp': time.time()}
            self.message_queue.append(message_with_id)
            
            # 限制队列大小(防止内存溢出)
            if len(self.message_queue) > 1000:
                self.message_queue = self.message_queue[-500:]
