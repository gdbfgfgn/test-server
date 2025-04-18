import http.server
import socketserver
import json
import os
import hashlib

DB_FILE = "users.json"
PORT = 8000

def load_users():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r', encoding='utf-8') as f:  # Указываем кодировку при чтении
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_users(users):
    with open(DB_FILE, 'w', encoding='utf-8') as f:  # Указываем кодировку при записи
        json.dump(users, f, indent=4, ensure_ascii=False)  # Используем ensure_ascii=False
def hash_password(password):
    salt = os.urandom(16)  # Генерация соли
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)  # Хеширование с солью
    return salt.hex() + ":" + hashed_password.hex()  # Сохраняем соль и хеш

def verify_password(password, hashed_password_with_salt):
    salt_hex, hashed_password_hex = hashed_password_with_salt.split(':')
    salt = bytes.fromhex(salt_hex)
    hashed_password_check = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password_check.hex() == hashed_password_hex


class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/web.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        elif self.path == '/users':
            self.send_response(200)
            self.send_header('Content-type', 'application/json; charset=utf-8') # Указываем кодировку в заголовке
            self.end_headers()
            users = load_users()
            user_list = [{"username": user["username"]} for user in users]
            self.wfile.write(json.dumps(user_list, ensure_ascii=False).encode('utf-8'))
        else:
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        if self.path == '/register':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
                username = data.get('username')
                password = data.get('password')

                if not username or not password:
                    self.send_response(400)
                    self.send_header('Content-type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write("Ошибка: Не все поля заполнены".encode('utf-8'))
                    return

                users = load_users()
                if any(user['username'] == username for user in users):
                    self.send_response(409)
                    self.send_header('Content-type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write("Ошибка: Пользователь с таким именем уже существует".encode('utf-8'))
                    return
                hashed_password = hash_password(password)
                users.append({'username': username, 'password': hashed_password})
                save_users(users)

                self.send_response(201)
                self.send_header('Content-type', 'application/json; charset=utf-8') # Указываем кодировку в заголовке
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Пользователь успешно зарегистрирован"}, ensure_ascii=False).encode('utf-8'))
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write("Ошибка: Неверный формат данных".encode('utf-8'))
            except Exception as e:
                print(f"Произошла ошибка: {e}")
                self.send_response(500)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write("Ошибка сервера".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print(f"Сервер запущен на порту {PORT}")
    httpd.serve_forever()
