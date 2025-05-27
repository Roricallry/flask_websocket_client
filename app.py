from flask import Flask, render_template
from threading import Thread
from socket_client import start_socket

client = Flask(__name__)
client_id = "A"  # 模拟多个客户端
server_url = "ws://127.0.0.1:5000"

@client.route('/')
def index():
    return render_template('home.html', server_url=server_url)

if __name__ == '__main__':
    Thread(target=start_socket).start()
    client.run(port=5001)