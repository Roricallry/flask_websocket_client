import socketio

# 创建客户端实例
client_sio = socketio.Client()

@client_sio.event
def connect():
    print('已连接到服务器')

@client_sio.event
def message(data):
    print(f'收到服务端消息: {data}')

@client_sio.event
def disconnect():
    print('断开连接')

def start_socket():
    # 连接到服务端
    try:
        client_sio.connect('http://localhost:5000')
    except socketio.exceptions.ConnectionError as e:
        print(f"连接失败: {e}")
        exit()

    while True:
        msg = input("输入消息: ")
        client_sio.send(msg)