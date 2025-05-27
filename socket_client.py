import socketio
import uuid
import time
import threading
from flask_socketio import SocketIO, send, emit, disconnect


# 生成设备ID（如果未注册，需先通过服务端API创建）
# curl -X POST http://localhost:5000/device
DEVICE_ID = "f912c125-b47d-4f4e-be05-5009185e85b4"  # 示例：替换为实际设备ID
PASSWORD = ""     # 如果设备设置了密码

# 创建客户端实例
client_sio = socketio.Client()

@client_sio.event
def connect():
    """连接成功回调"""
    print('[成功] 已连接到服务器')

@client_sio.event
def message(data):
    print(f'收到服务端消息: {data}')

@client_sio.event
def status(data):
    """接收服务端状态通知（如心跳响应）"""
    print(f'[状态] {data}')

@client_sio.event
def error(data):
    """接收错误消息"""
    print(f'[错误] {data}')
    client_sio.disconnect()

@client_sio.event
def disconnect():
    """断开连接回调"""
    print('[警告] 连接已断开')

def send_heartbeat():
    """定时发送心跳包（每30秒一次）"""
    while True:
        time.sleep(30)
        try:
            client_sio.emit('heartbeat')
        except:
            break

def start_socket():
    try:
        # 连接时传递 device_id 和 password
        client_sio.connect(
            f'http://localhost:5000?device_id={DEVICE_ID}&password={PASSWORD}',
            transports=['websocket']
        )

        # 启动心跳线程
        heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
        heartbeat_thread.start()

        # 用户输入循环
        while True:
            msg = input("输入消息（或输入 'exit' 退出）: ")
            if msg.lower() == 'exit':
                client_sio.disconnect()
                break
            client_sio.send(msg)

    except socketio.exceptions.ConnectionError as e:
        print(f'[错误] 连接失败: {e}')
    except KeyboardInterrupt:
        client_sio.disconnect()