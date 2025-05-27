pip list   
Package            Version
------------------ ---------
bidict             0.23.1
blinker            1.9.0
certifi            2025.4.26
charset-normalizer 3.4.2
click              8.2.1
colorama           0.4.6
Flask              3.1.1
Flask-SocketIO     5.5.1
h11                0.16.0
idna               3.10
itsdangerous       2.2.0
Jinja2             3.1.6
MarkupSafe         3.0.2
pip                25.1.1
python-engineio    4.12.1
python-socketio    5.13.0
requests           2.32.3
simple-websocket   1.1.0
urllib3            2.4.0
websocket-client   1.8.0
Werkzeug           3.1.3
wsproto            1.2.0

客户端一定要装的库pip install websocket-client
不能在pycharm中配置好后，在外面把整个文件夹复制一份充当客户端B，一定要另起炉灶，记得还要修改端口

在server启动后再运行client:python app.py
server在https://github.com/Roricallry/flask_websocket_server
