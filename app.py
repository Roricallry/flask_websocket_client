import os
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template
from threading import Thread

from cert_apply import generate_device_certificate
from socket_client import start_socket, DEVICE_ID, SERVER_URL, emit_user_decision, exit_event
from flask import request, jsonify
import json
import threading



app = Flask(__name__)

from flask_socketio import SocketIO, emit
socketio = SocketIO(app, async_mode='threading')

def start_websocket_thread():
    # 启动远程连接并传递socketio对象
    start_socket(socketio)

app.secret_key = os.getenv('SECRET_KEY', 'local-secret-key')

IS_ACTIVE = False
USER_EMAIL = '<EMAIL>'

@app.route('/')
def index():
    if IS_ACTIVE:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/send-code', methods=['POST'])
def send_code():
    email = request.form.get('email')
    action = request.form.get('action')
    print(email, action)
    if not email:
        flash('请输入邮箱', 'danger')
        return redirect(url_for('index'))

    try:
        res = requests.post(f'{SERVER_URL}/send-code', json={'email': email, 'action': action}, verify=False)
        if res.status_code == 200:
            flash('验证码已发送，请查收邮箱', 'success')
        else:
            flash(res.json().get('message', '验证码发送失败'), 'danger')
    except Exception as e:
        flash(f'请求失败: {e}', 'danger')
    if action == 'login':
        return render_template('login.html', email=email)
    else:
        return render_template('unbind_email.html', email=email)

@app.route('/login', methods=['POST', 'GET'])
def login():
    global IS_ACTIVE
    if IS_ACTIVE:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        code = request.form.get('code')

        try:
            print(request.form.to_dict())
            res = requests.post(f'{SERVER_URL}/user_login', json={'email': email, 'code': code, 'device_id': DEVICE_ID},
                                verify=False)
            if res.status_code == 200:

                IS_ACTIVE = True
                global USER_EMAIL
                USER_EMAIL = email
                exit_event.clear()  # 置exit_event为False
                threading.Thread(target=start_websocket_thread, daemon=True).start()

                flash('登录成功', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash(res.json().get('message', '登录失败'), 'danger')
        except Exception as e:
            flash(f'请求失败: {e}', 'danger')

        return render_template('login.html', email=email)
    else:
        return render_template('login.html')

@app.route('/unbind_email', methods=['POST', 'GET'])
def unbind_mail():
    global USER_EMAIL
    global IS_ACTIVE
    if not IS_ACTIVE:
        return redirect(url_for('index'))
    if request.method == 'POST':
        code = request.form.get('code')

        try:
            print(request.form.to_dict())
            res = requests.post(f'{SERVER_URL}/unbind_email',
                                json={'email': USER_EMAIL, 'code': code, 'device_id': DEVICE_ID}, verify=False)
            if res.status_code == 200:

                IS_ACTIVE = False
                USER_EMAIL = '<EMAIL>'
                exit_event.set() # 断开websocket连接(thread_event方法告诉线程该退出了)

                flash('解绑成功', 'success')
                return redirect(url_for('index'))
            else:
                flash(res.json().get('message', '解绑失败'), 'danger')
        except Exception as e:
            flash(f'请求失败: {e}', 'danger')

        return render_template('unbind_email.html', email=USER_EMAIL)
    else:
        return render_template('unbind_email.html', email=USER_EMAIL)

@app.route('/dashboard')
def dashboard():
    if not IS_ACTIVE:
        return redirect(url_for('login'))

    return render_template('dashboard.html', user_email=USER_EMAIL)

@app.route('/log-statistics', methods=['POST'])
def log_statistics():
    data = request.get_json()
    decision = data.get('decision')
    electricity_usage = data.get('electricity_usage')

    emit_user_decision(DEVICE_ID, decision, electricity_usage)

    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    generate_device_certificate() # 若本地还没有证书，则向服务器提交csr申请证书
    app.run(host='0.0.0.0', port=5001)
