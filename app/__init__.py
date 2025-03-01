from flask import Flask
from flask_sock import Sock
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO

socketio = SocketIO()
sock = Sock() 
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    socketio.init_app(app)
    sock.init_app(app) 

    from .routes import main
    app.register_blueprint(main)

    return app