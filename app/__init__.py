from flask import Flask
from flask_sock import Sock
from flask_socketio import SocketIO
from config import Config
from app.extensions import mail,db

socketio = SocketIO()
sock = Sock() 

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    mail.init_app(app)
    db.init_app(app)
    socketio.init_app(app)
    sock.init_app(app) 

    from .routes import main
    app.register_blueprint(main)
    
    with app.app_context():
        db.create_all()  # ✅ Ensures tables are created

    
    return app
