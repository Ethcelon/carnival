from gevent import monkey
monkey.patch_all()
import flask
from flask_wtf.csrf import CsrfProtect
from flask.ext.login import LoginManager
from flask_bootstrap import Bootstrap
from flask.ext.socketio import SocketIO

app = flask.Flask("gusac carnival 2015")
app.debug = True
CsrfProtect(app)
Bootstrap(app)
#toolbar = DebugToolbarExtension(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please login"

login_manager.init_app(app)


class configuration(object):
    SECRET_KEY = 'newapphurray'
    CSRF_ENABLED = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False

app.config.from_object(configuration)

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000)
