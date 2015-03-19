import carnival
import carnival.views
app = carnival.app

if __name__ == "__main__":
    carnival.socketio.run(app)
