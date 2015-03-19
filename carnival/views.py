from gevent import monkey
monkey.patch_all()
from flask.ext.paginate import Pagination
import carnival

import argparse
from operator import itemgetter
import os

import flask
from flask.ext.login import login_required, \
    login_user, logout_user, current_user

#from flask_debugtoolbar import DebugToolbarExtension
from forms import UpdateForm, LoginForm
import rethinkdb as r
from flask.ext.socketio import emit

RDB_HOST = os.environ.get('RDB_HOST') or 'localhost'
RDB_PORT = os.environ.get('RDB_PORT') or 28015
updatesdb = 'updatesdb'

thread = None

app = carnival.app
socketio = carnival.socketio
login_manager = carnival.login_manager


class configuration(object):
    SECRET_KEY = 'newapphurray'
    CSRF_ENABLED = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False


class User():
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return True

    def get_id(self):
        return unicode(self.username)


def dbSetup():
    connection = r.connect(host=RDB_HOST, port=RDB_PORT)
    connection.use(updatesdb)
    try:
        # DATABASE
        r.db_create(updatesdb).run(connection)
        # TABLES
        r.table_create('updates').run(connection)
        r.table_create('users').run(connection)
        r.table_create('log').run(connection)
        # INDEXES
        r.table('updates').index_create('timestamp').run(connection)
        r.table('updates').indexCreate("tags", multi=True).run(connection)
        r.table('users').index_create('username').run(connection)
        r.table('log').index_create('timestamp').run(connection)
        print ('Database setup completed. Now run the app without --setup: '
               '`python downloaddb.py`')
    except r.RqlRuntimeError, e:
        print e
    finally:
            connection.close()


def connectDb():
    try:
        rdb_conn = r.connect(host=RDB_HOST, port=RDB_PORT, db=updatesdb)
        rdb_conn.use(updatesdb)
        return rdb_conn
    except r.RqlDriverError:
        raise Exception("No database connection could be established.")


@app.before_request
def before_request():
    flask.g.user = current_user


@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.g.user is not None and flask.g.user.is_authenticated():
        return flask.redirect(flask.url_for('manage'))
    form = LoginForm(flask.request.form)
    print form.errors
    if flask.request.method == 'GET':
        return flask.render_template("login.html", form=form)
    if form.validate_on_submit():
        username = flask.request.form['username']
        password = flask.request.form['passwd']
        print username
        print password
        registered_user = r.db('updatesdb').table('users').filter({
            'username': username,
            'password': password
            }).limit(1).run(connectDb())
        if len(list(registered_user)) == 0:
            flask.flash('Username or Password is invalid', 'error')
            return flask.redirect(flask.url_for('login'))
        print "IM HERE_-----------------------------------------------"
        user = User(username=username, password=password)
        login_user(user)
        flask.flash("Logged in successfully.", "success")
        return flask.redirect(flask.url_for("manage"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return flask.redirect('login')


@app.route('/stream')
def stream():
    return flask.render_template('stream.html')


@app.route("/archive", methods=["GET"])
def getupdates():
    if not flask.request.json:
        flask.abort(404)
    rq = flask.request.get_json()
    ts = rq['last']
    if 'count' in rq.keys():
        count = rq['count']
    else:
        count = 10  # hardcoded
    """
    ts = "2015-01-14T23:42:37.928+00:00"
    """
    cursor = r.db('updatesdb').table('updates'
            ).filter(
            r.row["timestamp"].lt(ts)
            ).limit(count).run(connectDb())
    updates = sorted(list(cursor), key=itemgetter('timestamp'), reverse=True)
    return flask.jsonify(items=updates, count=len(updates)), 200


@app.route("/latest", methods=["GET"])
def latest():
    if not flask.request.json:
        flask.abort(404)
    rq = flask.request.get_json()
    ts = rq['last']
    """
    ts = "2015-01-14T23:42:37.928+00:00"
    """
    cursor = r.db('updatesdb').table('updates'
                ).filter(r.row["timestamp"].gt(ts)
                ).run(connectDb())
    updates = sorted(list(cursor), key=itemgetter('timestamp'), reverse=True)
    return flask.jsonify(items=updates, count=len(updates)), 200


@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    form = UpdateForm(flask.request.form)
    if flask.request.method == 'POST' and form.validate():
        update = {
            'head': form.head.data,
            'body': form.body.data,
            'tags': form.tags.data + ['all'],
            'timestamp': r.now().to_iso8601(),
            'author': flask.g.user.get_id()
            }
        res = r.table('updates').insert(
            update, return_changes=True
            ).run(connectDb())

        item = r.table('updates').get(
            res[u'generated_keys'][0]
            ).run(connectDb())
        flask.flash('New Update posted: %s' % (form.head.data), 'success')
        form = UpdateForm()
        push_new_update(item)
        return flask.render_template('post.html', form=form), 200
    elif form.errors:
        flask.flash('All form fields are required', 'danger')
    return flask.render_template(
        'post.html',
        form=form,
        username=flask.g.user.get_id()), 200


@app.route("/manage", methods=["GET"])
@login_required
def manage():
    search = False
    try:
        page = int(flask.request.args.get('page', 1))
    except ValueError:
        page = 1
    cursor = r.table('updates').order_by(
        index=(r.desc('timestamp'))
        ).slice(
        10*(page-1), 10*page
        ).run(connectDb())
    total = r.table('updates').count().run(connectDb())
    updates = list(cursor)
    pagination = Pagination(page=page,
                            total=total,
                            record_name='updates',
                            per_page=10,
                            show_single_page=False,
                            css_framework="bootstrap3",
                            link_size='md')
    return flask.render_template('manage.html',
                                 updates=updates,
                                 per_page=10,
                                 pagination=pagination,
                                 search=search,
                                 page=page,
                                 username=flask.g.user.get_id()
                                 ), 200


def write_to_log(keys, action):
    cursor = r.table('logs').insert(
        r.db('updatesdb').table('updates').get_all(*keys)
        ).run(connectDb())
    items = list(cursor)
    log = {
        "action": action,
        "timestamp": r.now().to_iso8601(),
        "items": {
            "items": items,
            "total": len(items)
            },
        "user": flask.g.user.get_id()
        }
    r.table('logs').insert(log).run(connectDb())


@app.route("/delete/<key>", methods=["GET"], endpoint='delete_GET')
@app.route("/delete", methods=["DELETE", "GET"])
@login_required
def delete(key=None):
    if flask.request.method == 'DELETE':
        if not flask.request.json:
            flask.abort(404)
        rq = flask.request.get_json()
        if not 'key' in rq.keys():
            return flask.jsonify(
                response="Need key to delete {...,'key':'key_to_delete', ...}"
                )
        else:
            key = rq['id']
        try:
            r.table('updates').get(key).delete().run(connectDb())
            write_to_log(list(key), 'delete')
            return flask.jsonify(response='delete success'), 200
        except Exception:
            return flask.jsonify(response='Could not delete'), 304
    elif flask.request.method == 'GET':
        try:
            page = int(flask.request.args.get('page', 1))
        except ValueError:
            page = 1
        if key is None:
            return flask.redirect(flask.url_for("manage"))
        try:
            r.table('updates').get(key).delete().run(connectDb())
            write_to_log(list(key), 'delete')
            return flask.redirect(flask.url_for("manage"))
        except Exception:
            return flask.redirect(flask.url_for("manage", page=page))
    flask.abort(404)


#SOCKET-IO
def push_new_update(upd):
    socketio.emit('new update',
                  upd,
                  namespace='/stream')


@socketio.on('connect', namespace='/stream')
def test_connect():
    emit('my response', {'data': 'Connected', 'count': 0})


@socketio.on('disconnect', namespace='/stream')
def test_disconnect():
    print('Client disconnected')


@login_manager.user_loader
def load_user(username):
    registered_user = r.db('updatesdb').table('users').filter(
        {'username': username}
    ).limit(1).run(connectDb())
    valid = list(registered_user)
    if len(valid) == 0:
        return None
    else:
        user = valid[0]
        return User(user['username'], user['password'])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--setup', dest='run_setup', action='store_true')
    args = parser.parse_args()
    if args.run_setup:
        dbSetup()
