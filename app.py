'''
app.py contains all of the server application
this is where you'll find all of the get/post request handlers
the socket event handlers are inside of socket_routes.py
'''

from flask import Flask, render_template, request, abort, url_for, session, redirect, jsonify
from flask_socketio import SocketIO
import db
import secrets
from sqlalchemy.exc import IntegrityError
from util import generate_salt, hash_password, verify_password

# import logging

# this turns off Flask Logging, uncomment this to turn off Logging
# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)

app = Flask(__name__)

# secret key used to sign the session cookie
app.config['SECRET_KEY'] = secrets.token_hex()
socketio = SocketIO(app)

# don't remove this!!
import socket_routes

# index page
@app.route("/")
def index():
    return render_template("index.jinja")

# login page
@app.route("/login")
def login():    
    return render_template("login.jinja")

# handles a post request when the user clicks the log in button
@app.route("/login/user", methods=["POST"])
def login_user():
    if not request.is_json:
        abort(404)

    username = request.json.get("username")
    password = request.json.get("password")

    user = db.get_user(username)
    if user is None:
        return "Error: User does not exist!"

    # if user.password != password:
    if not verify_password(user.password, password, user.salt):
        return "Error: Password does not match!"
    session['username'] = username
    session['logged_in'] = True
    return url_for('home', username=request.json.get("username"))

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return url_for('index')

# handles a get request to the signup page
@app.route("/signup")
def signup():
    return render_template("signup.jinja")

# handles a post request when the user clicks the signup button
@app.route("/signup/user", methods=["POST"])
def signup_user():
    if not request.is_json:
        abort(404)
    username = request.json.get("username")
    password = request.json.get("password")

    if db.get_user(username) is None:
        salt = generate_salt()
        # db.insert_user(username, password)
        db.insert_user(username, hash_password(password, salt), salt=salt)
        return url_for('home', username=username)
    return "Error: User already exists!"

# handler when a "404" error happens
@app.errorhandler(404)
def page_not_found(_):
    return render_template('404.jinja'), 404

# home page, where the messaging app is
@app.route("/home")
def home():
    if 'username' not in session:
        return redirect('/')
    if request.args.get("username") is None:
        abort(404)

    username = request.args.get("username")
    #
    # row_list = db.get_friend_by_username(request.args.get("username"))
    # friend_list = []
    # for row in row_list:
    #     if row.sender_username == username:
    #         friend_list.append(row.receiver_username)
    #     else:
    #         friend_list.append(row.sender_username)
    applying_list = db.get_user_applying(username)
    applied_list = db.get_user_applied(username)
    friend_list = db.get_user_friend(username)
    # applying_list = ["a","b"]
    # applied_list = ["w"]
    # friend_list = ["n"]
    return render_template("home.jinja", 
                           # username=request.args.get("username"),
                           username=username,
                           applying_list=applying_list,
                           applied_list=applied_list,
                           friend_list=friend_list)

# @app.route("/add_friend", methods=["POST"])
# def add_friend():
#     from_user = request.json.get("from_user")
#     to_user = request.json.get("to_user")
#     try:
#         db.insert_apply_message(from_user, to_user, True)
#         return "success"
#     except IntegrityError as e:
#         return "error"
@app.route("/applying")
def get_applying():
    if 'username' not in session:
        return redirect('/')
    username = request.args.get("username")
    applying_list = [user.to_user for user in db.get_user_applying(username)]
    res = {
        "applying_list": applying_list
    }
    return jsonify(res)


@app.route("/get_message")
def get_message():
    if 'username' not in session:
        return redirect('/')
    from_user = request.args.get("from_user")
    to_user = request.args.get("to_user")
    message_list = db.get_message(from_user, to_user) + db.get_message(to_user, from_user)
    res = {
        "message_list": message_list
    }
    return jsonify(res)
@app.route("/is_applied")
def is_applied():
    if 'username' not in session:
        return redirect('/')
    from_user = request.args.get("from_user")
    to_user = request.args.get("to_user")
    applying_list = db.get_user_applying(from_user)
    applying_users = []
    for applying in applying_list:
        applying_users.append(applying['username'])
    if to_user in applying_users:
        return {
            "is_applied": True
        }
    else:
        return {
            "is_applied": False
        }

if __name__ == '__main__':
    # socketio.run(app, allow_unsafe_werkzeug=True)
    socketio.run(app, allow_unsafe_werkzeug=True, ssl_context=('C:/Users/86189/OneDrive/desktop/INFO2222-Project/localhost+2.pem','C:/Users/86189/OneDrive/desktop/INFO2222-Project/localhost+2-key.pem'))
    # socketio.run(app)
