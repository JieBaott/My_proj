'''
db
database file, containing all the logic to interface with the sql database
'''
import base64

from sqlalchemy import create_engine, or_, and_
from sqlalchemy.orm import Session

import db
from models import *

from pathlib import Path
from util import decrypt_message

# creates the database directory
Path("database") \
    .mkdir(exist_ok=True)

# "database/main.db" specifies the database file
# change it if you wish
# turn echo = True to display the sql output
engine = create_engine("sqlite:///database/main.db", echo=False)

# initializes the database
Base.metadata.create_all(engine)

# inserts a user to the database
def insert_user(username: str, password: str, salt: str ):
    with Session(engine) as session:
        user = User(username=username, password=password, salt=salt)
        session.add(user)
        session.commit()

# gets a user from the database
def get_user(username: str):
    with Session(engine) as session:
        return session.get(User, username)
    
# def get_friend_by_username(username: str):
#     with Session(engine) as session:
#         row_list = session.query(ApplyMessage).filter(and_(or_(ApplyMessage.sender_username == username,
#                                                                ApplyMessage.receiver_username == username),
#                                                             ApplyMessage.status == True)).all()
#         return row_list

def get_password_by_username(username):
    with Session(engine) as session:
        user = session.get(User, username)
        return user.password
def get_user_applying(username):
    with Session(engine) as session:
        row_list = session.query(ApplyMessage).filter(ApplyMessage.from_user == username).all()
        applying_friends = []
        for row in row_list:
            item = {"username": row.to_user, "status": row.status}
            applying_friends.append(item)
        return applying_friends

def get_user_applied(username):
    with Session(engine) as session:
        row_list = session.query(ApplyMessage).filter(ApplyMessage.to_user == username).all()
        applied_friends = []
        for row in row_list:
            item = {"username": row.from_user, "status": row.status}
            applied_friends.append(item)
        return applied_friends
def get_user_friend(username):
    with Session(engine) as session:
        row_list = session.query(ApplyMessage).filter(and_(ApplyMessage.status == True,
                                                           or_(ApplyMessage.to_user == username,
                                                               ApplyMessage.from_user == username))).all()
        friend_list = []
        for row in row_list:
            if row.from_user == username:
                friend_list.append(row.to_user)
            else:
                friend_list.append(row.from_user)

        return friend_list

def insert_apply_message(username, friend_name):
    with Session(engine) as session:
        apply_message = ApplyMessage(from_user=username, to_user=friend_name, status=False)
        session.add(apply_message)
        session.commit()

def update_apply_status(username, to_user):
    with Session(engine) as session:
        row = session.query(ApplyMessage).filter(
            and_(ApplyMessage.to_user == username, ApplyMessage.from_user == to_user)).first()
        row.status = True
        session.commit()

def insert_message(from_user, to_user, content):
    with Session(engine) as session:
        message = Message(from_user=from_user, to_user=to_user, content=content)
        session.add(message)
        session.commit()


def get_message(from_user, to_user):
    with Session(engine) as session:
        row_list = session.query(Message).order_by(Message.create_time.asc()).filter(
            and_(Message.to_user == to_user, Message.from_user == from_user))
        message_list = []
        for row in row_list:
            encrypted_password_bytes = bytes.fromhex(db.get_password_by_username(from_user))
            key = base64.urlsafe_b64encode(encrypted_password_bytes)
            decrypted_message = decrypt_message(row.content, key)
            item = {
                "from_user": row.from_user,
                "to_user": row.to_user,
                "content": decrypted_message
            }
            message_list.append(item)
        return message_list

def set_user_online(username):
    with Session(engine) as session:
        user = session.query(User).filter_by(username=username).first()
        if user:
            user.is_online = True
            session.commit()


def set_user_offline(username):
    with Session(engine) as session:
        user = session.query(User).filter_by(username=username).first()
        if user:
            user.is_online = False
            session.commit()


def get_online_users():
    with Session(engine) as session:
        online_users = session.query(User).filter(User.status == True).all()
        session.close()
        return online_users



# a = get_friend_by_username("j")
# for i in a:
#     print(i.sender_username, i.receiver_username)
