'''
db
database file, containing all the logic to interface with the sql database
'''

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import *
from werkzeug.security import generate_password_hash

from pathlib import Path

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
def insert_user(username: str, password: str):
    with Session(engine) as session:
        user = User(username=username, password=generate_password_hash(password)) #@@@@@@@@@
        session.add(user)
        session.commit()

# gets a user from the database
def get_user(username: str):
    with Session(engine) as session:
        return session.get(User, username)
    
# new  

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
