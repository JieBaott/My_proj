from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User,ApplyMessage # 确保这里正确导入了Base和User类

# 创建数据库引擎，这里使用SQLite
# 请根据实际情况调整数据库的URL
engine = create_engine('sqlite:///database/main.db', echo=False)

# 创建Session类
Session = sessionmaker(bind=engine)

# 创建Session实例
session = Session()

# 查询所有用户
users = session.query(User).all()

message = session.query(ApplyMessage).all()
for user in message:
    print(user.sender_username)
    print(user.receiver_username)
    print(user.status)
# 打印每个用户的用户名和密码
for user in users:
    print(f"Username: {user.username}, Password: {user.password}")

# 关闭会话
session.close()
