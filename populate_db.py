# Database imports
from models import Base, User, Category, Item
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

# Initializations
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# 1. Create users
user1 = User(username="user1", picture="", email="", password_hash="")
user2 = User(username="user2", picture="", email="", password_hash="")
user3 = User(username="user3", picture="", email="", password_hash="")
session.add(user1)
session.add(user2)
session.add(user3)
session.commit()

# 2. Create categories
category1 = Category(name="category1", user=user1)
category2 = Category(name="category2", user=user1)
category3 = Category(name="category3", user=user2)
category4 = Category(name="category4", user=user2)
category5 = Category(name="category5", user=user2)
session.add(category1)
session.add(category2)
session.add(category3)
session.add(category4)
session.add(category5)
session.commit()

# 3. Create Items
item1 = Item(title="item1", description="", category=category1, user=user1)
item2 = Item(title="item2", description="", category=category1, user=user1)
item3 = Item(title="item3", description="", category=category2, user=user1)
item4 = Item(title="item4", description="", category=category2, user=user1)
item5 = Item(title="item5", description="", category=category2, user=user1)
item6 = Item(title="item6", description="", category=category3, user=user2)
item7 = Item(title="item7", description="", category=category4, user=user2)
item8 = Item(title="item8", description="", category=category4, user=user2)
session.add(item1)
session.add(item2)
session.add(item3)
session.add(item4)
session.add(item5)
session.add(item6)
session.add(item7)
session.add(item8)
session.commit()
