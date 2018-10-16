# sqlalchemy imports
from sqlalchemy import Column, create_engine, ForeignKey
from sqlalchemy import Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, backref

# other imports
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer)
from itsdangerous import BadSignature, SignatureExpired

# Initializations
Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in xrange(32))


class User(Base):
    '''
    User table

    Columns:
        id (int): PK for the table
        username (string)
        picture (string): url for the picture
        email (string):
        password_hash (string): hashed password created by hash_password
    '''
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True, nullable=False)
    picture = Column(String)
    email = Column(String)
    password_hash = Column(String(64))

    def hash_password(self, password):
        '''
        Function to create the hashed password and assign it to self

        Args:
            password (string): user entered password
        '''
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        '''
        Function to verify the given password against the stored hash password

        Args:
            password (string): user entered password to compare

        Returns:
            bool: True if password given is correct and False otherwise
        '''
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        '''
        Function to create an auth token for the user and mask the user id in it

        Args:
            expiration (int): number to specify the length of validity of the token

        Returns:
            serializer: auth token with the user id
        '''
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        '''
        Function to verify the given auth token

        Args:
            token (string): auth token

        Returns:
            int: user id if a valid token
            None: if an invalid token is given
        '''
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user_id = data['id']
        return user_id


class Category(Base):
    '''
    Category table

    Columns:
        id (int): identifier for the category, autogenerated
        name (string): name of the category
        user_id (int): foreignkey refering to the user that created the
        user (User): RelationShip - user object created the category
        items (Item): RelationShip - list of items that belong to the category
    '''
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))

    user = relationship(User)

    @property
    def serializeWithItems(self):
        '''
        Returns:
            object data in a serializable format with the list of items
        '''
        return {
            'id': self.id,
            'name': self.name,
            'item': [item.serialize for item in self.items]
        }

    @property
    def serializeWithoutItems(self):
        '''
        Returns:
            object data in a serializable format without the list of items
        '''
        return {
            'id': self.id,
            'name': self.name
        }

class Item(Base):
    '''
    Item table

    Columns:
        id (int): identifier for the item, autogenerated
        title (string): name of the item
        description (text)
        category_id (int)
        user_id (int)
        category (Category): RelationShip - many-to-one relationship
        user (User): RelationShip - many-to-one relationship
    '''
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    title = Column(String(80), index=True, nullable=False)
    description = Column(Text)
    category_id = Column(Integer, ForeignKey('category.id'))
    user_id = Column(Integer, ForeignKey('user.id'))

    # use cascade='delete,all' to propagate the deletion of the category onto
    # its items
    category = relationship(
        Category,
        backref=backref('items', uselist=True, cascade='all, delete'))
    user = relationship(User)

    @property
    def serialize(self):
        '''
        Returns:
            object data in a serializable format
        '''
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category_id': self.category_id
        }


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)