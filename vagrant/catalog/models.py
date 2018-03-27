from sqlalchemy import Column, Integer, String, create_engine, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), index=True)
    email = Column(String(250), nullable=False)
    password_hash = Column(String(64))
    token = Column(String(255))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    @property
    def serialize(self):
      return {
          'id': self.id,
           'name': self.name,
           'email': self.email,
       }


##Create an item class for our database
class Item(Base):
    __tablename__ = 'item'


    name = Column(String(80), nullable = False)
    category = Column(String(80))
    id = Column(Integer, primary_key = True)
    description = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'), nullable = False)
    user = relationship(User)

    @property
    def serialize(self):
       return {
          'id': self.id,
           'name': self.name,
           'category': self.category,
           'description' : self.description,
           'user_id' : self.user_id
       }

engine = create_engine('sqlite:///itemswithusers.db')
Base.metadata.create_all(engine)
