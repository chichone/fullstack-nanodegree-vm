from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine

Base = declarative_base()

##Create an item class for our database
class Item(Base):
    __tablename__ = 'item'


    name = Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(250))

    @property
    def serialize(self):
       return {
          'id': self.id,
           'name': self.name,
           'description' : self.description
       }



engine = create_engine('sqlite:///items.db')
Base.metadata.create_all(engine)
