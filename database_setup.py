import sys
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import datetime

Base = declarative_base()


class User(Base):
    __tablename__='user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)

class Place(Base):
    __tablename__ = 'place'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)

    @property
    def serialize(self):
        return {
            'name':self.name
            }

class Blog(Base):
    __tablename__ = 'blog'
    id = Column(Integer, primary_key=True)
    subject = Column(String, nullable=False)
    content = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    place_id = Column(Integer, ForeignKey('place.id'))
    place = relationship(Place)
    image = Column(String)
    created_on = Column(DateTime, default=datetime.datetime.utcnow)
    updated_on = Column(DateTime, default=datetime.datetime.utcnow,
                      onupdate = datetime.datetime.now)

    @property
    def serialize(self):
        return {
            'subject': self.subject,
            'content': self.content,
            'image': self.image,
            'user': self.user.name,
            'updated_on': self.updated_on
            }


engine = create_engine(
	'sqlite:///travelblog.db')

Base.metadata.create_all(engine)
