import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    user_name = Column(String(250), nullable=False)                         # login username
    email = Column(String(250))
    password = Column(String(250))
    created = Column(DateTime(timezone=True), server_default=func.now())
    member_level = Column(Integer, default=0)
    oauth_token = Column(String(250), nullable=False)                       # oauth twitter token
    token_secret = Column(String(250), nullable=False)                      # oauth token secret


class Search(Base):
    __tablename__ = 'search'                                                # search terms
    id = Column(Integer, primary_key=True)
    term_list = Column(String(250))                         #list of search terms
    user_id = Column(Integer, ForeignKey('user.id'))                        # foreign key
    user = relationship(User)

class Messages(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True)
    reply = Column(String(250))                         #reply message to new follower
    user_id = Column(Integer, ForeignKey('user.id'))                        # foreign key
    user = relationship(User)

class Customers(Base):
    __tablename__ ='customers'
    id = Column(Integer, primary_key=True)
    twitter_name = Column(String(250))                #customer twitter name
    twitter_id = Column(String(250))                  #customer twitter id
    email = Column(String(250))
    raking = Column(Integer)
    user_id = Column(Integer, ForeignKey('user.id'))                        # foreign key
    user = relationship(User)




engine = create_engine('sqlite:///buzzey.db')


Base.metadata.create_all(engine)
