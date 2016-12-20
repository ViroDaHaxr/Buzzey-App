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
    user_name = Column(String(250), nullable=False)                         # login username corresponds to twitter username
    email = Column(String(250))
    password = Column(String(250))
    created = Column(DateTime(timezone=True), server_default=func.now())
    member_level = Column(Integer, default=0)
    oauth_token = Column(String(250), nullable=False)                       # oauth token
    token_secret = Column(String(250), nullable=False)                      # oauth token secret


class Twitter(Base):
    __tablename__ = 'twitter'
    id = Column(Integer, primary_key=True)
    twitterid = Column(String(50), nullable=False)                        # twitter id
    screenname = Column(String(150))                                       # twitter name
    followers = Column(Integer, default=0)
    tweet_count = Column(Integer, default=0)
    web_url = Column(String(150))
    email = Column(String(50))
    location = Column(String(150))
    image_url = Column(String(150))
    bio = Column(String(250))
    following = Column(Integer, default = 0)
    user_id = Column(Integer, ForeignKey('user.id'))                        # foreign key
    user = relationship(User)



class Campaign(Base):                                                        # Settings for Twitter marketing campaign
    __tablename__ = 'campaign'
    id = Column(Integer, primary_key=True)
    campaign_name = Column(String(50))
    description = Column(String(250))
    search_terms = Column(String(250))                                      # search tems in python list
    autofollow = Column(Integer, default=0)
    autolike = Column(Integer, default=0)
    autocontent = Column(Integer, default=0)
    reply_message = Column(String(140))                                     #reply message to new follower
    offer_message = Column(String(140))                                     # Special offer Message
    offer_url = Column(String(150))                                         # special offer url
    local_offer = Column(Integer, default=0)
    user_id = Column(Integer, ForeignKey('user.id'))                        # foreign key
    user = relationship(User)

class Customer(Base):
    __tablename__ ='customer'
    id = Column(Integer, primary_key=True)
    twitter_name = Column(String(50))                                       #customer twitter name
    twitter_id = Column(String(250), nullable=False)                        #customer twitter id
    twitter_followers= Column(Integer, default=0)
    tweet_count = Column(Integer, default=0)
    web_url = Column(String(150))
    email = Column(String(50))
    location = Column(String(150))
    image_url = Column(String(150))
    dateOfBirth = Column(DateTime)
    bio = Column(String(250))
    following = Column(Integer, default = 0)
    user_id = Column(Integer, ForeignKey('user.id'))                        # foreign key
    user = relationship(User)


engine = create_engine('sqlite:///buzzey.db')


Base.metadata.create_all(engine)
