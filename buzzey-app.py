from flask import Flask, render_template, request, redirect, url_for, jsonify

from flask import session as login_session
import random, string
import os, re, time
import oauth2 as oauth
import urlparse
import urllib
import json

app = Flask(__name__)

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Search, Messages, Customers

engine = create_engine('sqlite:///buzzey.db')   # connect to db
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# -----------------  Twitter Dashboard for Digital Marketing ----------------------------#


@app.route('/')
@app.route('/main')
def main():
    if 'username' in login_session:
        return redirect(url_for('dashboard'))
    else:
        return render_template('publicindex.html')

@app.route('/dashboard/')
def dashboard():
    if 'username' not in login_session:
        return redirect(url_for('main'))
    try:
        user = session.query(User).filter_by(user_name=login_session['username']).one()
        login_session['user'] = user
    except:
        return redirect(url_for('main'))

    response = show_user(login_session['twitid'])


    return render_template('dashboard.html',response = response, user=user)


@app.route('/search')
def search():
    return "<h1>This is the search page!<h1>"

@app.route('/followers')
def followers():
    if 'followers' not in login_session:
        response = get_followers(login_session['twitid'])
#   add customers to DB
    else:
    #   read from DB
        pass
    return redirect(url_for('dashboard'))

@app.route('/rankings')
def rankings():
    if 'rankings' not in login_session:
        followers = get_followers(login_session['twitid'])
        rankings = get_rankings(followers)
        top_followers = rankings[0:20]
        login_session['rankings'] = True
    else:
#   get rankings from DB
        pass
    return redirect(url_for('dashboard'))


@app.route('/schedule')
def schedule():
    return "<h1>This is the schedule page!</h1>"

@app.route('/message')
def message():
    return "<h1>This is the view/submit messages page!</h1>"

@app.route('/logout')
def logout():
    login_session.clear()
    return redirect(url_for('main'))


@app.route('/campaigns/')
def campaign():
    return render_template('campaign.html')

@app.route('/newcampaign', methods = ['POST','GET'])
def newcampaign():
    if request.method == 'GET':
       return render_template('newcampaign.html')
    if request.method == 'POST':
       return render_template('campaignsettings.html')

@app.route('/viewrankings')
def viewrankings():
    return 'Rankings Table'

@app.route('/viewcustomers')
def customers():
    return 'Customers Table'

#-------------------------------------------  Helper Functions ----------------------------#

# get influence rankings (number of followers) for your followers
def get_rankings(followers):
    rankings = []
    for follower in followers:
       follower_id = follower['id_str']
       name = follower['screen_name']
       resp = show_user(follower_id)
       num = resp['followers_count']
       rankings.append([follower_id,name,num])
       time.sleep(0.1)
    rankings.sort(key = lambda x: x[2], reverse = True)
    login_session['rankings'] = True
    return rankings

def show_user(twitter_id):
   # Call api.twitter.com/1.1/users/show.json?user_id={user_id}
    real_client = oauth_get(login_session['user'])
    response, content = real_client.request(show_user_url + '?user_id=' + twitter_id, "GET")
    if response['status'] != '200':
        error_message = "Invalid response from Twitter API GET users/show : %s" % response['status']
        return render_template('error.html', error_message=error_message)
    response = json.loads(content)
    login_session['img_url'] = response['profile_image_url']
    return response

def get_followers(twitter_id):
    user = login_session['user']
    real_client = oauth_get(user)
    cursor = -1
    response = []
    while cursor != 0:
        resp, content = real_client.request(show_followers_url + '?user_id=' + twitter_id + '&cursor=' + str(cursor) + "&count=100", "GET")
        text = json.loads(content)
        if text and 'next_cursor' in text:
            cursor = text['next_cursor']
            response += text['users']
    login_session['followers'] = True
    return response


#  --------------------  Authorization via Twitter Oauth ------------------------#


@app.route('/start')
def start():
    # Generate the OAuth request tokens, then display them
    app_callback_url = url_for('callback', _external=True)

    consumer = oauth.Consumer(app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    client = oauth.Client(consumer)
    resp, content = client.request(request_token_url, "POST", body=urllib.urlencode({"oauth_callback": app_callback_url}))
    if resp['status'] != '200':
        error_message = "Invalid response %s" % resp['status']
        return render_template('error.html', error_message=error_message)

    request_token = dict(urlparse.parse_qsl(content))
    oauth_token = request_token['oauth_token']
    oauth_token_secret = request_token['oauth_token_secret']

    oauth_store[oauth_token] = oauth_token_secret
    return render_template('start.html', authorize_url=authorize_url, oauth_token=oauth_token, request_token_url=request_token_url)

@app.route('/callback')
def callback():
    # Accept the callback params, get the token and call the API to display this user's name and handle
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')
    oauth_denied = request.args.get('denied')

    # if the oauth request was denied, delete our local token and show an error message
    if oauth_denied:
        if oauth_denied in oauth_store:
            del oauth_store[oauth_denied]
        return render_template('error.html', error_message="the OAuth request was denied by this user")

    if not oauth_token or not oauth_verifier:
        return render_template('error.html', error_message="callback param(s) missing")

    # unless oauth_token is still stored locally, return error
    if oauth_token not in oauth_store:
        return render_template('error.html', error_message="oauth_token not found locally")

    oauth_token_secret = oauth_store[oauth_token]

    # if we got this far, we have both call back params and we have found this token locally

    consumer = oauth.Consumer(app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    token = oauth.Token(oauth_token, oauth_token_secret)
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)

    resp, content = client.request(access_token_url, "POST")
    access_token = dict(urlparse.parse_qsl(content))

    name = access_token['screen_name']
    user_id = access_token['user_id']

    login_session['twitid'] = user_id
    login_session['username'] = name

    # These are the tokens you would store long term, someplace safe

    real_oauth_token = access_token['oauth_token']
    real_oauth_token_secret = access_token['oauth_token_secret']

    user_in_db = False

    try:
        user_in_db = session.query(User).filter_by(user_name=name).one()
    except:
        print('no user found')
    if not user_in_db:
           newuser = User(user_name=name,oauth_token=real_oauth_token,token_secret=real_oauth_token_secret)
           session.add(newuser)
           session.commit()

    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_message='uncaught exception'), 500


# ------------------------------ Twitter Oauth Parameters -------------------------------#
request_token_url = 'https://twitter.com/oauth/request_token'
access_token_url = 'https://twitter.com/oauth/access_token'
authorize_url = 'https://twitter.com/oauth/authorize'
show_user_url = 'https://api.twitter.com/1.1/users/show.json'
show_followers_url = "https://api.twitter.com/1.1/followers/list.json"

# Support keys from environment vars (heroku). You should add your keys to config.cfg

app.config['APP_CONSUMER_KEY'] = os.getenv('TWAUTH_APP_CONSUMER_KEY', 'API_Key_from_Twitter')
app.config['APP_CONSUMER_SECRET'] = os.getenv('TWAUTH_APP_CONSUMER_SECRET', 'API_Secret_from_Twitter')


app.config.from_pyfile('config.cfg', silent=True)

oauth_store = {}

def oauth_get(user):
    consumer = oauth.Consumer(app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    rot,rotc = user.oauth_token,user.token_secret
    real_token = oauth.Token(rot,rotc)
    return(oauth.Client(consumer, real_token))





if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'dev_secret'
    app.run(host='0.0.0.0', port=8000)
