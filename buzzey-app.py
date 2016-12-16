from flask import Flask, render_template, request, redirect, url_for, jsonify

from flask import session as login_session
import random, string
import os, re
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
    if 'twitter' in login_session:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('start'))

@app.route('/dashboard/')
def dashboard():
    if 'username' not in login_session:
        return redirect(url_for('main'))

    # Call api.twitter.com/1.1/users/show.json?user_id={user_id}
    user = session.query(User).filter_by(user_name=login_session['username']).one()
    if not user:
        return "error: username not found"
    consumer = oauth.Consumer(app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])

    rot,rotc = user.oauth_token,user.token_secret
    real_token = oauth.Token(rot,rotc)
    real_client = oauth.Client(consumer, real_token)

    print(show_user_url + '?user_id=' + login_session['username'])
    real_resp, real_content = real_client.request(show_user_url + '?user_id=' + login_session['twitid'], "GET")
    if real_resp['status'] != '200':
        error_message = "Invalid response from Twitter API GET users/show : %s" % real_resp['status']
        return render_template('error.html', error_message=error_message)
    response = json.loads(real_content)
    print('recieved response')
    followers_count = response['followers_count']

    return render_template('dashboard.html',followers=followers_count)


@app.route('/search')
def search():
    return "<h1>This is the search page!<h1>"

@app.route('/schedule')
def schedule():
    return "<h1>This is the schedule page!</h1>"

@app.route('/message')
def message():
    return "<h1>This is the view/submit messages page!</h1>"





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

    screen_name = access_token['screen_name']
    user_id = access_token['user_id']

    login_session['twitid'] = user_id

    # These are the tokens you would store long term, someplace safe

    real_oauth_token = access_token['oauth_token']
    real_oauth_token_secret = access_token['oauth_token_secret']

    print('oauth_token =',real_oauth_token)
    print('oauth_secret =',real_oauth_token_secret)

    # Call api.twitter.com/1.1/users/show.json?user_id={user_id}

    real_token = oauth.Token(real_oauth_token, real_oauth_token_secret)
    real_client = oauth.Client(consumer, real_token)
    real_resp, real_content = real_client.request(show_user_url + '?user_id=' + user_id, "GET")

    if real_resp['status'] != '200':
        error_message = "Invalid response from Twitter API GET users/show : %s" % real_resp['status']
        return render_template('error.html', error_message=error_message)

    response = json.loads(real_content)

#    print(response)

#    friends_count = response['friends_count']
#    statuses_count = response['statuses_count']
#    followers_count = response['followers_count']
    name = response['name']
    login_session['username'] = name
    user = False
    try:
        user = session.query(User).filter_by(user_name=name).all()
    except:
        print('no user found')
    if not user:
           newuser = User(user_name=name,oauth_token=real_oauth_token,token_secret=real_oauth_token_secret)
           session.add(newuser)
           session.commit()
           user = session.query(User).filter_by(user_name=name).one()



    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_message='uncaught exception'), 500

# ------------------------------ Twitter Oauth Parameters -------------------------------#
request_token_url = 'https://twitter.com/oauth/request_token'
access_token_url = 'https://twitter.com/oauth/access_token'
authorize_url = 'https://twitter.com/oauth/authorize'
show_user_url = 'https://api.twitter.com/1.1/users/show.json'

# Support keys from environment vars (heroku). You should add your keys to config.cfg

app.config['APP_CONSUMER_KEY'] = os.getenv('TWAUTH_APP_CONSUMER_KEY', 'API_Key_from_Twitter')
app.config['APP_CONSUMER_SECRET'] = os.getenv('TWAUTH_APP_CONSUMER_SECRET', 'API_Secret_from_Twitter')


app.config.from_pyfile('config.cfg', silent=True)

oauth_store = {}

# ------------------------  Login via Password ------------------------------------------#

@app.route('/login/', methods = ['POST','GET'])
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state


    if request.method == 'GET':
        return render_template('login.html', state = state)

    if request.method =='POST':
        have_error = False
        username = request.form['username']
        password = request.form['password']
        verify = request.form['verify']
        email = request.form['email']

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not valid_email(email):
            params['error_email'] = "Please enter a valid email address."
            have_error = True

        if have_error:
            return render_template('login.html', **params)
        else:
            login_session['username'] = username

        #  add to DB
            newuser = User(user_name=username,email=email,password=password.encode('rot13'))
            session.add(newuser)
            session.commit()

            return redirect(url_for('dashboard'))

#   -------------------  regular expressions for signup ---------------------------------#

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    user = session.query(User).filter_by(user_name=username).all()

    return username and USER_RE.match(username) and not user

PASS_RE = re.compile(r"^.{5,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return email and EMAIL_RE.match(email)



if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'my_secret_key'
    app.run(host='0.0.0.0', port=8000)
