import logging
import random, string, httplib2, json, requests
from sqlalchemy import create_engine, asc
from models import Base, Item, User
from flask import Flask, redirect, jsonify, request, url_for, abort, g, render_template, flash, make_response
from flask import session as login_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask.ext.httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)



engine = create_engine('sqlite:///itemswithusers.db')
Base.metadata.bind = engine

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu App"

DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

@app.route('/')
def splash():
    urlOut = ('/login')
    try:
        urlOut += request.args['state']
    except:
        logging.info('no token')
    return redirect(urlOut)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')


    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])

    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    flash("you are now logged in as %s" % login_session['username'])
    return output

@app.route("/usercp")
def userCP():
    logging.info(login_session)
    return render_template('usercp.html', STATE=request.args['state'])

@app.route("/new", methods=['GET', 'POST'])
def newItem():
    infirst = 'a'
    try:
        stategiven = request.args['state']
        infirst += request.args['state']
    except:
        logging.info('no state token')
        return redirect('/login')

    logging.info('state******************')
    logging.info(stategiven)

    logging.info(login_session['state'])
    logging.info(stategiven == login_session['state'])

    print(login_session)

    if 'username' not in login_session:
        flash("action requires login")
        return redirect('/login')
    else:
        flash("logged in")

    if request.method == 'GET':

        return render_template('newItemForm.html', STATE=stategiven)

    elif request.method == 'POST':

        if stategiven != login_session['state']:
            return redirect('/login')

        request.get_data()
        code = request.data.decode('utf-8')
        logging.info('code')
        logging.info(code)

        def itemDecoder(raw_item):
            arr = raw_item.split('&')
            d = {}
            for i in arr:
                key, value = i.split('=')
                d[key] = value
            return d

        decoded_item = itemDecoder(code)


        makeANewItem(name = decoded_item['name'], description = decoded_item['description'], category = decoded_item['category'], user_id = login_session['user_id'])

        return redirect('/api/items?state=' + stategiven)

@app.route('/gdisconnect')
def gdisconnect():
    failed = False
    # Only disconnect a connected user.

    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    logging.info("resultV")
    logging.info(result)
    logging.info("result^")

    if result['status'] == '200':
        # Reset the user's sesson.
        try:
            del login_session['access_token']
            print('access token removed')

        except:
            failed = True
            print('failed to remove access token')

        try:
            del login_session['username']
            print('username revoked')
        except:
            failed = True
            print('failed to revoke username')

        try:
            del login_session['state']
            print('state revoked')
        except:
            failed = True
            print('failed to revoke state')

        try:
            del login_session['user_id']
            print('user_id revoked')
        except:
            failed = True
            print('failed to revoke user_id')

        try:
            del login_session['gplus_id']
            print('gplus_id revoked')
        except:
            failed = True
            print('failed to revoke gplus_id')

        try:
            del login_session['email']
            print('email revoked')
        except:
            failed = True
            print('failed to revoke email')

        if failed == True:
            print ("failed to remove all user data")

        if failed == False:
            print("removed all")

        logging.info(login_session)
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:

        try:
            del login_session['access_token']
            print('access token removed')

        except:
            failed = True
            print('failed to remove access token')

        try:
            del login_session['username']
            print('username revoked')
        except:
            failed = True
            print('failed to revoke username')

        try:
            del login_session['state']
            print('state revoked')
        except:
            failed = True
            print('failed to revoke state')

        try:
            del login_session['user_id']
            print('user_id revoked')
        except:
            failed = True
            print('failed to revoke user_id')

        try:
            del login_session['gplus_id']
            print('gplus_id revoked')
        except:
            failed = True
            print('failed to revoke gplus_id')

        try:
            del login_session['email']
            print('email revoked')
        except:
            failed = True
            print('failed to revoke email')

        if failed == True:
            print ("failed to remove all user data")

        if failed == False:
            print("removed all")

        # del login_session['access_token']
        # For whatever reason, the given token was invalid.
        print('failed to revoke access token from google server')

        return redirect('/api/items')

@app.route("/login", methods=['GET', 'POST'])
def showLogin():

    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)



@app.route("/api/items")
def allItemsFunction():
    logging.info("login_sessionV")
    logging.info(login_session)
    logging.info("login_session^")
    return getAllItems()

@app.route("/api/item/<int:id>")
def oneItemFunction(id):
    return jsonify(getItem(id).serialize)


@app.route("/item", methods=['GET', 'POST', 'PUT', 'DELETE'])
def itemrt():
    if request.method == 'GET':
        itemrt = url_for('itemrt')
        return render_template('editItem.html', itemrt = itemrt, STATE = request.args['state'])
    return redirect('/login')


@app.route("/item/<int:id>/modify", methods=['GET', 'PUT', 'DELETE'])
def itemMod(id):
    #debug
    if login_session['state'] is None or login_session['username'] is None or login_session['user_id']  is None or login_session['access_token']  is None or request.args['state'] != login_session['state']:
        print('missing credentials')
        return redirect('/login')

    if request.method == 'GET':
        return render_template('editItem.html', id=id, STATE=request.args['state'])

    try:
        item = getItem(id)
    except:
        print 'item not found'

    logging.info('****************&')
    logging.info('item.user_id')

    if item.user_id != login_session['user_id']:
        make_response(
            json.dumps('Unauthorized user information', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'PUT':
        logging.info('in put')
        stategiven = request.args['state']
        if stategiven != login_session['state']:
            logging.info('not matching')
            return redirect('/login')

        request.get_data()
        code = request.data.decode('utf-8')

        def itemDecoder(raw_item):
            arr = raw_item.split('&')
            d = {}
            for i in arr:
                key, value = i.split('=')
                d[key] = value
            return d

        decoded_item = itemDecoder(code)

        logging.info('decoded_itemV')
        logging.info(decoded_item)
        logging.info('^decoded_itemb')
        if decoded_item['name'] is not None:
            item.name = decoded_item['name']
        if decoded_item['description'] is not None:
            item.description = decoded_item['description']
        if decoded_item['category'] is not None:
            item.category = decoded_item['category']
        session.add(item)
        session.commit()
        return ('hi')


    else:
        return deleteItem(id)


@app.route("/users", methods = ['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print "missing arguments"
        abort(400)

    try:
        if session.query(User).filter_by(username = username).first() is not None:
            print "existing user"
            user = session.query(User).filter_by(username=username).first()
            return jsonify({'message':'user already exists'}), 200#, {'Location': url_for('get_user', id = user.id, _external = True)}
    except:
        print 'no users'

    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({ 'username': user.username }), 201#, {'Location': url_for('get_user', id = user.id, _external = True)}

@app.route('/api/users')
def get_users():
    try:
        users = session.query(User).all()
    except:
        return ('no users')
    return jsonify(users=[user.serialize for user in users])


def getAllItems():
    try:
        items = session.query(Item).all()
    except:
        return ('no items')
    return jsonify(Items=[i.serialize for i in items])

def getItem(id):
    return session.query(Item).filter_by(id=id).one()


def makeANewItem(name, description, category, user_id):
    item = Item(name=name, description=description, category=category, user_id=user_id)
    session.add(item)
    session.commit()
    return jsonify(Item=item.serialize)


def deleteItem(id):
    item = getItem(id)
    session.delete(item)
    session.commit()
    return "Item Deleted"


def createUser(login_session):
    print('creating new user...')
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()

    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
        app.secret_key = 'password'
        app.debug = True
        app.run(host='0.0.0.0', port=5001)
































