from sqlalchemy import create_engine
from models import Base, Item, User
from flask import Flask, jsonify, request, url_for, abort, g
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from flask.ext.httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()


engine = create_engine('sqlite:///items.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)


@app.route("/")
@app.route("/api/items", methods=['GET', 'POST'])
def itemsFunction():
    if request.method == 'GET':
        return getAllItems()
    elif request.method == 'POST':
        print("Making a New item")
        ##pull from json data in post instead
        # name = request.args.get('name', '')
        name = request.json.get('name')
        description = request.json.get('description')
        category = request.json.get('category')
        print name
        # return 'hi'
        return makeANewItem(name, description, category)

@app.route('/users', methods = ['POST'])
def new_user():
    username = request.json.get('username')
    print username
    password = request.json.get('password')
    print password
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


def makeANewItem(name, description, category):
    item = Item(name=name, description=description, category=category)
    session.add(item)
    session.commit()
    return jsonify(Item=item.serialize)

if __name__ == '__main__':
        app.debug = True
        app.run(host='0.0.0.0', port=5000)
