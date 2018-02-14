from sqlalchemy import create_engine
from models import Base, Item, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template
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
def displaySplashPage():
    return render_template('index.html')

@app.route("/login", methods=['GET', 'POST'])
def loginPage():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        return 'post'

@app.route("/register")
def registerPage():
    return render_template('register.html')

@app.route("/usercp")
def userCP():
    return render_template('usercp.html')

@app.route("/api/")
def allItemsFunction():
    return getAllItems()

@app.route("/api/<int:id>")
def oneItemFunction(id):
    return jsonify(getItem(id).serialize)



@app.route("/item/<int:id>", methods=['POST', 'PUT', 'DELETE'])
@auth.login_required
def itemsFunction(id):
    #debug
    try:
        name = request.json.get('name')
        description = request.json.get('description')
        category = request.json.get('category')
    except:
        print 'data not provided'

    try:
        item = getItem(id)
    except:
        print 'item not found'

    if request.method == 'POST':
        return makeANewItem(name, description, category)

    elif request.method == 'PUT':
        if name is not None:
            item.name = name
        if description is not None:
            item.description = description
        if category is not None:
            item.category = category
        session.add(item)
        session.commit()
        return jsonify(item.serialize)

    else:
        return deleteItem(id)


@app.route("/users", methods = ['POST'])
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

@auth.verify_password
def verify_password(username, password):
    user = session.query(User).filter_by(username = username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True

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


def makeANewItem(name, description, category):
    item = Item(name=name, description=description, category=category)
    session.add(item)
    session.commit()
    return jsonify(Item=item.serialize)

def deleteItem(id):
    item = getItem(id)
    session.delete(item)
    session.commit()
    return "Item Deleted"


if __name__ == '__main__':
        app.debug = True
        app.run(host='0.0.0.0', port=5000)
