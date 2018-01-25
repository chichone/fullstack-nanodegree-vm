from flask import Flask, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Item


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
        print name
        print description
        # return 'hi'
        return makeANewItem(name, description)


def getAllItems():
    items = session.query(Item).all()
    return jsonify(Items=[i.serialize for i in items])


def makeANewItem(name, description):
    item = Item(name=name, description=description)
    session.add(item)
    session.commit()
    return jsonify(Item=item.serialize)

if __name__ == '__main__':
        app.debug = False
        app.run(host='0.0.0.0', port=5000)
