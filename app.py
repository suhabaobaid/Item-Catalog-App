# Database imports
from models import Base, User, Category, Item
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, and_

# Flask imports
from flask import Flask, jsonify, request, url_for, g
from flask import render_template
from flask_httpauth import HTTPBasicAuth


# Constants
LATEST_ITEM_LIMIT = 10

# Initializations
# Connect to the database and create a session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
# Create the flask application
app = Flask(__name__)


# --------------------------------------
# JSON APIs to show Catalog information
# --------------------------------------
@app.route('/api/v1/catalog.json')
def catalogJSON():
    categories = session.query(Category).all()
    return jsonify(
        Category=[category.serializeWithItems for category in categories]
    )


@app.route('/api/v1/categories.json')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(
        Category=[category.serializeWithoutItems for category in categories]
    )


@app.route('/api/v1/items.json')
def itemsJSON():
    items = session.query(Item).all()
    return jsonify(
        Item=[item.serialize for item in items]
    )


# --------------------------------------
# Authentication routes
# --------------------------------------
@app.route('/login')
def show_login():
    return render_template('login.html')


# --------------------------------------
# CRUD for categories
# --------------------------------------
@app.route('/')
@app.route('/catalog')
def show_catalog():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(
        Item.id.desc()).limit(LATEST_ITEM_LIMIT).all()
    item_count = len(items)
    # TODO: Add check if user is logged in
    print categories[0].serializeWithItems
    return render_template(
        'public_catalog.html',
        categories=categories,
        items=items,
        item_count=item_count,
        len=len
    )


@app.route('/catalog/<category>/items')
def show_category_items(category):
    categories = session.query(Category).all()
    items = session.query(Category).filter_by(name=category).first().items
    item_count = len(items)
    return render_template(
        'category_items.html',
        categories=categories,
        items=items,
        items_header=category,
        item_count=item_count,
        len=len
    )

# --------------------------------------
# CRUD for items
# --------------------------------------


@app.route('/catalog/<category>/<item>')
def show_item(category, item):
    itemDetails = session.query(Item).join(Category).filter(Item.title == item).filter(Category.name == category).first()
    return render_template(
        'item.html',
        item=itemDetails
    )


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
