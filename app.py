# Database imports
from models import Base, User, Category, Item
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, and_

# Flask imports
from flask import Flask, jsonify, request, url_for, g, make_response
from flask import render_template, abort, flash, redirect
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth

# authentication imports
import google.oauth2.credentials
import google_auth_oauthlib.flow
from oauth2client.client import FlowExchangeError, flow_from_clientsecrets

# other imports
import random
import string
import json
import httplib2
import requests
import functools


# Constants
LATEST_ITEM_LIMIT = 10
SECRET_KEY = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in xrange(32))
CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
CLIENT_SECRET_FILE = 'client_secret.json'
SCOPES = ['profile', 'email']

# Initializations
# Connect to the database and create a session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
# Create the flask application
app = Flask(__name__)


# --------------------------------------
# Login required decorator
# --------------------------------------
def login_required(f):
    @functools.wraps(f)  # this is for introspection
    def wrapper(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return wrapper

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


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # check the X-Requested-With header to prevent the CSRF attacks
    if not request.headers.get('X-Requested-With'):
        abort(403)

    # parse the authcode
    auth_code = request.data
    try:
        # Construct a Flow object and get the credentials object
        flow = flow_from_clientsecrets(
            CLIENT_SECRET_FILE,
            SCOPES
        )
        flow.redirect_uri = 'postmessage'
        credentials = flow.step2_exchange(auth_code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'),
            401
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    # check if the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # check if error exists in the access token, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify the user against the access token
    g_id = credentials.id_token['sub']
    if result['user_id'] != g_id:
        response = make_response(json.dumps(
            'Token granted does not match user ID'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify the access token for the intended app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            'Token does not match the app ID'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check if the logged in user is already connected
    stored_credentials = login_session.get('access_token')
    stored_g_id = login_session.get('g_id')
    if stored_credentials is not None and g_id == stored_g_id:
        response = make_response(json.dumps(
            'Current user already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token and refresh token in the session
    login_session['access_token'] = access_token
    login_session['g_id'] = g_id

    # Get info of the user
    userInfo = requests.get(
        'https://www.googleapis.com/oauth2/v1/userinfo',
        params={
            'access_token': credentials.access_token,
            'alt': 'json'
        }
    )

    userInfo = userInfo.json()

    # save user and other info in the login session, useful for multiple
    # providers
    login_session['provider'] = 'google'
    login_session['username'] = userInfo['name']
    login_session['picture'] = userInfo['picture']
    login_session['email'] = userInfo['email']

    # Do database check and save for the user
    users = session.query(User).all()
    for user in users:
        print 'user loop', user.username

    print login_session['email']
    try:
        user = session.query(User).filter_by(
            email=login_session['email']).one()
        user_id = user.id
    except:
        user_id = None

    if not user_id:
        # create user in the db
        newUser = User(
            username=login_session['username'], email=login_session['email'],
            picture=login_session['picture'], password_hash="")
        session.add(newUser)
        session.commit()
    # save the user_id in the login session
    login_session['user_id'] = user_id

    # show output to the screen
    output = ''
    output += '<h1> Welcome ' + login_session['username'] + '!</h1>'
    output += '<img class="userImage" src="' + login_session['picture'] + '">'
    flash('You have successfully logged in!!', 'alert alert-success')
    print 'username', login_session['username']
    print login_session.get('username')
    return output


# @app.route('gdisconnect')
# def gdisconnect():
    # # get credentials from the login_session
    # credentials = login_session['credentials']
    # # revoke a token by sending an HTTP GET request
    # requests.post(
    #     'https://accounts.google.com/o/oauth2/revoke',
    #     params={'token': credentials.access_token},
    #     headers={'content-type': 'application/x-www-form-urlencoded'}
    # )

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
    print login_session.get('username')
    login_session['test'] = 'hello'
    return render_template(
        'public_catalog.html',
        categories=categories,
        items=items,
        item_count=item_count,
        len=len
    )


@app.route('/catalog/categories/new', methods=['GET', 'POST'])
@login_required
def new_category():
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'],
            user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash('New category created!', 'alert alert-success')
        return redirect(url_for('show_catalog'))
    else:
        return render_template(
            'category_form.html', action_url=url_for('new_category'))


@app.route(
    '/catalog/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        print category.name
        if request.method == 'POST':
            old_name = category.name
            category.name = request.form['name']
            session.add(category)
            session.commit()
            flash(
                old_name + ' category has been changed to ' +
                category.name, 'alert alert-success')
            return redirect(url_for('show_catalog'))
        else:
            return render_template(
                'category_form.html',
                category=category,
                action_url=url_for('edit_category', category_id=category_id)
            )
    except:
        flash('There is no such category', 'alert alert-danger')
        return redirect(url_for('show_catalog'))


@app.route(
    '/catalog/categories/<int:category_id>/delete',
    methods=['GET', 'POST'])
@login_required
def delete_category(category_id):
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        if request.method == 'POST':
            name = category.name
            session.delete(category)
            session.commit()
            flash(
                name + ' category has been successfully deleted with its items',
                'alert alert-success')
            return redirect(url_for('show_category'))
        else:
            return render_template('delete_category.html', category=category)
    except:
        flash('There is no such category')
        return redirect(url_for('show_catalog'))


@app.route('/catalog/categories/<int:category_id>/items')
def show_category_items(category_id):
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Category).filter_by(id=category_id).first().items
    item_count = len(items)
    print login_session['test']
    return render_template(
        'category_items.html',
        categories=categories,
        items=items,
        items_header=category.name,
        item_count=item_count,
        len=len
    )
# --------------------------------------
# CRUD for items
# --------------------------------------


@app.route('/catalog/categories/<int:category_id>/items/<int:item_id>')
def show_item(category_id, item_id):
    itemDetails = session.query(Item).join(Category).filter(
        Item.id == item_id).filter(Category.id == category_id).first()
    return render_template(
        'item.html',
        item=itemDetails
    )


@app.route('/catalog/items/new', methods=['GET', 'POST'])
@login_required
def new_item():
    if request.method == 'POST':
        item = Item(
            title=request.form['title'],
            description=request.form['description'],
            category_id=request.form['category'],
            user_id=login_session['user_id']
        )
        session.add(item)
        session.commit()
        flash(
            item.title + ' has been successfully created',
            'alert alert-success')
        return redirect(url_for('show_catalog'))
    else:
        categories = session.query(Category).all()
        return render_template(
            'item_form.html',
            categories=categories,
            action_url=url_for('new_item'))


@app.route('/catalog/items/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    try:
        item = session.query(Item).filter_by(id=item_id).one()
        if request.method == 'POST':
            item.title = request.form['title']
            item.description = request.form['description']
            item.category_id = request.form['category']
            session.add(item)
            session.commit()
            flash(
                item.title + ' has been successfully updated',
                'alert alert-success')
            return redirect(url_for('show_catalog'))
        else:
            categories = session.query(Category).all()
            return render_template(
                'item_form.html',
                item=item,
                categories=categories,
                action_url=url_for('edit_item', item_id=item_id)
            )
    except:
        flash('There is no such item', 'alert alert-danger')
        return redirect(url_for('show_catalog'))


@app.route('/catalog/items/<int:item_id>/delete', methods=['GET', 'POST'])
def delete_item(item_id):
    try:
        item = session.query(Item).filter_by(id=item_id).one()
        if request.method == 'POST':
            title = item.title
            session.delete(item)
            session.commit()
            flash(
                title + 'has been successfully deleted',
                'alert alert-success'
            )
            return redirect(url_for('show_catalog'))
        else:
            return render_template('delete_item.html', item=item)
    except:
        flash('There is no such item', 'alert alert-danger')
        return redirect(url_for('show_catalog'))



if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'SECRET_KEY'
    app.run(host='0.0.0.0', port=5000)
