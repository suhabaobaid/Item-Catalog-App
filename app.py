#!/usr/bin/env python2

# Database imports
from models import Base, User, Category, Item
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, and_

# Flask imports
from flask import Flask, jsonify, request, url_for, g, make_response
from flask import render_template, abort, flash, redirect
from flask import session as login_session

# authentication imports
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
engine = create_engine(
    'sqlite:///catalog.db', connect_args={'check_same_thread': False})
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
# Create the flask application
app = Flask(__name__)


# --------------------------------------
# Login required decorator
# --------------------------------------

def login_required(f):
    '''
    decorator to restrict access to pages if user not logged in
    '''
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
    '''
    Returns:
        catalog (json): whole catalog including categories and items
    '''
    categories = session.query(Category).all()
    return jsonify(
        Category=[category.serializeWithItems for category in categories]
    )


@app.route('/api/v1/categories.json')
def categoriesJSON():
    '''
    Returns:
        categories (json): list of categories
    '''
    categories = session.query(Category).all()
    return jsonify(
        Category=[category.serializeWithoutItems for category in categories]
    )


@app.route('/api/v1/items.json')
def itemsJSON():
    '''
    Returns:
        items (json): list of items
    '''
    items = session.query(Item).all()
    return jsonify(
        Item=[item.serialize for item in items]
    )


# --------------------------------------
# Authentication routes
# --------------------------------------

@app.route('/login')
def show_login():
    '''
    Returns:
        login (html)
    '''
    return render_template('login.html')


@app.route('/gconnect', methods=['POST'])
def gconnect():
    '''
    End point called after the client is authenticated and user gives
    permission to the app
    Args:
        auth_code -> from request sent by google OAuth
    Returns:
        output (html): for successful login otherwise sends an error response
        to client
    '''
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

    # save the credentials
    # ACTION ITEM: store the credentials in a persistent db in production
    # login_session['credentials'] = credentials_to_dict(credentials)
    # print login_session['credentials']

    # Do database check and save the user
    try:
        user = session.query(User).filter_by(
            email=login_session['email']).one()
        user_id = user.id
    except:
        user_id = None

    if not user_id:
        # create user in the db
        user = User(
            username=login_session['username'], email=login_session['email'],
            picture=login_session['picture'], password_hash="")
        session.add(user)
        session.commit()

    # save the user.id in the login session
    login_session['user_id'] = user.id

    # show output to the screen
    output = ''
    output += '<h1> Welcome ' + login_session['username'] + '!</h1>'
    output += '<img class="userImage" src="' + login_session['picture'] + '">'
    construct_flash('You have successfully logged in!!', 'success')
    return output


@app.route('/logout')
def logout():
    '''
    Endpoint for logout, generalized logout according to provider in
    login_session
    '''
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()

        del login_session['provider']
        flash(
            'You have successfully logged out',
            'alert alert-success')
        return redirect(url_for('show_catalog'))


def gdisconnect():
    '''
    Function to check and revoke google's user token and resets the
    login_session
    '''
    # get access_token from the login_session
    access_token = login_session['access_token']
    # only logout authenticated users
    if access_token is None:
        response = make_response(
            json.dumps('No user is connected'),
            401
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    # revoke a token by sending an HTTP GET request
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # reset login_session if  successful revoke
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['g_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']

        response = make_response(json.dumps('Successfully disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # invalid token
        response = make_response(
            json.dumps('Invalid token for the user, failed to revoke token'),
            400
        )
        return response


# --------------------------------------
# CRUD for categories
# --------------------------------------

@app.route('/')
@app.route('/catalog')
def show_catalog():
    '''
    Allows user to view the catalog page, certain (add,edit,delete) available
    for authenicated users
    Returns:
        catalog (html): page with all the categories and latest items
    '''
    categories = session.query(Category).all()
    items = session.query(Item).order_by(
        Item.id.desc()).limit(LATEST_ITEM_LIMIT).all()
    item_count = len(items)
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
    '''
    Allows authenticated users to add a new category
    Returns:
        category_form (html): form to fill for the category
    '''
    if request.method == 'POST':
        new_category = Category(
            name=request.form['name'],
            user_id=login_session['user_id'])
        add_to_db(new_category)
        construct_flash('New category created!', 'success')
        return redirect(url_for('show_catalog'))
    else:
        return render_template(
            'category_form.html', action_url=url_for('new_category'))


@app.route(
    '/catalog/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    '''
    Allows authenticated users to edit a category they own
    Returns:
        category_form (html): form to edit the category
    '''
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        if category.user_id == login_session['user_id']:
            if request.method == 'POST':
                old_name = category.name
                category.name = request.form['name']
                add_to_db(category)
                construct_flash(
                    old_name + ' category has been changed to ' +
                    category.name, 'success')
                return redirect(url_for('show_catalog'))
            else:
                return render_template(
                    'category_form.html',
                    category=category,
                    action_url=url_for(
                        'edit_category', category_id=category_id)
                )
        else:
            construct_flash(
                'You do not have the autherization to edit', 'danger')
            return redirect(url_for('show_catalog'))
    except:
        construct_flash('There is no such category', 'danger')
        return redirect(url_for('show_catalog'))


@app.route(
    '/catalog/categories/<int:category_id>/delete',
    methods=['GET', 'POST'])
@login_required
def delete_category(category_id):
    '''
    Allows authenticated users to delete a category they own and its items
    Note:
        This will cause the deletion of items created by other users if exist
    Returns:
        delete_category (html): template for confirmation of deletion
    '''
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        if category.user_id == login_session['user_id']:
            if request.method == 'POST':
                name = category.name
                delete_from_db(category)
                construct_flash(
                    name +
                    ' category has been successfully deleted with its items',
                    'success')
                return redirect(url_for('show_category'))
            else:
                return render_template(
                    'delete_category.html', category=category)
        else:
            construct_flash(
                'You do not have the autherization to delete', 'danger')
            return redirect(url_for('show_catalog'))
    except:
        flash('There is no such category')
        return redirect(url_for('show_catalog'))


@app.route('/catalog/categories/<int:category_id>/items')
def show_category_items(category_id):
    '''
    Allows public users to view the items that belong to the selected category
    Returns:
        category_items (html): template showing the list of categories and the
        items in
        in the selected category
    '''
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Category).filter_by(id=category_id).first().items
    item_count = len(items)
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
    '''
    Allows public users to view the details of an item,
    authenticated owner users get the option to edit and delete
    Returns:
        item (html): template to display the details of the item (title,
        description and category)
    '''
    itemDetails = session.query(Item).join(Category).filter(
        Item.id == item_id).filter(Category.id == category_id).first()
    return render_template(
        'item.html',
        item=itemDetails
    )


@app.route('/catalog/items/new', methods=['GET', 'POST'])
@login_required
def new_item():
    '''
    Allows authenticates users to create a new item
    Returns:
        item_form (html): form to add item's details
    '''
    if request.method == 'POST':
        item = Item(
            title=request.form['title'],
            description=request.form['description'],
            category_id=request.form['category'],
            user_id=login_session['user_id']
        )
        add_to_db(item)
        construct_flash(
            item.title + ' has been successfully created',
            'success')
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
    '''
    Allows authenticates users to edited an item they own
    Returns:
        item_form (html): form to edit item's details
    '''
    try:
        item = session.query(Item).filter_by(id=item_id).one()
        if item.user_id == login_session['user_id']:
            if request.method == 'POST':
                item.title = request.form['title']
                item.description = request.form['description']
                item.category_id = request.form['category']
                add_to_db(item)
                construct_flash(
                    item.title + ' has been successfully updated',
                    'success')
                return redirect(url_for('show_catalog'))
            else:
                categories = session.query(Category).all()
                return render_template(
                    'item_form.html',
                    item=item,
                    categories=categories,
                    action_url=url_for('edit_item', item_id=item_id)
                )
        else:
            construct_flash(
                'You do not have the autherization to edit', 'danger')
            return redirect(url_for('show_catalog'))
    except:
        construct_flash('There is no such item', 'danger')
        return redirect(url_for('show_catalog'))


@app.route('/catalog/items/<int:item_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_item(item_id):
    '''
    Allows authenticates users to delete an item they own
    Returns:
        item_form (html): template to confirm deletion of an item
    '''
    try:
        item = session.query(Item).filter_by(id=item_id).one()
        if item.user_id == login_session['user_id']:
            if request.method == 'POST':
                title = item.title
                delete_from_db(item)
                construct_flash(
                    title + 'has been successfully deleted',
                    'success'
                )
                return redirect(url_for('show_catalog'))
            else:
                return render_template('delete_item.html', item=item)
        else:
            construct_flash(
                'You do not have the autherization to delete', 'danger')
            return redirect(url_for('show_catalog'))
    except:
        construct_flash('There is no such item', 'danger')
        return redirect(url_for('show_catalog'))


# --------------------------------------
# Helper function
# --------------------------------------

def credentials_to_dict(credentials):
    '''
    trasnforms credentials object to a dictionary
    Args:
        credentials (obj): provided by OAuth flow
    Returns:
        credentials (dict)
    '''
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


def construct_flash(message, flash_type):
    '''
    Creates a flash
    Args:
        message (string): flash message
        flash_type (string): ['danger', 'warning', 'success'] type of flash
    '''
    flash(message, 'alert alert-%s' % flash_type)


def add_to_db(obj):
    '''
    Adds object to the db and commits, for creation and editing of object
    Args:
        obj (model object)
    '''
    session.add(obj)
    session.commit()


def delete_from_db(obj):
    '''
    Delete object to the db and commits
    Args:
        obj (model object)
    '''
    session.delete(obj)
    session.commit()


if __name__ == '__main__':
    app.debug = True
    app.secret_key = SECRET_KEY
    app.run(host='0.0.0.0', port=5000)
