from flask import Flask, render_template, request, redirect, url_for
from flask import flash, jsonify
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Place, Blog

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response, send_from_directory
import requests
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = 'images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5*1024*1024

engine = create_engine('sqlite:///travelblog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu"

categories = session.query(Category)
places = session.query(Place)


@app.route('/')
@app.route('/home')
def Home():
    ''' Displays all the categories
    '''
    return render_template('home.html', cat=categories, places=places)


@app.route('/category/<int:category_id>')
def Categories(category_id):
    ''' Displays all the places in a particular category
    '''
    cplaces = session.query(Place).filter_by(category_id=category_id)
    return render_template('categoryPlaces.html', category_id=category_id,
                           cat=categories, places=places, cplaces=cplaces)


@app.route('/category/<int:category_id>/newplace', methods=['GET', 'POST'])
def AddPlace(category_id):
    ''' Any user can add a place. But it will be added only if there was no
    place of same name before '''
    if 'user_id' in login_session:
        if request.method == 'GET':
            return render_template('addPlace.html', cat=categories,
                                   places=places, category_id=category_id)
        else:
            if request.form['place']:
                ps = session.query(Place).filter_by(name=request.form['place'])
                c = 0
                for p in ps:
                    c += 1
                if c != 0:
                    flash("This place already exists")
                    return redirect(url_for('Categories',
                                            category_id=category_id))
                else:
                    new_place = Place(name=request.form['place'],
                                      category_id=category_id)
                    session.add(new_place)
                    session.commit()
                    flash("New place added")
                    return redirect(url_for('Places', category_id=category_id,
                                            place_id=new_place.id))
            else:
                flash('Name of place is mandatory')
                return redirect(request.url)
    else:
        flash("Please login to add new place")
        return redirect('/login')


@app.route('/category/<int:category_id>/place/<int:place_id>')
def Places(category_id, place_id):
    ''' Displays all the blogs for a place
    '''
    blogs = session.query(Blog).filter_by(place_id=place_id)
    c = 0
    for b in blogs:
        c += 1
    place = session.query(Place).filter_by(id=place_id)
    cp = 0
    for p in place:
        cp += 1
    if cp == 0:
        flash("This place does not exist")
        return redirect('/')
    else:
        place = place.one()
        return render_template('placeBlogs.html', cat=categories,
                               blogs=blogs, category_id=category_id,
                               place_id=place_id, places=places,
                               place=place, c=c)


def allowed_file(filename):
    ''' Checks for allowed extensions for the file to be uploaded
    '''
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/category/<int:category_id>/place/<int:place_id>/newblog',
           methods=['GET', 'POST'])
def NewBlog(category_id, place_id):
    ''' Allows users to post a new blog
    '''
    if 'user_id' in login_session:
        if request.method == 'GET':
            # Prevents cross site request forgery through a random token
            CSRF_Token = ''.join(random.choice(string.ascii_uppercase +
                                               string.digits)
                                 for x in xrange(32))
            login_session['CSRF_Token'] = CSRF_Token
            return render_template('addblog.html', cat=categories,
                                   places=places, category_id=category_id,
                                   place_id=place_id, token=CSRF_Token)
        else:
            if request.form['token'] == login_session['CSRF_Token']:
                del login_session['CSRF_Token']
                if request.form['subject'] and request.form['content']:
                    filename = ''
                    if 'file' in request.files:
                        file = request.files['file']
                        if file.filename == '':
                            flash('No image file selected')
                        if file and allowed_file(file.filename):
                            filename = secure_filename(file.filename)
                            path = os.path.join(app.config['UPLOAD_FOLDER'],
                                                filename)
                            file.save(path)
                    con = request.form['content'].replace('\n', '<br>')
                    blog = Blog(subject=request.form['subject'], content=con,
                                image=filename,
                                user_id=login_session['user_id'],
                                place_id=place_id)
                    session.add(blog)
                    session.commit()
                    flash("New Blog added")
                    return redirect(url_for('Blogs', category_id=category_id,
                                            place_id=place_id,
                                            blog_id=blog.id))

                else:
                    flash('You have to provide both subject and content')
                    return redirect(request.url)
            else:
                flash("You don't have access to this")
                del login_session['CSRF_Token']
                return redirect(url_for('Places', category_id=category_id,
                                        place_id=place_id))
    else:
        flash("Please login to post a blog") 
        return redirect('/login')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    ''' returns a file from upload folder
    '''
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

# Checks if the blog which is requested exists or not
def checkBlog(blog):
    c = 0
    print blog
    for bl in blog:
        c += 1
    return c

@app.route('/category/<int:category_id>/place/<int:place_id>/'
           'blog/<int:blog_id>')
def Blogs(category_id, place_id, blog_id):
    ''' Displays a particular blog
    '''
    blog = session.query(Blog).filter_by(id=blog_id)
    if checkBlog(blog):
        blog = blog.one()
        return render_template('blog.html', b=blog, cat=categories,
                           category_id=category_id, places=places)
    else:
        flash('No such blog exists')
        return redirect('/')


@app.route('/category/<int:category_id>/place/<int:place_id>/blog/'
           '<int:blog_id>/edit', methods=['GET', 'POST'])
def EditBlog(category_id, place_id, blog_id):
    ''' Edits a blog. Only users which are logged in and are the owner of the
    blog are permitted to edit it.'''
    if 'user_id' in login_session:
        blog = session.query(Blog).filter_by(id=blog_id)
        if checkBlog(blog):
            blog = blog.one()
            if login_session['user_id'] == blog.user.id:
                if request.method == 'GET':
                    # Prevents cross site request forgery through random token
                    CSRF_Token = ''.join(random.choice(
                        string.ascii_uppercase + string.digits)
                                         for x in xrange(32))
                    login_session['CSRF_Token'] = CSRF_Token
                    return render_template('editBlog.html', b=blog,
                                           cat=categories,
                                           places=places, token=CSRF_Token)
                else:
                    if request.form['token'] == login_session['CSRF_Token']:
                        del login_session['CSRF_Token']
                        if request.form['subject'] and request.form['content']:
                            blog.subject = request.form['subject']
                            blog.content = request.form[
                                'content'].replace('\n','<br>')
                            session.add(blog)
                            session.commit()
                            flash("Blog has been edited")
                            return redirect(url_for('Blogs',
                                                    category_id=category_id,
                                                    place_id=place_id,
                                                    blog_id=blog.id))
                        else:
                            flash('You have to provide both subject & content')
                            return render_template('editBlog.html',
                                                   cat=categories,
                                                   places=places)
                    else:
                        flash("You don't have access to this")
                        del login_session['CSRF_Token']
                        return redirect(url_for('Blogs',
                                                category_id=category_id,
                                                place_id=place_id,
                                                blog_id=blog.id))
            else:
                flash("You don't have access to this")
                return redirect('/')
        else:
            flash('No such blog exists')
            return redirect('/')
    else:
        flash("Please login to edit blog")
        return redirect('/login')


@app.route('/category/<int:category_id>/place/<int:place_id>/blog/'
           '<int:blog_id>/delete', methods=['GET', 'POST'])
def DeleteBlog(category_id, place_id, blog_id):
    ''' Deletes the blog if the user is logged in and owner of the blog.
    '''
    if 'user_id' in login_session:
        blog = session.query(Blog).filter_by(id=blog_id)
        if checkBlog(blog):
            blog = blog.one()
            if login_session['user_id'] == blog.user.id:
                if request.method == 'GET':
                    # Prevents cross site request forgery through random token
                    CSRF_Token = ''.join(random.choice(
                        string.ascii_uppercase + string.digits)
                                         for x in xrange(32))
                    login_session['CSRF_Token'] = CSRF_Token
                    return render_template('deleteBlog.html', b=blog,
                                           cat=categories, places=places,
                                           token=CSRF_Token)
                else:
                    if request.form['token'] == login_session['CSRF_Token']:
                        del login_session['CSRF_Token']
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'],
                                               blog.image))
                        session.delete(blog)
                        session.commit()
                        flash("Blog has been deleted")
                        return redirect(url_for('Places',
                                                category_id=category_id,
                                                place_id=place_id))
                    else:
                        flash("You don't have access to this")
                        del login_session['CSRF_Token']
                        return redirect(url_for('Blogs',
                                                category_id=category_id,
                                                place_id=place_id,
                                                blog_id=blog.id))
            else:
                flash("You don't have access to this")
                return redirect('/')
        else:
            flash('No such blog exists')
            return redirect('/')
    else:
        flash("Please login to delete the blog")
        return redirect('/login')


@app.route('/category/<int:category_id>/place/<int:place_id>/blog/'
           '<int:blog_id>/imageedit', methods=['GET', 'POST'])
def EditDelImage(category_id, place_id, blog_id):
    ''' Gives the option to change and delete an image if there was one
    alredy or to upload an image if there was no previous image.
    '''
    if 'user_id' in login_session:
        blog = session.query(Blog).filter_by(id=blog_id)
        if checkBlog(blog):
            blog = blog.one()
            if login_session['user_id'] == blog.user.id:
                if request.method == 'GET':
                    # Prevents cross site request forgery through random token
                    CSRF_Token = ''.join(random.choice(
                        string.ascii_uppercase + string.digits)
                                         for x in xrange(32))
                    login_session['CSRF_Token'] = CSRF_Token
                    return render_template('editdelImage.html', b=blog,
                                           cat=categories, places=places,
                                           token=CSRF_Token)
                else:
                    if request.form['token'] == login_session['CSRF_Token']:
                        del login_session['CSRF_Token']
                        if ('edit_img' in request.form or
                            'new_img' in request.form):
                            if 'file' in request.files:
                                file = request.files['file']
                                if file.filename == '':
                                    flash('No image file selected')
                                    return redirect(url_for('EditBlog',
                                                            place_id=place_id,
                                                            blog_id=blog_id,
                                                            category_id=category_id
                                                            ))
                                if file and allowed_file(file.filename):
                                    if 'edit_img' in request.form:
                                        os.remove(os.path.join(
                                            app.config['UPLOAD_FOLDER'],
                                            blog.image))
                                    filename = secure_filename(file.filename)
                                    path = os.path.join(app.config[
                                        'UPLOAD_FOLDER'],filename)
                                    file.save(path)
                                    blog.image = filename
                                    session.commit()
                                    flash("Image has been edited")
                                    return redirect(url_for('EditBlog',
                                                            category_id=
                                                            category_id,
                                                            place_id=place_id,
                                                            blog_id=blog_id))
                        if 'del_img' in request.form:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'],
                                                   blog.image))
                            blog.image = ''
                            session.commit()
                            flash("Image has been deleted")
                            return redirect(url_for('EditBlog',
                                                    category_id=category_id,
                                                    place_id=place_id,
                                                    blog_id=blog_id))
                    else:
                        flash("You don't have access to this")
                        del login_session['CSRF_Token']
                        return redirect(url_for('Blogs',
                                                category_id=category_id,
                                                place_id=place_id,
                                                blog_id=blog.id))

            else:
                flash("You don't have access to this")
                return redirect('/')
        else:
            flash('No such blog exists')
            return redirect('/')
    else:
        flash("Please login to modify image")
        return redirect('/login')


@app.route('/category/<int:category_id>/json')
def CategoryJson(category_id):
    ''' Returns all the places in a particular category in JSON format
    '''
    places = session.query(Place).filter_by(category_id=category_id)
    return jsonify(Places_in_this_Category=[p.serialize for p in places])


@app.route('/category/<int:category_id>/place/<int:place_id>/json')
def PlaceJson(category_id, place_id):
    ''' Returns all the blogs on a particular place in JSON format.
    '''
    blogs = session.query(Blog).filter_by(place_id=place_id).order_by(
        desc(Blog.updated_on))
    return jsonify(Blogs_for_this_Place=[b.serialize for b in blogs])


@app.route('/login')
def ShowLogin():
    '''Displays login page'''
    # Anti forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, cat=categories,
                           places=places)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

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
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (' " style = "width: 100px; height: 100px;border-radius: 50px;'
               '-webkit-border-radius: 50px;-moz-border-radius: 50px;"> ')
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/logout')
def gdisconnect():
    access_token = login_session['credentials']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s' %
           login_session['credentials'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] != '200':
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/v2.8/oauth/access_token?'
           'grant_type=fb_exchange_token&client_id=%s&client_secret=%s&'
           'fb_exchange_token=%s' % (app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    token = 'access_token=' + data['access_token']

    # Use token to get user info from API
    # userinfo_url = "https://graph.facebook.com/v2.8/me"
    url = 'https://graph.facebook.com/v2.8/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly
    # logout,let's strip out the information before the equals sign in our
    # token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = ('https://graph.facebook.com/v2.8/me/picture?%s&redirect=0&'
           'height=200&width=200' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (' " style = "width: 100px; height: 100px;border-radius: 50px;'
               '-webkit-border-radius: 50px;-moz-border-radius: 50px;"> ')

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token=%s' %
           (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have been successfully logged out.")
        return redirect(url_for('Home'))
    else:
        flash("You were not logged in")
        return redirect(url_for('/login'))


if __name__ == '__main__':
    app.secret_key = 'secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
