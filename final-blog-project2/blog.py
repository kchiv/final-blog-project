import re
import hmac
import webapp2
import jinjatemp
from user import User
from post import Post
from comment import Comments
from likes import Likes

from google.appengine.ext import db

import os
import jinja2

secret = 'imsosecret'

def make_secure_val(val):
    # Creates a hash
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    # Checks whether hash value from user is valid
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return jinjatemp.temp_render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        # Base function for setting cookie
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        # Checks whether cookie from user is valid
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        # Sets the cookie for 'user_id'
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        # Removes the cookie
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class BlogFront(BlogHandler):
    def get(self):
        # Renders all posts on blog homepage
        posts = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        # GQL queries and other elements to generate individual post page
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comment_feed = db.GqlQuery("SELECT * FROM Comments WHERE post_id = " +
                                    post_id + " ORDER BY created DESC")
        comment_count = comment_feed.count()
        like_lookup = db.GqlQuery("SELECT * FROM Likes WHERE post_id = " +
                                    post_id)
        like_count = like_lookup.count()

        if not post:
            # If the post does not exist return 404
            self.error(404)
            self.write("This post does not exist!")
            return

        # Only show edit and delete buttons to signed in users
        if self.user:
            self.render("permalink.html",
                        post = post,
                        comment_feed = comment_feed,
                        comment_count = comment_count,
                        likes = like_count)
        else:
            self.render("permalink.html",
                        post = post,
                        comment_feed = comment_feed,
                        comment_count = comment_count,
                        likes = like_count)

    def post(self, post_id):
        # GQL queries and other elements to generate individual post page
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comment_feed = db.GqlQuery("SELECT * FROM Comments WHERE post_id = " +
                                    post_id + " ORDER BY created DESC")
        comment_count = comment_feed.count()
        like_lookup = db.GqlQuery("SELECT * FROM Likes WHERE post_id = " +
                                    post_id)
        like_count = like_lookup.count()

        if not post:
            # If the post does not exist return a 404
            self.error(404)
            self.write("This post does not exist!")
            return

        c = ""
        if self.user:
            if (self.request.get('like') and
                self.request.get('like') == 'update'):
            # If a like button is pressed then lookup whether a like
            # already exists for the user
                user_likes = db.GqlQuery("SELECT * FROM Likes " +
                                        "WHERE post_id = " +
                                        post_id +
                                        " and user_id = " +
                                        str(self.user.key().id()))
                user_like_count = user_likes.count()
                if self.user.key().id() == post.user_id:
                    # If user is also author return error if they
                    # like their own post
                    like_error = "You cannot like your own post!"
                    self.render("permalink.html",
                                post = post,
                                comment_feed = comment_feed,
                                comment_count = comment_count,
                                likes = like_count,
                                like_error = like_error)
                elif user_like_count == 0:
                    # If user has not liked the post
                    # put the like data into the datastore
                    l = Likes(parent = blog_key(),
                                user_id = self.user.key().id(),
                                post_id = int(post_id))
                    l.put()
                    self.render("permalink.html",
                                post = post,
                                comment_feed = comment_feed,
                                comment_count = comment_count,
                                likes = like_count)
                else:
                    # Returns error if user likes more than once
                    like_error = "You can only like a post once!"
                    self.render("permalink.html",
                                post = post,
                                comment_feed = comment_feed,
                                comment_count = comment_count,
                                likes = like_count,
                                like_error = like_error)
            if self.request.get('comment'):
                # If comment exists add comment to datastore
                c = Comments(parent = blog_key(),
                            user_id = self.user.key().id(),
                            post_id = int(post_id),
                            comment = self.request.get('comment'))
                c.put()
                self.render("permalink.html",
                            post = post,
                            comment_feed = comment_feed,
                            comment_count = comment_count,
                            likes = like_count)
        else:
            # Is not user redirect to login page
            self.redirect("/login")


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            # If subject and content exist then
            # put post content into databse
            p = Post(parent = blog_key(), user_id = self.user.key().id(),
                    subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)

class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            # If user exists render edit post page else redirect to login
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                # If the post does not exist return 404
                self.error(404)
                self.write("This post does not exist!")
                return
            elif post.user_id == self.user.key().id():
                self.render("edit-post.html", subject = post.subject,
                            content = post.content, post_id = post_id)
            else:
                error = "You need permission to edit this post."
                self.render("edit-post.html", error = error)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            # If subject and content exists put content in datastore
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                # If the post does not exist return 404
                self.error(404)
                self.write("This post does not exist!")
                return
            else:
                post.subject = subject
                post.content = content
                if post.user_id == self.user.key().id():
                    post.put()
                    self.redirect('/blog/%s' % post_id)
                else:
                    error = "You can only edit your own posts!"
                    self.render("edit-post.html",
                                subject = subject,
                                content = content,
                                error = error)
        else:
            error = "You need a title and content for your post!"
            self.render("edit-post.html",
                        subject = subject,
                        content = content,
                        error = error)

class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            # If author user ID matches user ID
            # then remove post from datastore
            key = db.Key.from_path('Post', int(post_id), parent = blog_key())
            post = db.get(key)
            if not post:
                # If the post does not exist return 404
                self.error(404)
                self.write("This post does not exist!")
                return
            elif post.user_id == self.user.key().id():
                post.delete()
                success = "Your post has been succesfully deleted!"
                self.render("delete-post.html", success = success)
            else:
                fail = "You do not have permission to delete this post!"
                self.render("delete-post.html", fail = fail)
        else:
            self.redirect("/login")

class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        # If comment author ID matches user ID
        # then load edit comments page
        # otherwise redirect to login page
        if self.user:
            key = db.Key.from_path('Comments',
                                    int(comment_id),
                                    parent = blog_key())
            c = db.get(key)
            if not c:
                # If the post does not exist return 404
                self.error(404)
                self.write("This post does not exist!")
                return
            elif c.user_id == self.user.key().id():
                self.render("edit-comments.html", comment = c.comment)
            else:
                error = "You can only edit your own comments."
                self.render("edit-comments.html", error = error)
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        # If comment exists update comment with
        # new content in datastore
        if not self.user:
            self.redirect("/login")

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comments',
                                    int(comment_id),
                                    parent = blog_key())
            c = db.get(key)
            if not c:
                # If the post does not exist return 404
                self.error(404)
                self.write("This comment does not exist!")
                return
            elif c.user_id == self.user.key().id():
                c.comment = comment
                c.put()
                self.redirect('/blog/%s' % post_id)
            else:
                error = "You can only edit your own comments!"
                self.render("edit-comments.html",
                            subject = subject,
                            content = content,
                            error = error)
        else:
            error = "Please provide a comment!"
            self.render("edit-comments.html", error = error)

class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        # If comment author ID matches user ID
        # remove comment from datastore
        if self.user:
            key = db.Key.from_path('Comments',
                                    int(comment_id),
                                    parent = blog_key())
            c = db.get(key)
            if not c:
                # If the post does not exist return 404
                self.error(404)
                self.write("This comment does not exist!")
                return
            elif c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/%s" % post_id)
            else:
                self.redirect("/login")
        else:
            self.redirect("/login")


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    # Checks if username is valid
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    # Checks if password is valid
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    # Checks if email is valid
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        # Gets all inputs from form
        self.firstname = self.request.get('firstname').title()
        self.lastname = self.request.get('lastname').title()
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # Creates dictionary with arguments that
        # that will be passed into template
        params = dict(username = self.username,
                      email = self.email)

        # Checks if all inputs are valid and if not return errors
        if not self.firstname:
            params['error_firstname'] = "You need to provide your first name."
            have_error = True

        if not self.lastname:
            params['error_lastname'] = "You need to provide your last name."
            have_error = True

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            # If error exists return signup form with
            # error mesages
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        # Make sure the user doesn't already exist
        # and if they do not exist add User info
        # to the datastore
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.firstname,
                            self.lastname,
                            self.username,
                            self.password,
                            self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            # If user exists set user cookie
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        # Remove cookie
        self.logout()
        self.redirect('/blog/logged-out')

class LogoutPage(BlogHandler):
    def get(self):
        self.render('logged-out.html')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/blog/logged-out', LogoutPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/welcome', Unit3Welcome),
                               ],
                              debug=True)