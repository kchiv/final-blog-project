from google.appengine.ext import db

import random
import hashlib
import hmac
from string import letters

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def valid_pw(name, password, h):
    # Check wether password is correct
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def make_pw_hash(name, pw, salt = None):
    # Hash a password with a salt
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def make_salt(length = 5):
    # Make random salt
    return ''.join(random.choice(letters) for x in xrange(length))



class User(db.Model):
    first_name = db.StringProperty(required = True)
    last_name = db.StringProperty(required = True)
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        # Find a user by their ID
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        # Find a user by their name
        u = db.GqlQuery("SELECT * FROM User WHERE name = :1", name).get()
        return u

    @classmethod
    def register(cls, first_name, last_name, name, pw, email = None):
        # Returns instance of the 'User' object
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    first_name = first_name,
                    last_name = last_name,
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        # Returns user if they input valid password
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u