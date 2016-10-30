from google.appengine.ext import db
from user import User

class Likes(db.Model):
    user_id = db.IntegerProperty(required = True)
    post_id = db.IntegerProperty(required = True)