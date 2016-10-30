from google.appengine.ext import db
from user import User

class Comments(db.Model):
    user_id = db.IntegerProperty(required = True)
    post_id = db.IntegerProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def getUserName(self):
        # Gets user by ID and returns first and last name
        user = User.by_id(self.user_id)
        full_name = "%s %s" % (user.first_name, user.last_name)
        return full_name