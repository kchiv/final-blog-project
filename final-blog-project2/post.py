from google.appengine.ext import db
from user import User
import os
import jinja2
import jinjatemp

class Post(db.Model):
    user_id = db.IntegerProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        # Replace new line with line break for post content
        self._render_text = self.content.replace('\n', '<br>')
        return jinjatemp.temp_render_str("post.html", p = self)

    def getUserName(self):
        # Gets user by ID and returns first and last name
        user = User.by_id(self.user_id)
        full_name = "%s %s" % (user.first_name, user.last_name)
        return full_name