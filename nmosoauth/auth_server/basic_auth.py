from flask_basicauth import BasicAuth
from .models import User


class BasicAuthorization(BasicAuth):

    def check_credentials(self, username, password):
        try:
            user = User.query.filter_by(username=username).first()
            return username == user.username and password == user.password
        except Exception:
            self.challenge()


auth = BasicAuthorization()
