import datetime 
from app import db, bcrypt 
from sqlalchemy.ext.hybrid import hybrid_property 

class Users(db.Model):
    __tablename__ = "users" 

    id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(50), nullable=False, unique=True) 
    email = db.Column(db.String(255), nullable=False, unique=True)
    _password = db.Column(db.String(255), nullable=False) #hybrid column
    confirmed = db.Column(db.Boolean(), default=False) 
    confirmed_at = db.Column(db.DateTime)
    date_created = db.Column(db.DateTime,  default=datetime.datetime.utcnow)
    date_modified = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    current_login_at = db.Column(db.DateTime)
    current_login_ip = db.Column(db.String(45))
    login_count = db.Column(db.Integer, default=0)

    @hybrid_property 
    def password(self):
        return self._password 

    @password.setter 
    def _set_password(self, plaintext):
        self._password = bcrypt.generate_password_hash(plaintext)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    def get_urole(self):
        return self.urole

    def __repr__(self):
        return "<username-{}".format(self.username)