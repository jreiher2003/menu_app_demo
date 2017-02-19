import datetime
from flask_testing import TestCase 
from app import app,db 
from app.users.models import Users 

class BaseTestCase(TestCase):
    """ A base test case """ 

    def create_app(self):
        app.config.from_object('config.TestConfig')
        app.test_client() 
        return app 

    @classmethod
    def setUp(self):
        db.create_all()
        db.session.add(
            Users(
                username="j3ff_",
                email="jreiher2003@yahoo.com",
                password='password123'
                )
            )
        db.session.commit() 

    @classmethod
    def tearDown(self):
        db.session.remove()
        db.drop_all() 