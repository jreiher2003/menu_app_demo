# tests/test_config.py 

import unittest  
from flask import current_app 
from flask_testing import TestCase 
from app import app 

class TestDevelopmentConfig(TestCase):

    def create_app(self):
        app.config.from_object('config.DevelopmentConfig')
        return app

    def test_app_is_development(self):
        self.assertTrue(app.config['DEBUG'] is True)
        self.assertTrue(app.config['WTF_CSRF_ENABLED'] is True)
        self.assertTrue(app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] is True)
        self.assertTrue(app.config['RECAPTCHA_ENABLED'] is True)
        self.assertTrue(app.config['MAIL_SERVER'] == 'smtp.gmail.com')
        self.assertTrue(app.config['MAIL_DEFAULT_SENDER'] == '"Menu App Admin" <noreply@menu_app_demo.com>')

class TestProductionConfig(TestCase):

    def create_app(self):
        app.config.from_object('config.ProductionConfig')
        return app

    def test_app_is_production(self):
        self.assertTrue(app.config['DEBUG'] is False)

class TestTestingConfig(TestCase):

    def create_app(self):
        app.config.from_object('config.TestConfig')
        return app 

    def test_app_is_test_mode(self):
        self.assertTrue(app.config['DEBUG'] is True)
        self.assertTrue(app.config['TESTING'] is True)
        self.assertTrue(app.config['PRESERVE_CONTEXT_ON_EXCEPTION'] is False)
        self.assertTrue(app.config['WTF_CSRF_ENABLED'] is False)
        self.assertTrue(app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:')

    

if __name__ == '__main__':
    unittest.main()
       