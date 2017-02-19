import unittest
import datetime
from base import BaseTestCase 
from app import bcrypt, app,db
from flask_login import current_user 
from app.users.models import Users 
from app.users.forms import RegisterForm, LoginForm, RecoverPasswordForm, SendEmailConfirmForm, ChangePasswordTokenForm
from app.users.utils import generate_confirmation_token, confirm_token

class TestUserForms(BaseTestCase):

    def test_validate_login_form(self):
        form = LoginForm(email="jreiher2003@yahoo.com",password="password123",remember=True)
        self.assertTrue(form.validate())

    def test_validate_register_form(self):
        form = RegisterForm(username="test1", email="test1@test.com", password="password123", password_confirm="password123")
        self.assertTrue(form.validate())

    def test_validate_register_form_email_already_exsits(self):
        """ validate false email already registed """
        form = RegisterForm(username="test1", email="jreiher2003@yahoo.com", password="password123", password_confirm="password123")
        self.assertFalse(form.validate())

    def test_validate_recover_password_form_email_not_registered(self):
        """ should validate false """
        form = RecoverPasswordForm(email="test@test123.com")
        self.assertFalse(form.validate())

    def test_validate_recover_password_form_email_good_registered(self):
        """ should validate true """
        form = RecoverPasswordForm(email="jreiher2003@yahoo.com")
        self.assertTrue(form.validate())

    def test_validate_send_email_confirm_form(self):
        form = SendEmailConfirmForm(email="test@test.com")
        self.assertTrue(form.validate())

    def test_validate_change_password_token_form(self):
        form = ChangePasswordTokenForm(password="password1234", password_confirm="password1234")
        self.assertTrue(form.validate())

    

class TestUserViews(BaseTestCase):

    def test_register_page(self):
        with self.client:
            response1 = self.client.get("/register/", content_type="html/text")
            self.assertTrue('Register',response1.data)

    def test_get_by_id(self):
        with self.client:
            self.client.post("/login/", data=dict(
                email="jreiher2003@yahoo.com", password="password123"
            ), follow_redirects=True)
            self.assertTrue(current_user.is_active)
            self.assertTrue(current_user.id == 1)
            self.assertFalse(current_user.id == 20)

    def test_check_password(self):
        user = Users.query.filter_by(email="jreiher2003@yahoo.com").first()
        self.assertTrue(bcrypt.check_password_hash(user.password, "password123"))
        self.assertFalse(bcrypt.check_password_hash(user.password, "foobar"))
        
    def login(self, email, password):
        return self.client.post('/login/', data=dict(
            email=email,
            password=password
        ), follow_redirects=True)

    def logout(self):
        return self.client.get('/logout/', follow_redirects=True)

    def test_login_logout(self):
        rv = self.login('jreiher2003@yahoo.com', 'password123')
        assert 'yo' in rv.data
        rv = self.logout()
        assert 'You were logged out' in rv.data
        rv = self.login('adminx@yahoo.com', 'default')
        assert 'Invalid Credentials' in rv.data
        rv = self.login('admin@yahoo.com', 'defaultx')
        assert 'Invalid Credentials' in rv.data

    def test_correct_login(self):
        # Ensure login behaves correctly with correct credentials.
        with self.client:
            response = self.client.post(
                '/login/',
                data=dict(email="jreiher2003@yahoo.com", password="password123"),
                follow_redirects=True
            )
            self.assertTrue(response.status_code == 200)
            self.assertTrue(current_user.email == "jreiher2003@yahoo.com")
            self.assertTrue(current_user.is_active())
            self.assertTrue(current_user.is_authenticated())
            self.assertTemplateUsed('index.html')

    def test_incorrect_login(self):
        # Ensure login behaves correctly with incorrect credentials.
        with self.client:
            response = self.client.post(
                '/login/',
                data=dict(email="not@correct.com", password="incorrect"),
                follow_redirects=True
            )
            self.assertTrue(response.status_code == 200)
            self.assertIn(b'Invalid', response.data)
            self.assertFalse(current_user.is_active)
            self.assertFalse(current_user.is_authenticated)
            self.assertTemplateUsed('login.html')

    def test_profile_route_requires_login(self):
        # Ensure profile route requires logged in user.
        self.client.get('/profile/', follow_redirects=True)
        self.assertTemplateUsed('login.html')

    def test_confirm_token_route_requires_login(self):
        # Ensure confirm/<token> route requires logged in user.
        self.client.get('/confirm/blah', follow_redirects=True)
        self.assertTemplateUsed('login.html')

    def test_confirm_token_route_valid_token(self):
        # Ensure user can confirm account with valid token.
        with self.client:
            self.client.post('/login/', data=dict(
                email='jreiher2003@yahoo.com', password='password123'
            ), follow_redirects=True)
            token = generate_confirmation_token('jreiher2003@yahoo.com')
            response = self.client.get(
                '/confirm/'+token, follow_redirects=True)
            self.assertIn(
                b'You have confirmed your account. Thanks!', response.data)
            self.assertTemplateUsed('index.html')
            user = Users.query.filter_by(email='jreiher2003@yahoo.com').first_or_404()
            self.assertIsInstance(user.confirmed_at, datetime.datetime)
            self.assertTrue(user.confirmed)

    def test_confirm_token_route_invalid_token(self):
        # Ensure user cannot confirm account with invalid token.
        with self.client:
            self.client.post('/login/', data=dict(
                email='jreiher2003@yahoo.com', password='password123'
            ), follow_redirects=True)
            token = generate_confirmation_token('test@test1.com')
            response = self.client.get('/confirm/'+token, follow_redirects=True)
            self.assertIn(b'The confirmation link is invalid or has expired.',response.data)

    def test_confirm_token_route_expired_token(self):
        # Ensure user cannot confirm account with expired token.
        user = Users(username="testme",email='test@test1.com', password='test1', confirmed=False)
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token('test@test1.com')
        self.assertFalse(confirm_token(token, -1))

    def test_forgot_password_does_not_require_login(self):
        # Ensure user can request new password without login.
        self.client.get('/forgot-password/', follow_redirects=True)
        self.assertTemplateUsed('forgot_password.html')

    def test_correct_forgot_password_request(self):
        """Ensure login behaves correctly with correct credentials. requires a registered email"""
        with self.client:
            response = self.client.post(
                '/forgot-password/',
                data=dict(email="jreiher2003@yahoo.com"),
                follow_redirects=True
            )
            self.assertTrue(response.status_code == 200)
            self.assertTemplateUsed('login.html')

    def test_reset_forgotten_password_valid_token(self):
        # Ensure user can confirm account with valid token.
        with self.client:
            self.client.post('/forgot-password/', data=dict(
                email='jreiher2003@yahoo.com',
            ), follow_redirects=True)
            token = generate_confirmation_token('jreiher2003@yahoo.com')
            response = self.client.get('/password-reset/'+token, follow_redirects=True)
            self.assertTemplateUsed('forgot_password_change.html')
            self.assertIn(
                b'Reset Password',
                response.data
            )
            self.assertFalse(current_user.is_authenticated)

    def test_reset_forgotten_password_valid_token_correct_login(self):
        # Ensure user can confirm account with valid token.
        with self.client:
            self.client.post('/forgot-password/', data=dict(
                email='jreiher2003@yahoo.com',
            ), follow_redirects=True)
            token = generate_confirmation_token('jreiher2003@yahoo.com')
            response = self.client.get('/password-reset/'+token+"/", follow_redirects=True)
            self.assertTemplateUsed('forgot_password_change.html')
            self.assertIn(
                b'Reset Password',
                response.data
            )
            response = self.client.post(
                '/password-reset/'+token+"/",
                data=dict(password="new-password", confirm="new-password"),
                follow_redirects=True
            )
            self.assertIn(
                b'Successful password updated!',
                response.data
            )
            self.assertTemplateUsed('index.html')
            self.assertTrue(current_user.is_authenticated)
            self.client.get('/logout/')
            self.assertFalse(current_user.is_authenticated)

            response = self.client.post(
                '/login/',
                data=dict(email="jreiher2003@yahoo.com", password="new-password"),
                follow_redirects=True
            )
            self.assertTrue(response.status_code == 200)
            self.assertTrue(current_user.email == "jreiher2003@yahoo.com")
            self.assertTrue(current_user.is_active())
            self.assertTrue(current_user.is_authenticated)
            self.assertTemplateUsed('index.html')

    def test_reset_forgotten_password_valid_token_invalid_login(self):
        # Ensure user can confirm account with valid token.
        with self.client:
            self.client.post('/forgot-password/', data=dict(
                email='jreiher2003@yahoo.com',
            ), follow_redirects=True)
            token = generate_confirmation_token('jreiher2003@yahoo.com')
            response = self.client.get('/password-reset/'+token+"/", follow_redirects=True)
            self.assertTemplateUsed('forgot_password_change.html')
            self.assertIn(
                b'Reset Password',
                response.data
            )
            response = self.client.post(
                '/password-reset/'+token+"/",
                data=dict(password="new-password", confirm="new-password"),
                follow_redirects=True
            )
            self.assertIn(
                b'Successful password updated!',
                response.data
            )
            self.assertTemplateUsed('index.html')
            self.assertTrue(current_user.is_authenticated)
            self.client.get('/logout/')
            self.assertFalse(current_user.is_authenticated)

            response = self.client.post(
                '/login/',
                data=dict(email="jreiher2003@yahoo.com", password="just_a_test_user"),
                follow_redirects=True
            )
            self.assertTrue(response.status_code == 200)
            self.assertFalse(current_user.is_authenticated)
            self.assertIn(
                b'<strong>Invalid Credentials.</strong> Please try again.',
                response.data
            )
            self.assertTemplateUsed('login.html')

if __name__ == '__main__':
    unittest.main()