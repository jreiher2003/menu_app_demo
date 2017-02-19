import os 
import unittest 
from app import app, db
from flask_script import Manager, Server 

manager = Manager(app)

manager.add_command("runserver", Server(host="0.0.0.0",port=6970))

@manager.command 
def dropdb():
    print "drop all tables"
    db.drop_all()

@manager.command 
def createall():
    print "just created all tables"
    db.create_all()

@manager.command 
def test():
    """ Runs the tests without coverage. """
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)

if __name__ == "__main__":
    manager.run()