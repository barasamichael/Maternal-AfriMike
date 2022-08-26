import flask
from flask_login import login_required
from . import main
from .. import db

from ..models import (Permission)


@main.route('/')
@main.route('/home')
@main.route('/homepage')
def homepage():
    return flask.render_template('main/homepage.html')


@main.route('/contact_us')
def contact_us():
    return flask.render_template('main/contact_us.html')

@main.route('/branches')
def branches():
    branches = None
    return flask.render_template('main/branches.html', branches = branches)


@main.route('/about_us')
def about_us():
    return flask.render_template('main/about_us.html')
