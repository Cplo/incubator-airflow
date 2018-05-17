#!/usr/bin/env python
# -*- coding: utf-8 -*-

from airflow.contrib.auth.backends.saml import saml
import flask_login
import logging
from airflow import settings
from airflow import models
from flask import url_for, redirect
from flask import flash
from flask_login import login_required, current_user, logout_user

login_manager = flask_login.LoginManager()
login_manager.login_view = 'airflow.login'  # Calls login() bellow
login_manager.login_message = None
LOG = logging.getLogger(__name__)


class AuthenticationError(Exception):
    pass


class SamlUser(models.User):
    def is_active(self):
        '''Required by flask_login'''
        return True

    def is_authenticated(self):
        '''Required by flask_login'''
        return True

    def is_anonymous(self):
        '''Required by flask_login'''
        return False

    def get_id(self):
        '''Returns the current user id as required by flask_login'''
        return str(self.id)

    def data_profiling(self):
        '''Provides access to data profiling tools'''
        return True

    def is_superuser(self):
        '''Access all the things'''
        return True

    @property
    def user(self):
        return super(SamlUser, self)


@login_manager.user_loader
def load_user(userid):
    LOG.info("Loading user %s", userid)
    if not userid or userid == 'None':
        return None

    session = settings.Session()
    user = session.query(SamlUser).filter(models.User.id == int(userid)).first()
    if not user:
        return None
    session.expunge_all()
    session.commit()
    session.close()
    return user


def login(self, request):
    return saml.login_redirect()


def saml_login(self, request):
    try:
        saml_user = saml.SamlUser()
        session = settings.Session()
        if not saml_user.email:
            session.close()
            raise AuthenticationError("email not set")

        login_user = SamlUser()
        login_user.username = saml_user.email.split('@')[0]
        login_user.email = saml_user.email
        try_registe(login_user, session)

        LOG.info("User %s successfully authenticated", login_user.email)
        flask_login.login_user(login_user)
        session.commit()
        session.close()

        return redirect(url_for("admin.index"))
    except AuthenticationError as exp:
        flash("Incorrect login details")
        return "login failed for {}".format(exp)


def try_registe(user, session):
    query_user = session.query(models.User).filter(models.User.email == user.email).first()
    if not query_user:
        session.add(user)
        session.commit()
    else:
        user.id = query_user.id
