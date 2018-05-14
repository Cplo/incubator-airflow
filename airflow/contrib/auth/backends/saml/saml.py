#!/usr/bin/env python
# -*- coding: utf-8 -*-
from onelogin.saml2.auth import OneLogin_Saml2_Auth, OneLogin_Saml2_Settings
from flask import request, Request, redirect
from urlparse import urlparse
from OpenSSL import crypto
from os.path import exists
from typing import Dict
import hashlib
import jinja2
import json
import os


SAML_HOST = "https://airflow.devops.xiaohongshu.com"


def login_redirect():
    if 'referrer' in request.headers:
        return_to = request.headers['referrer']
    else:
        return_to = SAML_HOST + "/api/v1/login"
    return redirect(init_saml_auth().login(return_to=return_to), code=302)


class SamlUser(object):
    def __init__(self):
        self._auth = init_saml_auth()
        self._identifier = None
        self._auth.process_response()

    @property
    def email(self):
        key = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
        emails = self._auth.get_attribute(key)
        if not emails:
            return None
        return emails[0]

    @property
    def name(self):
        key = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'
        names = self._auth.get_attribute(key)
        if not names:
            return None
        return names[0]

    @property
    def group(self):
        key = 'http://schemas.xmlsoap.org/claims/Group'
        groups = self._auth.get_attribute(key)
        if len(groups) < 2:
            return ""
        else:
            return groups[1]


class Config(object):
    DOMAIN = SAML_HOST
    SAML_CERT_PATH = os.path.dirname(os.path.abspath(__file__))
    SAML_CONFIG_PATH = os.path.dirname(os.path.abspath(__file__))


def init_saml_auth():
    # type: (Dict) -> OneLogin_Saml2_Auth
    req_data = prepare_request(request)
    settings = load_settings()
    auth = OneLogin_Saml2_Auth(
        request_data=req_data,
        old_settings=settings
    )
    return auth


def prepare_request(req):
    # type: (Request) -> Dict
    domain = urlparse(Config.DOMAIN)
    return {
        'https': 'on' if domain.scheme == 'https' else 'off',
        'server_name': domain.hostname,
        'script_name': req.path,
        'get_data': req.args.copy(),
        'post_data': req.form.copy(),
        'lowercase_urlencoding': True,
        'query_string': req.query_string
    }


def load_settings():
    # type:() -> Dict
    settings = render_settings_template()
    settings = json.loads(settings)

    advanced_filename = '{}/advanced_settings.json'.format(Config.SAML_CONFIG_PATH)
    if not exists(advanced_filename):
        return settings

    with open(advanced_filename, 'r') as json_data:
        settings.update(json.load(json_data))
    return settings


def render_settings_template():
    cert_path = Config.SAML_CERT_PATH
    dp_cert = "{}/data-platform.cert".format(cert_path)
    dp_key = "{}/data-platform.key".format(cert_path)

    args = {
        "domain": Config.DOMAIN,
        "data_platform_cert": read_cert(dp_cert),
        "data_platform_key": read_cert(dp_key),
    }

    tpath = "{}/settings.json".format(Config.SAML_CONFIG_PATH)
    import os
    print(os.getcwd())
    with open(tpath, 'r') as f:
        content = f.read()
        template = jinja2.Template(content)
    return template.render(**args)


def format_cert(c):
    # type: (unicode) -> unicode
    c = c.replace('\r', '')
    c = c.replace('\n', '')
    c = c.replace('\x0D', '')
    return c


def read_cert(p):
    try:
        with open(p, "r") as f:
            p = f.read()
            p = format_cert(p)
            return p
    except:
        return ""


def generate_metadata():
    settings = load_settings()
    settings = OneLogin_Saml2_Settings(settings=settings)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if len(errors) > 0:
        print("generate saml metadata failed: {}".format(errors))
        return

    meta_path = "{}/saml_metadata.xml".format(Config.SAML_CONFIG_PATH)
    with open(meta_path, "w") as f:
        f.write(metadata)


def create_cert(domain):
    # load base cert and key
    cert_path = Config.SAML_CERT_PATH
    base_cert = "{}/base.cert".format(cert_path)
    base_key = "{}/base.key".format(cert_path)
    with open(base_cert, "r") as f:
        content = f.read()
        base_cert = crypto.load_certificate(crypto.FILETYPE_PEM, content)
    with open(base_key, "r") as f:
        content = f.read()
        base_key = crypto.load_privatekey(crypto.FILETYPE_PEM, content)

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    md5_hash = hashlib.md5()
    md5_hash.update(domain)
    serial = int(md5_hash.hexdigest(), 36)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "CN"
    cert.get_subject().ST = "Shanghai"
    cert.get_subject().L = "Shanghai"
    cert.get_subject().O = "Red Book DataTeam"
    cert.get_subject().OU = "Red Book DataTeam"
    cert.get_subject().CN = domain
    cert.set_serial_number(serial=serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(base_cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(base_key, 'sha1')

    cert_file = "{}/data-platform.cert".format(cert_path)
    key_file = "{}/data-platform.key".format(cert_path)
    with open(cert_file, "wt") as f:
        content = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        f.write(content)

    with open(key_file, "wt") as f:
        content = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
        f.write(content)
