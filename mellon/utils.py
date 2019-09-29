# django-mellon - SAML2 authentication for Django
# Copyright (C) 2014-2019 Entr'ouvert
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import logging
import datetime
import importlib
from functools import wraps
import isodate
from xml.parsers import expat

import django
from django.contrib import auth
from django.template.loader import render_to_string
from django.utils.timezone import make_aware, now, make_naive, is_aware, get_default_timezone
from django.conf import settings
from django.utils.six.moves.urllib.parse import urlparse
import lasso

from . import app_settings
from .compat import reverse


def create_metadata(request):
    entity_id = reverse('mellon_metadata')
    login_url = reverse(app_settings.LOGIN_URL)
    logout_url = reverse(app_settings.LOGOUT_URL)
    public_keys = []
    for public_key in app_settings.PUBLIC_KEYS:
        if public_key.startswith('/'):
            # clean PEM file
            content = open(public_key).read()
            public_key = ''.join(content.splitlines()[1:-1])
        public_keys.append(public_key)
    name_id_formats = app_settings.NAME_ID_FORMATS
    ctx = {
        'request': request,
        'entity_id': request.build_absolute_uri(entity_id),
        'login_url': request.build_absolute_uri(login_url),
        'logout_url': request.build_absolute_uri(logout_url),
        'public_keys': public_keys,
        'name_id_formats': name_id_formats,
        'default_assertion_consumer_binding': app_settings.DEFAULT_ASSERTION_CONSUMER_BINDING,
        'organization': app_settings.ORGANIZATION,
        'contact_persons': app_settings.CONTACT_PERSONS,
    }
    if app_settings.METADATA_PUBLISH_DISCOVERY_RESPONSE:
        ctx['discovery_endpoint_url'] = request.build_absolute_uri(
            reverse('mellon_login'))
    return render_to_string('mellon/metadata.xml', ctx)


def create_server(request):
    logger = logging.getLogger(__name__)
    root = request.build_absolute_uri('/')
    cache = getattr(settings, '_MELLON_SERVER_CACHE', {})
    if root not in cache:
        metadata = create_metadata(request)
        if app_settings.PRIVATE_KEY:
            private_key = app_settings.PRIVATE_KEY
            private_key_password = app_settings.PRIVATE_KEY_PASSWORD
        elif app_settings.PRIVATE_KEYS:
            private_key = app_settings.PRIVATE_KEYS[0]
            private_key_password = None
            if isinstance(private_key, (tuple, list)):
                private_key_password = private_key[1]
                private_key = private_key[0]
        else:  # no signature
            private_key = None
            private_key_password = None
        server = lasso.Server.newFromBuffers(metadata, private_key_content=private_key,
                                             private_key_password=private_key_password)
        if app_settings.SIGNATURE_METHOD:
            symbol_name = 'SIGNATURE_METHOD_' + app_settings.SIGNATURE_METHOD.replace('-', '_').upper()
            if hasattr(lasso, symbol_name):
                server.signatureMethod = getattr(lasso, symbol_name)
            else:
                logger.warning('mellon: unable to set signature method %s', app_settings.SIGNATURE_METHOD)

        server.setEncryptionPrivateKeyWithPassword(private_key, private_key_password)
        private_keys = app_settings.PRIVATE_KEYS
        # skip first key if it is already loaded
        if not app_settings.PRIVATE_KEY:
            private_keys = app_settings.PRIVATE_KEYS[1:]
        for key in private_keys:
            password = None
            if isinstance(key, (tuple, list)):
                password = key[1]
                key = key[0]
            server.setEncryptionPrivateKeyWithPassword(key, password)
        for idp in get_idps():
            if idp and idp.get('METADATA'):
                try:
                    server.addProviderFromBuffer(lasso.PROVIDER_ROLE_IDP, idp['METADATA'])
                except lasso.Error as e:
                    logger.error('bad metadata in idp %s, %s', idp['ENTITY_ID'], e)
        cache[root] = server
        settings._MELLON_SERVER_CACHE = cache
    return settings._MELLON_SERVER_CACHE.get(root)


def create_login(request):
    server = create_server(request)
    login = lasso.Login(server)
    if not app_settings.PRIVATE_KEY and not app_settings.PRIVATE_KEYS:
        login.setSignatureHint(lasso.PROFILE_SIGNATURE_HINT_FORBID)
    return login


def get_idp(entity_id):
    for adapter in get_adapters():
        if hasattr(adapter, 'get_idp'):
            idp = adapter.get_idp(entity_id)
            if idp:
                return idp
    return {}


def get_idps():
    for adapter in get_adapters():
        if hasattr(adapter, 'get_idps'):
            for idp in adapter.get_idps():
                yield idp


def flatten_datetime(d):
    d = d.copy()
    for key, value in d.items():
        if isinstance(value, datetime.datetime):
            d[key] = value.isoformat()
    return d


def iso8601_to_datetime(date_string, default=None):
    '''Convert a string formatted as an ISO8601 date into a datetime
       value.

       This function ignores the sub-second resolution'''
    try:
        dt = isodate.parse_datetime(date_string)
    except Exception:
        return default
    if is_aware(dt):
        if not settings.USE_TZ:
            dt = make_naive(dt, get_default_timezone())
    else:
        if settings.USE_TZ:
            dt = make_aware(dt, get_default_timezone())
    return dt


def get_seconds_expiry(datetime_expiry):
    return (datetime_expiry - now()).total_seconds()


def to_list(func):
    @wraps(func)
    def f(*args, **kwargs):
        return list(func(*args, **kwargs))
    return f


def import_object(path):
    module, name = path.rsplit('.', 1)
    module = importlib.import_module(module)
    return getattr(module, name)


@to_list
def get_adapters(idp={}):
    idp = idp or {}
    adapters = tuple(idp.get('ADAPTER', ())) + tuple(app_settings.ADAPTER)
    for adapter in adapters:
        yield import_object(adapter)()


def get_values(saml_attributes, name):
    values = saml_attributes.get(name)
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        return (values,)
    return values


def get_setting(idp, name, default=None):
    '''Get a parameter from an IdP specific configuration or from the main
       settings.
    '''
    return idp.get(name) or getattr(app_settings, name, default)


def create_logout(request):
    logger = logging.getLogger(__name__)
    server = create_server(request)
    mellon_session = request.session.get('mellon_session', {})
    entity_id = mellon_session.get('issuer')
    session_index = mellon_session.get('session_index')
    name_id_format = mellon_session.get('name_id_format')
    name_id_content = mellon_session.get('name_id_content')
    name_id_name_qualifier = mellon_session.get('name_id_name_qualifier')
    name_id_sp_name_qualifier = mellon_session.get('name_id_sp_name_qualifier')
    session_dump = render_to_string('mellon/session_dump.xml', {
        'entity_id': entity_id,
        'session_index': session_index,
        'name_id_format': name_id_format,
        'name_id_content': name_id_content,
        'name_id_name_qualifier': name_id_name_qualifier,
        'name_id_sp_name_qualifier': name_id_sp_name_qualifier,
    })
    logger.debug('session_dump %s', session_dump)
    logout = lasso.Logout(server)
    if not app_settings.PRIVATE_KEY:
        logout.setSignatureHint(lasso.PROFILE_SIGNATURE_HINT_FORBID)
    logout.setSessionFromDump(session_dump)
    return logout


def is_nonnull(s):
    return '\x00' not in s


def same_origin(url1, url2):
    """
    Checks if two URLs are 'same-origin'
    """
    p1, p2 = urlparse(url1), urlparse(url2)
    if url1.startswith('/') or url2.startswith('/'):
        return True
    try:
        return (p1.scheme, p1.hostname, p1.port) == (p2.scheme, p2.hostname, p2.port)
    except ValueError:
        return False


def get_status_codes_and_message(profile):
    assert profile, 'missing lasso.Profile'
    assert profile.response, 'missing response in profile'
    assert profile.response.status, 'missing status in response'

    from .views import lasso_decode

    status_codes = []

    status = profile.response.status
    a = status
    while a.statusCode:
        status_codes.append(lasso_decode(a.statusCode.value))
        a = a.statusCode
    message = None
    if status.statusMessage:
        message = lasso_decode(status.statusMessage)
    return status_codes, message


def login(request, user):
    for adapter in get_adapters():
        if hasattr(adapter, 'auth_login'):
            adapter.auth_login(request, user)
            break
    else:
        auth.login(request, user)


def get_xml_encoding(content):
    xml_encoding = 'utf-8'

    def xmlDeclHandler(version, encoding, standalone):
        global xml_encoding

        if encoding:
            xml_encoding = encoding
    parser = expat.ParserCreate()
    parser.XmlDeclHandler = xmlDeclHandler
    try:
        parser.Parse(content, True)
    except expat.ExpatError as e:
        raise ValueError('invalid XML %s' % e)
    return xml_encoding


def get_local_path(request, url):
    if not url:
        return
    parsed = urlparse(url)
    path = parsed.path
    if request.META.get('SCRIPT_NAME'):
        path = path[len(request.META['SCRIPT_NAME']):]
    return path
