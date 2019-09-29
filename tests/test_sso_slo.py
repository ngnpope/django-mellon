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

import datetime
import re
import base64
import zlib
import xml.etree.ElementTree as ET

import lasso

from pytest import fixture

from django.utils import six
from django.utils.six.moves.urllib import parse as urlparse
from django.utils.encoding import force_str

from mellon.utils import create_metadata

from httmock import all_requests, HTTMock, response as mock_response

from mellon.compat import reverse

from utils import reset_caplog


@fixture
def idp_metadata():
    return open('tests/metadata.xml').read()


@fixture
def idp_private_key():
    return open('tests/idp-private-key.pem').read()


@fixture
def sp_private_key():
    return open('tests/sp-private-key.pem').read()


@fixture
def sp_public_key():
    return ''.join(open('tests/sp-public-key.pem').read().splitlines()[1:-1])


@fixture
def sp_settings(private_settings, idp_metadata, sp_private_key, sp_public_key):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': idp_metadata,
    }]
    private_settings.MELLON_PUBLIC_KEYS = [sp_public_key]
    private_settings.MELLON_PRIVATE_KEYS = [sp_private_key]
    private_settings.MELLON_NAME_ID_POLICY_FORMAT = lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT
    private_settings.LOGIN_REDIRECT_URL = '/'
    private_settings.MELLON_SIGNATURE_METHOD = 'RSA_SHA256'
    return private_settings


@fixture
def sp_metadata(sp_settings, rf):
    request = rf.get('/')
    return create_metadata(request)


class MockIdp(object):
    def __init__(self, idp_metadata, private_key, sp_metadata):
        self.server = server = lasso.Server.newFromBuffers(idp_metadata, private_key)
        self.server.signatureMethod = lasso.SIGNATURE_METHOD_RSA_SHA256
        server.addProviderFromBuffer(lasso.PROVIDER_ROLE_SP, sp_metadata)

    def process_authn_request_redirect(self, url, auth_result=True, consent=True, msg=None):
        login = lasso.Login(self.server)
        login.processAuthnRequestMsg(url.split('?', 1)[1])
        # See
        # https://docs.python.org/2/library/zlib.html#zlib.decompress
        # for the -15 magic value.
        #
        # * -8 to -15: Uses the absolute value of wbits as the window size
        # logarithm. The input must be a raw stream with no header or trailer.
        #
        # it means Deflate instead of GZIP (same stream no header, no trailer)
        self.request = zlib.decompress(
            base64.b64decode(
                urlparse.parse_qs(
                    urlparse.urlparse(url).query)['SAMLRequest'][0]), -15)
        assert 'rsa-sha256' in url
        try:
            login.validateRequestMsg(auth_result, consent)
        except lasso.LoginRequestDeniedError:
            pass
        else:
            login.buildAssertion(lasso.SAML_AUTHENTICATION_METHOD_PASSWORD,
                                 datetime.datetime.now().isoformat(),
                                 None,
                                 datetime.datetime.now().isoformat(),
                                 datetime.datetime.now().isoformat())

            def add_attribute(name, *values, **kwargs):
                fmt = kwargs.get('fmt', lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC)
                statements = login.response.assertion[0].attributeStatement or [lasso.Saml2AttributeStatement()]
                statement = statements[0]
                login.response.assertion[0].attributeStatement = statements
                attributes = list(statement.attribute)
                for attribute in attributes:
                    if attribute.name == name and attribute.nameFormat == fmt:
                        break
                else:
                    attribute = lasso.Saml2Attribute()
                    attributes.append(attribute)
                    statement.attribute = attributes
                attribute_values = list(attribute.attributeValue)
                atv = lasso.Saml2AttributeValue()
                attribute_values.append(atv)
                attribute.attributeValue = attribute_values
                value_any = []
                for value in values:
                    if isinstance(value, lasso.Node):
                        value_any.append(value)
                    else:
                        mtn = lasso.MiscTextNode.newWithString(force_str(value))
                        mtn.textChild = True
                        value_any.append(mtn)
                atv.any = value_any
            add_attribute('email', 'john', '.doe@gmail.com')
            add_attribute('wtf', 'john', lasso.MiscTextNode.newWithXmlNode('<a>coucou</a>'))

        if not auth_result and msg:
            login.response.status.statusMessage = msg
        if login.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_ART:
            login.buildArtifactMsg(lasso.HTTP_METHOD_ARTIFACT_GET)
            self.artifact = login.artifact
            self.artifact_message = login.artifactMessage
        elif login.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_POST:
            login.buildAuthnResponseMsg()
        else:
            raise NotImplementedError
        if login.msgBody:
            assert b'rsa-sha256' in base64.b64decode(login.msgBody)
        return login.msgUrl, login.msgBody, login.msgRelayState

    def resolve_artifact(self, soap_message):
        login = lasso.Login(self.server)
        login.processRequestMsg(soap_message)
        assert 'rsa-sha256' in soap_message
        if hasattr(self, 'artifact') and self.artifact == login.artifact:
            # artifact is known, go on !
            login.artifactMessage = self.artifact_message
            # forget the artifact
            del self.artifact
            del self.artifact_message
        login.buildResponseMsg()
        assert 'rsa-sha256' in login.msgBody
        return '<?xml version="1.0"?>\n' + login.msgBody

    def mock_artifact_resolver(self):
        @all_requests
        def f(url, request):
            content = self.resolve_artifact(request.body)
            return mock_response(200, content=content,
                                 headers={'Content-Type': 'application/soap+xml'})
        return f


@fixture
def idp(sp_settings, idp_metadata, idp_private_key, sp_metadata):
    return MockIdp(idp_metadata, idp_private_key, sp_metadata)


def test_sso_slo(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login') + '?next=/whatever/')
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    assert relay_state
    assert 'eo:next_url' not in str(idp.request)
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), params={'SAMLResponse': body, 'RelayState': relay_state})
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert urlparse.urlparse(response['Location']).path == '/whatever/'


def test_sso(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login'))
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    assert not relay_state
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), params={'SAMLResponse': body, 'RelayState': relay_state})
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert urlparse.urlparse(response['Location']).path == sp_settings.LOGIN_REDIRECT_URL


def test_sso_request_denied(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login'))
    url, body, relay_state = idp.process_authn_request_redirect(
        response['Location'],
        auth_result=False,
        msg='User is not allowed to login')
    assert not relay_state
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), params={'SAMLResponse': body, 'RelayState': relay_state})
    if six.PY3:
        assert "status is not success codes: ['urn:oasis:names:tc:SAML:2.0:status:Responder',\
 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied']" in caplog.text
    else:
        assert "status is not success codes: [u'urn:oasis:names:tc:SAML:2.0:status:Responder',\
 u'urn:oasis:names:tc:SAML:2.0:status:RequestDenied']" in caplog.text


def test_sso_request_denied_artifact(db, app, caplog, sp_settings, idp_metadata, idp_private_key, rf):
    sp_settings.MELLON_DEFAULT_ASSERTION_CONSUMER_BINDING = 'artifact'
    request = rf.get('/')
    sp_metadata = create_metadata(request)
    idp = MockIdp(idp_metadata, idp_private_key, sp_metadata)
    response = app.get(reverse('mellon_login'))
    url, body, relay_state = idp.process_authn_request_redirect(
        response['Location'],
        auth_result=False,
        msg='User is not allowed to login')
    assert not relay_state
    assert body is None
    assert reverse('mellon_login') in url
    assert 'SAMLart' in url
    acs_artifact_url = url.split('testserver', 1)[1]
    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url, params={'RelayState': relay_state})
    assert "status is not success codes: ['urn:oasis:names:tc:SAML:2.0:status:Responder',\
 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied']" in caplog.text
    assert 'User is not allowed to login' in response


def test_sso_artifact(db, app, caplog, sp_settings, idp_metadata, idp_private_key, rf):
    sp_settings.MELLON_DEFAULT_ASSERTION_CONSUMER_BINDING = 'artifact'
    request = rf.get('/')
    sp_metadata = create_metadata(request)
    idp = MockIdp(idp_metadata, idp_private_key, sp_metadata)
    response = app.get(reverse('mellon_login') + '?next=/whatever/')
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    assert relay_state
    assert body is None
    assert reverse('mellon_login') in url
    assert 'SAMLart' in url
    acs_artifact_url = url.split('testserver', 1)[1]
    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url, params={'RelayState': relay_state})
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert urlparse.urlparse(response['Location']).path == '/whatever/'
    # force delog, but keep session information for relaystate handling
    assert app.session
    del app.session['_auth_user_id']
    assert 'dead artifact' not in caplog.text
    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url, params={'RelayState': relay_state})
    # verify retry login was asked
    assert 'dead artifact' in caplog.text
    assert urlparse.urlparse(response['Location']).path == reverse('mellon_login')
    response = response.follow()
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    assert relay_state
    reset_caplog(caplog)
    # verify caplog has been cleaned
    assert 'created new user' not in caplog.text
    assert body is None
    assert reverse('mellon_login') in url
    assert 'SAMLart' in url
    acs_artifact_url = url.split('testserver', 1)[1]
    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url, params={'RelayState': relay_state})
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert urlparse.urlparse(response['Location']).path == '/whatever/'


def test_sso_slo_pass_next_url(db, app, idp, caplog, sp_settings):
    sp_settings.MELLON_ADD_AUTHNREQUEST_NEXT_URL_EXTENSION = True
    response = app.get(reverse('mellon_login') + '?next=/whatever/')
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    assert 'eo:next_url' in str(idp.request)
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), params={'SAMLResponse': body, 'RelayState': relay_state})
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert response['Location'].endswith('/whatever/')


def test_sso_artifact_no_loop(db, app, caplog, sp_settings, idp_metadata, idp_private_key, rf):
    sp_settings.MELLON_DEFAULT_ASSERTION_CONSUMER_BINDING = 'artifact'
    request = rf.get('/')
    sp_metadata = create_metadata(request)
    idp = MockIdp(idp_metadata, idp_private_key, sp_metadata)
    response = app.get(reverse('mellon_login'))
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    assert body is None
    assert reverse('mellon_login') in url
    assert 'SAMLart' in url
    acs_artifact_url = url.split('testserver', 1)[1]

    # forget the artifact
    idp.artifact = ''

    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url)
    assert 'MELLON_RETRY_LOGIN=1;' in response['Set-Cookie']

    # first error, we retry
    assert urlparse.urlparse(response['Location']).path == reverse('mellon_login')

    # check we are not logged
    assert not app.session

    # redo
    response = app.get(reverse('mellon_login'))
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    assert body is None
    assert reverse('mellon_login') in url
    assert 'SAMLart' in url
    acs_artifact_url = url.split('testserver', 1)[1]

    # forget the artifact
    idp.artifact = ''
    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url)

    # check cookie is deleted after failed retry
    # Py3-Dj111 variation
    assert re.match(r'.*MELLON_RETRY_LOGIN=("")?;', response['Set-Cookie'])
    assert 'Location' not in response

    # check we are still not logged
    assert not app.session

    # check return url is in page
    assert '"%s"' % sp_settings.LOGIN_REDIRECT_URL in response.text


def test_sso_slo_pass_login_hints_always_backoffice(db, app, idp, caplog, sp_settings):
    sp_settings.MELLON_LOGIN_HINTS = ['always_backoffice']
    response = app.get(reverse('mellon_login') + '?next=/whatever/')
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    root = ET.fromstring(idp.request)
    login_hints = root.findall('.//{https://www.entrouvert.com/}login-hint')
    assert len(login_hints) == 1, 'missing login hint'
    assert login_hints[0].text == 'backoffice', 'login hint is not backoffice'


def test_sso_slo_pass_login_hints_backoffice(db, app, idp, caplog, sp_settings):
    sp_settings.MELLON_LOGIN_HINTS = ['backoffice']
    response = app.get(reverse('mellon_login') + '?next=/whatever/')
    url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
    root = ET.fromstring(idp.request)
    login_hints = root.findall('.//{https://www.entrouvert.com/}login-hint')
    assert len(login_hints) == 0

    for next_url in ['/manage/', '/admin/', '/manager/']:
        response = app.get(reverse('mellon_login') + '?next=%s' % next_url)
        url, body, relay_state = idp.process_authn_request_redirect(response['Location'])
        root = ET.fromstring(idp.request)
        login_hints = root.findall('.//{https://www.entrouvert.com/}login-hint')
        assert len(login_hints) == 1, 'missing login hint'
        assert login_hints[0].text == 'backoffice', 'login hint is not backoffice'


def test_middleware_mixin_first_time(db, app, idp, caplog, settings):
    settings.MELLON_OPENED_SESSION_COOKIE_NAME = 'IDP_SESSION'
    assert 'MELLON_PASSIVE_TRIED' not in app.cookies
    # webtest-lint is against unicode
    app.set_cookie(str('IDP_SESSION'), str('1'))
    response = app.get('/', status=302)
    assert urlparse.urlparse(response.location).path == '/login/'
    assert (urlparse.parse_qs(urlparse.urlparse(response.location).query, keep_blank_values=True)
            == {'next': ['http://testserver/'], 'passive': ['']})

    # simulate closing of session at IdP
    app.cookiejar.clear('testserver.local', '/', 'IDP_SESSION')
    assert 'IDP_SESSION' not in app.cookies

    # verify MELLON_PASSIVE_TRIED is removed
    assert 'MELLON_PASSIVE_TRIED' in app.cookies
    response = app.get('/', status=200)
    assert 'MELLON_PASSIVE_TRIED' not in app.cookies

    # check passive authentication is tried again
    app.set_cookie(str('IDP_SESSION'), str('1'))
    response = app.get('/', status=302)
    assert urlparse.urlparse(response.location).path == '/login/'
    assert (urlparse.parse_qs(urlparse.urlparse(response.location).query, keep_blank_values=True)
            == {'next': ['http://testserver/'], 'passive': ['']})
    assert 'MELLON_PASSIVE_TRIED' in app.cookies
