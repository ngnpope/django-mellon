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

import pytest
import mock
import lasso
from django.utils.six.moves.urllib.parse import parse_qs, urlparse
import base64
import random
import hashlib
from httmock import HTTMock

import django
from django.utils.encoding import force_text
from django.utils.http import urlencode

from xml_utils import assert_xml_constraints

from mellon.compat import reverse

from utils import error_500, html_response

pytestmark = pytest.mark.django_db


def test_null_character_on_samlresponse_post(app):
    app.post(reverse('mellon_login'), params={'SAMLResponse': '\x00'}, status=400)


def test_metadata(private_settings, client):
    ns = {
        'sm': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
    }
    private_settings.MELLON_PUBLIC_KEYS = ['xxx', '/yyy']
    private_settings.MELLON_NAME_ID_FORMATS = [lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED]
    private_settings.MELLON_DEFAULT_ASSERTION_CONSUMER_BINDING = 'artifact'
    private_settings.MELLON_ORGANIZATION = {
        'NAMES': [
            'Foobar',
            {
                'LABEL': 'FoobarEnglish',
                'LANG': 'en',
            }
        ],
        'DISPLAY_NAMES': [
            'Foobar',
            {
                'LABEL': 'FoobarEnglish',
                'LANG': 'en',
            }
        ],
        'URLS': [
            'http://foobar.com/',
            {
                'URL': 'http://foobar.com/en/',
                'LANG': 'en',
            }
        ],
    }
    private_settings.MELLON_CONTACT_PERSONS = [
        {
            'CONTACT_TYPE': 'administrative',
            'COMPANY': 'FooBar',
            'GIVENNAME': 'John',
            'SURNAME': 'Doe',
            'EMAIL_ADDRESSES': [
                'john.doe@foobar.com',
                'john.doe@personal-email.com',
            ],
            'TELEPHONE_NUMBERS': [
                '+abcd',
                '+1234',
            ],
        },
        {
            'CONTACT_TYPE': 'technical',
            'COMPANY': 'FooBar2',
            'GIVENNAME': 'John',
            'SURNAME': 'Doe',
            'EMAIL_ADDRESSES': [
                'john.doe@foobar.com',
                'john.doe@personal-email.com',
            ],
            'TELEPHONE_NUMBERS': [
                '+abcd',
                '+1234',
            ],
        },
    ]

    with mock.patch('mellon.utils.open', mock.mock_open(read_data='BEGIN\nyyy\nEND'), create=True):
        response = client.get('/metadata/')
    assert_xml_constraints(
        response.content,
        ('/sm:EntityDescriptor[@entityID="http://testserver/metadata/"]', 1,
         ('/*', 4),
         ('/sm:SPSSODescriptor', 1,
          ('/*', 6),
          ('/sm:NameIDFormat', 1),
          ('/sm:SingleLogoutService', 1),
          ('/sm:AssertionConsumerService', None,
           ('[@isDefault="true"]', None,
            ('[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"]', 1),
            ('[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]', 0)),
           ('[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]', 1)),
          ('/sm:KeyDescriptor/ds:KeyInfo/ds:X509Data', 2,
           ('/ds:X509Certificate', 2),
           ('/ds:X509Certificate[text()="xxx"]', 1),
           ('/ds:X509Certificate[text()="yyy"]', 1))),
         ('/sm:Organization', 1,
          ('/sm:OrganizationName', 2),
          ('/sm:OrganizationName[text()="Foobar"]', 1),
          ('/sm:OrganizationName[text()="FoobarEnglish"]', 1,
           ('[@xml:lang="en"]', 1)),
          ('/sm:OrganizationDisplayName', 2),
          ('/sm:OrganizationDisplayName[text()="Foobar"]', 1),
          ('/sm:OrganizationDisplayName[text()="FoobarEnglish"]', 1,
           ('[@xml:lang="en"]', 1)),
          ('/sm:OrganizationURL', 2),
          ('/sm:OrganizationURL[text()="http://foobar.com/"]', 1),
          ('/sm:OrganizationURL[text()="http://foobar.com/en/"]', 1,
           ('[@xml:lang="en"]', 1))),
         ('/sm:ContactPerson', 2,
          ('[@contactType="technical"]', 1),
          ('[@contactType="administrative"]', 1))),
        namespaces=ns)


def test_sp_initiated_login_improperly_configured2(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = []
    response = client.get('/login/')
    assert response.status_code == 400
    assert b'no idp found' in response.content


def test_sp_initiated_login_discovery_service(private_settings, client):
    private_settings.MELLON_DISCOVERY_SERVICE_URL = 'https://disco'
    response = client.get('/login/')
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('https://disco?')
    assert params == {'return': ['http://testserver/login/?nodisco=1'],
                      'entityID': ['http://testserver/metadata/']}


def test_sp_initiated_login_discovery_service_passive(private_settings, client):
    private_settings.MELLON_DISCOVERY_SERVICE_URL = 'https://disco'
    response = client.get('/login/?passive=1')
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('https://disco?')
    assert params == {'isPassive': ['true'],
                      'entityID': ['http://testserver/metadata/'],
                      'return': ['http://testserver/login/?passive=1&nodisco=1']}


def test_sp_initiated_login_discovery_service_nodisco(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = []
    private_settings.MELLON_DISCOVERY_SERVICE_URL = 'https://disco'
    response = client.get('/login/?nodisco=1')
    assert response.status_code == 400
    assert b'no idp found' in response.content


def test_sp_initiated_login(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': open('tests/metadata.xml').read(),
    }]
    response = client.get('/login/?next=%2Fwhatever')
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('http://idp5/singleSignOn?')
    assert set(params.keys()) == set(['SAMLRequest', 'RelayState'])
    assert len(params['SAMLRequest']) == 1
    assert base64.b64decode(params['SAMLRequest'][0])
    assert client.session['mellon_next_url_%s' % params['RelayState'][0]] == '/whatever'


def test_sp_initiated_login_chosen(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': open('tests/metadata.xml').read(),
    }]
    qs = urlencode({
        'entityID': 'http://idp5/metadata',
        'next': '/whatever',
    })
    response = client.get('/login/?' + qs)
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('http://idp5/singleSignOn?')
    assert set(params.keys()) == set(['SAMLRequest', 'RelayState'])
    assert len(params['SAMLRequest']) == 1
    assert base64.b64decode(params['SAMLRequest'][0])
    assert client.session['mellon_next_url_%s' % params['RelayState'][0]] == '/whatever'


def test_sp_initiated_login_requested_authn_context(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': open('tests/metadata.xml').read(),
        'AUTHN_CLASSREF': ['urn:be:fedict:iam:fas:citizen:eid',
                           'urn:be:fedict:iam:fas:citizen:token'],
    }]
    response = client.get('/login/')
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('http://idp5/singleSignOn?')
    assert list(params.keys()) == ['SAMLRequest']
    assert len(params['SAMLRequest']) == 1
    assert base64.b64decode(params['SAMLRequest'][0])
    request = lasso.Samlp2AuthnRequest()
    assert request.initFromQuery(urlparse(response['Location']).query)
    assert request.requestedAuthnContext.authnContextClassRef == (
        'urn:be:fedict:iam:fas:citizen:eid', 'urn:be:fedict:iam:fas:citizen:token')


def test_malfortmed_artifact(private_settings, client, caplog):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': open('tests/metadata.xml').read(),
    }]
    response = client.get('/login/?SAMLart=xxx', status=400)
    assert b'artifact is malformed' in response.content
    assert 'artifact is malformed' in caplog.text


@pytest.fixture
def artifact():
    entity_id = b'http://idp5/metadata'
    token = b'x' * 20
    return force_text(base64.b64encode(b'\x00\x04\x00\x00' + hashlib.sha1(entity_id).digest() + token))


def test_error_500_on_artifact_resolve(private_settings, client, caplog, artifact):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': open('tests/metadata.xml').read(),
    }]
    with HTTMock(error_500):
        client.get('/login/?SAMLart=%s' % artifact)
    assert 'IdP returned 500' in caplog.text


def test_invalid_msg_on_artifact_resolve(private_settings, client, caplog, artifact):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': open('tests/metadata.xml').read(),
    }]
    with HTTMock(html_response):
        client.get('/login/?SAMLart=%s' % artifact)
    assert 'ArtifactResolveResponse is malformed' in caplog.text
