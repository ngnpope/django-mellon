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

import mock
import lasso

from mellon.utils import create_metadata, iso8601_to_datetime, flatten_datetime
from mellon.views import check_next_url
from xml_utils import assert_xml_constraints


def test_create_metadata(rf, private_settings, caplog):
    ns = {
        'sm': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'idpdisc': 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol',
    }
    private_settings.MELLON_PUBLIC_KEYS = ['xxx', '/yyy']
    private_settings.MELLON_NAME_ID_FORMATS = [lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED]
    private_settings.MELLON_DEFAULT_ASSERTION_CONSUMER_BINDING = 'artifact'
    request = rf.get('/')
    with mock.patch('mellon.utils.open', mock.mock_open(read_data='BEGIN\nyyy\nEND'), create=True):
        metadata = create_metadata(request)
    assert_xml_constraints(
        metadata.encode('utf-8'),
        ('/sm:EntityDescriptor[@entityID="http://testserver/metadata/"]', 1,
         ('/*', 1),
         ('/sm:SPSSODescriptor', 1,
          ('/*', 6),
          ('/sm:NameIDFormat', 1),
          ('/sm:SingleLogoutService', 1),
          ('/sm:AssertionConsumerService[@isDefault=\'true\'][@Binding=\'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\']', 1),
          ('/sm:AssertionConsumerService[@isDefault=\'true\'][@Binding=\'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\']',
           0),
          ('/sm:AssertionConsumerService[@Binding=\'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\']',
           1),
          ('/sm:KeyDescriptor/ds:KeyInfo/ds:X509Data', 2,
           ('/ds:X509Certificate', 2),
           ('/ds:X509Certificate[text()=\'xxx\']', 1),
           ('/ds:X509Certificate[text()=\'yyy\']', 1)))),
        namespaces=ns)

    private_settings.MELLON_METADATA_PUBLISH_DISCOVERY_RESPONSE = True
    with mock.patch('mellon.utils.open', mock.mock_open(read_data='BEGIN\nyyy\nEND'), create=True):
        metadata = create_metadata(request)
    assert_xml_constraints(
        metadata.encode('utf-8'),
        ('/sm:EntityDescriptor[@entityID="http://testserver/metadata/"]', 1,
         ('/*', 1),
         ('/sm:SPSSODescriptor', 1,
          ('/*', 7),
          ('/sm:Extensions', 1,
           ('/idpdisc:DiscoveryResponse', 1)),
          ('/sm:NameIDFormat', 1),
          ('/sm:SingleLogoutService', 1),
          ('/sm:AssertionConsumerService[@isDefault=\'true\'][@Binding=\'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\']', 1),
          ('/sm:AssertionConsumerService[@isDefault=\'true\'][@Binding=\'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\']',
           0),
          ('/sm:AssertionConsumerService[@Binding=\'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\']',
           1),
          ('/sm:KeyDescriptor/ds:KeyInfo/ds:X509Data', 2,
           ('/ds:X509Certificate', 2),
           ('/ds:X509Certificate[text()=\'xxx\']', 1),
           ('/ds:X509Certificate[text()=\'yyy\']', 1)))),
        namespaces=ns)


def test_iso8601_to_datetime(private_settings):
    import django.utils.timezone
    import pytz

    private_settings.TIME_ZONE = 'UTC'
    if hasattr(django.utils.timezone.get_default_timezone, 'cache_clear'):
        django.utils.timezone.get_default_timezone.cache_clear()
    django.utils.timezone._localtime = None
    private_settings.USE_TZ = False
    # UTC ISO8601 -> naive datetime UTC
    assert iso8601_to_datetime('2010-10-01T10:10:34Z') == datetime.datetime(
        2010, 10, 1, 10, 10, 34)
    # NAIVE ISO8601 -> naive datetime UTC
    assert iso8601_to_datetime('2010-10-01T10:10:34') == datetime.datetime(
        2010, 10, 1, 10, 10, 34)
    private_settings.USE_TZ = True
    # UTC+1h ISO8601 -> Aware datetime UTC
    assert iso8601_to_datetime('2010-10-01T10:10:34+01:00') == datetime.datetime(
        2010, 10, 1, 9, 10, 34, tzinfo=pytz.utc)
    # Naive ISO8601 -> Aware datetime UTC
    assert iso8601_to_datetime('2010-10-01T10:10:34') == datetime.datetime(
        2010, 10, 1, 10, 10, 34, tzinfo=pytz.utc)


def test_flatten_datetime():
    d = {
        'x': datetime.datetime(2010, 10, 10, 10, 10, 34),
        'y': 1,
        'z': 'u',
    }
    assert set(flatten_datetime(d).keys()) == set(['x', 'y', 'z'])
    assert flatten_datetime(d)['x'] == '2010-10-10T10:10:34'
    assert flatten_datetime(d)['y'] == 1
    assert flatten_datetime(d)['z'] == 'u'


def test_check_next_url(rf):
    assert not check_next_url(rf.get('/'), u'')
    assert not check_next_url(rf.get('/'), None)
    assert not check_next_url(rf.get('/'), u'\x00')
    assert not check_next_url(rf.get('/'), u'\u010e')
    assert not check_next_url(rf.get('/'), u'https://example.invalid/')
    # default hostname is testserver
    assert check_next_url(rf.get('/'), u'http://testserver/ok/')
