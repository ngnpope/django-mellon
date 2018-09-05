import re
import datetime

import mock
import lasso
import requests.exceptions
from httmock import HTTMock

from mellon.utils import create_server, create_metadata, iso8601_to_datetime, flatten_datetime
import mellon.utils
from xml_utils import assert_xml_constraints

from utils import error_500, metadata_response


def test_create_server_connection_error(mocker, rf, private_settings, caplog):
    mocker.patch('requests.get',
                 side_effect=requests.exceptions.ConnectionError('connection error'))
    private_settings.MELLON_IDENTITY_PROVIDERS = [
        {
            'METADATA_URL': 'http://example.com/metadata',
        }
    ]
    request = rf.get('/')
    create_server(request)
    assert 'connection error' in caplog.text


def test_create_server_internal_server_error(mocker, rf, private_settings, caplog):
    private_settings.MELLON_IDENTITY_PROVIDERS = [
        {
            'METADATA_URL': 'http://example.com/metadata',
        }
    ]
    request = rf.get('/')
    assert not 'failed with error' in caplog.text
    with HTTMock(error_500):
        create_server(request)
    assert 'failed with error' in caplog.text


def test_create_server_invalid_metadata(mocker, rf, private_settings, caplog):
    private_settings.MELLON_IDENTITY_PROVIDERS = [
        {
            'METADATA': 'xxx',
        }
    ]
    request = rf.get('/')
    assert not 'failed with error' in caplog.text
    with HTTMock(error_500):
        create_server(request)
    assert len(caplog.records) == 1
    assert re.search('METADATA.*is invalid', caplog.text)


def test_create_server_invalid_metadata_file(mocker, rf, private_settings, caplog):
    private_settings.MELLON_IDENTITY_PROVIDERS = [
        {
            'METADATA': '/xxx',
        }
    ]
    request = rf.get('/')
    assert not 'failed with error' in caplog.text
    with mock.patch('mellon.adapters.open', mock.mock_open(read_data='yyy'), create=True):
        with HTTMock(error_500):
            server = create_server(request)
    assert len(server.providers) == 0


def test_create_server_good_metadata_file(mocker, rf, private_settings, caplog):
    private_settings.MELLON_IDENTITY_PROVIDERS = [
        {
            'METADATA': '/xxx',
        }
    ]
    request = rf.get('/')
    with mock.patch(
        'mellon.adapters.open', mock.mock_open(read_data=open('tests/metadata.xml').read()),
            create=True):
        server = create_server(request)
    assert 'ERROR' not in caplog.text
    assert len(server.providers) == 1


def test_create_server_good_metadata(mocker, rf, private_settings, caplog):
    private_settings.MELLON_IDENTITY_PROVIDERS = [
        {
            'METADATA': open('tests/metadata.xml').read(),
        }
    ]
    request = rf.get('/')
    assert not 'failed with error' in caplog.text
    server = create_server(request)
    assert 'ERROR' not in caplog.text
    assert len(server.providers) == 1


def test_create_server_invalid_idp_dict(mocker, rf, private_settings, caplog):
    private_settings.MELLON_IDENTITY_PROVIDERS = [
        {
        }
    ]
    request = rf.get('/')
    assert not 'failed with error' in caplog.text
    create_server(request)
    assert 'missing METADATA' in caplog.text


def test_create_server_good_metadata_url(mocker, rf, private_settings, caplog):
    private_settings.MELLON_IDENTITY_PROVIDERS = [
        {
            'METADATA_URL': 'http://example.com/metadata',
        }
    ]

    request = rf.get('/')
    assert not 'failed with error' in caplog.text
    with HTTMock(metadata_response):
        server = create_server(request)
    assert 'ERROR' not in caplog.text
    assert len(server.providers) == 1


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
        'z': 'uu',
    }
    assert set(flatten_datetime(d).keys()) == set(['x', 'y', 'z'])
    assert flatten_datetime(d)['x'] == '2010-10-10T10:10:34'
    assert flatten_datetime(d)['y'] == 1
    assert flatten_datetime(d)['z'] == 'uu'
