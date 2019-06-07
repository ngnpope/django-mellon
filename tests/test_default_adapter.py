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

import pytest
import re
import lasso
from multiprocessing.pool import ThreadPool

from django.contrib import auth
from django.db import connection

from mellon.adapters import DefaultAdapter
from mellon.backends import SAMLBackend

pytestmark = pytest.mark.django_db

User = auth.get_user_model()


@pytest.fixture
def idp():
    return {
        'METADATA': open('tests/metadata.xml').read(),
    }


@pytest.fixture
def saml_attributes():
    return {
        'name_id_format': lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT,
        'name_id_content': 'x' * 32,
        'issuer': 'http://idp5/metadata',
        'username': ['foobar'],
        'email': ['test@example.net'],
        'first_name': ['Foo'],
        'last_name': ['Bar'],
        'is_superuser': ['true'],
        'group': ['GroupA', 'GroupB', 'GroupC'],
    }


@pytest.fixture
def john(db):
    return User.objects.create(username='john.doe', email='john.doe@example.com')


@pytest.fixture
def jane(db):
    return User.objects.create(username='jane.doe', email='john.doe@example.com')


def test_format_username(settings, idp, saml_attributes):
    adapter = DefaultAdapter()
    assert adapter.format_username(idp, {}) is None
    assert adapter.format_username(idp, saml_attributes) == ('x' * 32 + '@saml')[:30]
    settings.MELLON_USERNAME_TEMPLATE = '{attributes[name_id_content]}'
    assert adapter.format_username(idp, saml_attributes) == ('x' * 32)[:30]
    settings.MELLON_USERNAME_TEMPLATE = '{attributes[username][0]}'
    assert adapter.format_username(idp, saml_attributes) == 'foobar'


def test_lookup_user(settings, idp, saml_attributes):
    adapter = DefaultAdapter()
    user = adapter.lookup_user(idp, saml_attributes)
    assert user is not None

    user2 = adapter.lookup_user(idp, saml_attributes)
    assert user.id == user2.id

    User.objects.all().delete()
    assert User.objects.count() == 0

    settings.MELLON_PROVISION = False
    user = adapter.lookup_user(idp, saml_attributes)
    assert user is None
    assert User.objects.count() == 0


def test_lookup_user_transaction(transactional_db, concurrency, idp, saml_attributes):
    adapter = DefaultAdapter()
    p = ThreadPool(concurrency)

    if connection.vendor == 'postgresql':
        with connection.cursor() as c:
            c.execute('SHOW max_connections')
            max_connections = c.fetchone()[0]
            if int(max_connections) <= concurrency:
                pytest.skip('Number of concurrent connections above postgresql maximum limit')

    def f(i):
        # sqlite has a default lock timeout of 5s seconds between different access to the same in
        # memory DB
        if connection.vendor == 'sqlite':
            connection.cursor().execute('PRAGMA busy_timeout = 400000')
        try:
            return adapter.lookup_user(idp, saml_attributes)
        finally:
            connection.close()
    users = p.map(f, range(concurrency))

    assert len(users) == concurrency
    assert len(set(user.pk for user in users)) == 1


def test_provision_user_attributes(settings, django_user_model, idp, saml_attributes, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_ATTRIBUTE_MAPPING = {
        'email': u'{attributes[email][0]}',
        'first_name': u'{attributes[first_name][0]}',
        'last_name': u'{attributes[last_name][0]}',
    }
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes)
    assert user.username == 'x' * 30
    assert user.first_name == 'Foo'
    assert user.last_name == 'Bar'
    assert user.email == 'test@example.net'
    assert user.is_superuser is False
    assert user.is_staff is False
    assert len(caplog.records) == 4
    assert 'created new user' in caplog.text
    assert 'set field first_name' in caplog.text
    assert 'set field last_name' in caplog.text
    assert 'set field email' in caplog.text


def test_provision_user_groups(settings, django_user_model, idp, saml_attributes, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_GROUP_ATTRIBUTE = 'group'
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes)
    assert user.groups.count() == 3
    assert set(user.groups.values_list('name', flat=True)) == set(saml_attributes['group'])
    assert len(caplog.records) == 4
    assert 'created new user' in caplog.text
    assert 'adding group GroupA' in caplog.text
    assert 'adding group GroupB' in caplog.text
    assert 'adding group GroupC' in caplog.text
    saml_attributes2 = saml_attributes.copy()
    saml_attributes2['group'] = ['GroupB', 'GroupC']
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes2)
    assert user.groups.count() == 2
    assert set(user.groups.values_list('name', flat=True)) == set(saml_attributes2['group'])
    assert len(caplog.records) == 6
    assert 'removing group GroupA' in caplog.records[-1].message


def test_provision_is_superuser(settings, django_user_model, idp, saml_attributes, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_SUPERUSER_MAPPING = {
        'is_superuser': 'true',
    }
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes)
    assert user.is_superuser is True
    assert user.is_staff is True
    assert 'flag is_staff and is_superuser added' in caplog.text
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes)
    assert user.is_superuser is True
    assert user.is_staff is True
    assert not 'flag is_staff and is_superuser removed' in caplog.text


def test_provision_absent_attribute(settings, django_user_model, idp, saml_attributes, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_ATTRIBUTE_MAPPING = {
        'email': '{attributes[email][0]}',
        'first_name': '{attributes[first_name][0]}',
        'last_name': '{attributes[last_name][0]}',
    }
    local_saml_attributes = saml_attributes.copy()
    del local_saml_attributes['email']
    user = SAMLBackend().authenticate(saml_attributes=local_saml_attributes)
    assert not user.email
    assert len(caplog.records) == 4
    assert 'created new user' in caplog.text
    assert re.search(r'invalid reference.*email', caplog.text)
    assert 'set field first_name' in caplog.text
    assert 'set field last_name' in caplog.text


def test_provision_long_attribute(settings, django_user_model, idp, saml_attributes, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_ATTRIBUTE_MAPPING = {
        'email': '{attributes[email][0]}',
        'first_name': '{attributes[first_name][0]}',
        'last_name': '{attributes[last_name][0]}',
    }
    local_saml_attributes = saml_attributes.copy()
    local_saml_attributes['first_name'] = [('y' * 32)]
    user = SAMLBackend().authenticate(saml_attributes=local_saml_attributes)
    assert user.first_name == 'y' * 30
    assert len(caplog.records) == 4
    assert 'created new user' in caplog.text
    assert 'set field first_name' in caplog.text
    assert 'to value %r ' % (u'y' * 30) in caplog.text
    assert 'set field last_name' in caplog.text
    assert 'set field email' in caplog.text


def test_lookup_user_transient_with_email(private_settings, idp, saml_attributes):
    private_settings.MELLON_TRANSIENT_FEDERATION_ATTRIBUTE = 'email'
    adapter = DefaultAdapter()
    saml_attributes['name_id_format'] = lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT
    assert User.objects.count() == 0
    user = adapter.lookup_user(idp, saml_attributes)
    assert user is not None
    assert user.saml_identifiers.count() == 1
    assert user.saml_identifiers.first().name_id == saml_attributes['email'][0]

    user2 = adapter.lookup_user(idp, saml_attributes)
    assert user.id == user2.id

    User.objects.all().delete()
    assert User.objects.count() == 0

    private_settings.MELLON_PROVISION = False
    user = adapter.lookup_user(idp, saml_attributes)
    assert user is None
    assert User.objects.count() == 0


def test_lookup_user_by_attributes_bad_setting1(settings, idp, saml_attributes, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    settings.MELLON_LOOKUP_BY_ATTRIBUTES = 'coin'
    assert adapter.lookup_user(idp, saml_attributes) is None
    assert caplog.records[-1].message.endswith('it must be a list')


def test_lookup_user_by_attributes_bad_setting2(settings, idp, saml_attributes, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    settings.MELLON_LOOKUP_BY_ATTRIBUTES = ['coin']
    assert adapter.lookup_user(idp, saml_attributes) is None
    assert caplog.records[-1].message.endswith('it must be a list of dicts')


def test_lookup_user_by_attributes_bad_setting3(settings, idp, saml_attributes, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    settings.MELLON_LOOKUP_BY_ATTRIBUTES = [{}]
    assert adapter.lookup_user(idp, saml_attributes) is None
    assert caplog.records[-1].message.endswith('user_field is missing')


def test_lookup_user_by_attributes_bad_setting4(settings, idp, saml_attributes, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    settings.MELLON_LOOKUP_BY_ATTRIBUTES = [{'user_field': 'username'}]
    assert adapter.lookup_user(idp, saml_attributes) is None
    assert caplog.records[-1].message.endswith('saml_attribute is missing')


def test_lookup_user_by_attributes_not_found(settings, idp, saml_attributes, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    caplog.set_level('DEBUG')
    settings.MELLON_LOOKUP_BY_ATTRIBUTES = [{'user_field': 'username', 'saml_attribute': 'saml_at1'}]
    saml_attributes['saml_at1'] = ['john.doe']
    assert adapter.lookup_user(idp, saml_attributes) is None
    assert caplog.records[-2].message.endswith(': not found')


def test_lookup_user_by_attributes_too_many1(settings, idp, saml_attributes, john, jane, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    settings.MELLON_LOOKUP_BY_ATTRIBUTES = [{'user_field': 'email', 'saml_attribute': 'saml_at1'}]
    saml_attributes['saml_at1'] = ['john.doe@example.com']
    assert adapter.lookup_user(idp, saml_attributes) is None
    assert 'too many users found(2)' in caplog.records[-1].message


def test_lookup_user_by_attributes_too_manyi2(settings, idp, saml_attributes, john, jane, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    saml_attributes['saml_at1'] = ['john.doe']
    saml_attributes['saml_at2'] = ['jane.doe']

    settings.MELLON_LOOKUP_BY_ATTRIBUTES = [
        {'user_field': 'username', 'saml_attribute': 'saml_at1'},
        {'user_field': 'username', 'saml_attribute': 'saml_at2'},
    ]
    assert adapter.lookup_user(idp, saml_attributes) is None
    assert 'too many users found(2)' in caplog.records[-1].message


def test_lookup_user_by_attributes_found(settings, idp, saml_attributes, john, jane, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    saml_attributes['saml_at1'] = ['john.doe']
    settings.MELLON_LOOKUP_BY_ATTRIBUTES = [
        {'user_field': 'username', 'saml_attribute': 'saml_at1'},
    ]
    assert adapter.lookup_user(idp, saml_attributes) == john


def test_lookup_user_by_attributes_ignore_case(settings, idp, saml_attributes, john, jane, caplog):
    settings.MELLON_PROVISION = False

    adapter = DefaultAdapter()
    saml_attributes['saml_at1'] = ['Jane.Doe']
    settings.MELLON_LOOKUP_BY_ATTRIBUTES = [
        {'user_field': 'username', 'saml_attribute': 'saml_at1'},
    ]
    assert adapter.lookup_user(idp, saml_attributes) is None

    settings.MELLON_LOOKUP_BY_ATTRIBUTES = [
        {'user_field': 'username', 'saml_attribute': 'saml_at1', 'ignore-case': True},
    ]
    assert adapter.lookup_user(idp, saml_attributes) == jane
