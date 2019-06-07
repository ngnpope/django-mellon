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

import logging
import pytest
import django_webtest


@pytest.fixture
def app(request):
    wtm = django_webtest.WebTestMixin()
    wtm._patch_settings()
    request.addfinalizer(wtm._unpatch_settings)
    return django_webtest.DjangoTestApp()


@pytest.fixture
def concurrency(settings):
    '''Select a level of concurrency based on the db, sqlite3 is less robust
       thant postgres due to its transaction lock timeout of 5 seconds.
    '''
    if 'sqlite' in settings.DATABASES['default']['ENGINE']:
        return 20
    else:
        return 100


@pytest.fixture
def private_settings(request):
    import django.conf
    from django.conf import UserSettingsHolder
    old = django.conf.settings._wrapped
    django.conf.settings._wrapped = UserSettingsHolder(old)

    def finalizer():
        django.conf.settings._wrapped = old
    request.addfinalizer(finalizer)
    return django.conf.settings


@pytest.fixture
def caplog(caplog):
    import py.io
    caplog.set_level(logging.INFO)
    caplog.handler.stream = py.io.TextIO()
    caplog.handler.records = []
    return caplog
