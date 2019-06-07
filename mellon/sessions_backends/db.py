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

from django.contrib.sessions.backends.db import SessionStore

from mellon import utils


class SessionStore(SessionStore):
    def get_session_not_on_or_after(self):
        session_not_on_or_after = self.get('mellon_session', {}).get('session_not_on_or_after')
        if session_not_on_or_after:
            return utils.iso8601_to_datetime(session_not_on_or_after)
        return None

    def get_expiry_age(self, **kwargs):
        session_not_on_or_after = self.get_session_not_on_or_after()
        if session_not_on_or_after and 'expiry' not in kwargs:
            kwargs['expiry'] = session_not_on_or_after
        return super(SessionStore, self).get_expiry_age(**kwargs)

    def get_expiry_date(self, **kwargs):
        session_not_on_or_after = self.get_session_not_on_or_after()
        if session_not_on_or_after and 'expiry' not in kwargs:
            kwargs['expiry'] = session_not_on_or_after
        return super(SessionStore, self).get_expiry_date(**kwargs)
