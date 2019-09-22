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

from django.contrib.auth.backends import ModelBackend

from . import utils


class SAMLBackend(ModelBackend):
    def authenticate(self, request=None, **credentials):
        saml_attributes = credentials.get('saml_attributes') or {}
        # without an issuer we can do nothing
        if 'issuer' not in saml_attributes:
            return
        idp = utils.get_idp(saml_attributes['issuer'])
        adapters = utils.get_adapters(idp)
        for adapter in adapters:
            if not hasattr(adapter, 'authorize'):
                continue
            if not adapter.authorize(idp, saml_attributes):
                return
        for adapter in adapters:
            if not hasattr(adapter, 'lookup_user'):
                continue
            user = adapter.lookup_user(idp, saml_attributes)
            if user:
                break
        else:  # no user found
            return
        for adapter in adapters:
            if not hasattr(adapter, 'provision'):
                continue
            adapter.provision(user, idp, saml_attributes)
        return user
