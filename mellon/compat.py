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

import django
if django.VERSION < (1, 11, 0):
    from django.core.urlresolvers import reverse
    MiddlewareClass = object

    is_authenticated = lambda user: user.is_authenticated()
else:
    from django.urls import reverse
    from django.utils.deprecation import MiddlewareMixin
    MiddlewareClass = MiddlewareMixin

    is_authenticated = lambda user: user.is_authenticated
