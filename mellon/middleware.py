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

from django.utils.http import urlencode
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse

from . import app_settings, utils

PASSIVE_TRIED_COOKIE = 'MELLON_PASSIVE_TRIED'


class PassiveAuthenticationMiddleware(object):
    def process_response(self, request, response):
        # When unlogged remove the PASSIVE_TRIED cookie
        if app_settings.OPENED_SESSION_COOKIE_NAME \
           and PASSIVE_TRIED_COOKIE in request.COOKIES \
           and app_settings.OPENED_SESSION_COOKIE_NAME not in request.COOKIES:
            response.delete_cookie(PASSIVE_TRIED_COOKIE)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Skip AJAX requests
        if request.is_ajax():
            return
        # Skip views asking to be skiped
        if getattr(view_func, 'mellon_no_passive', False):
            return
        # Skip mellon views
        if request.resolver_match.url_name and request.resolver_match.url_name.startswith('mellon_'):
            return
        if not any(utils.get_idps()):
            return
        if not app_settings.OPENED_SESSION_COOKIE_NAME:
            return
        if hasattr(request, 'user') and request.user.is_authenticated():
            return
        if PASSIVE_TRIED_COOKIE in request.COOKIES:
            return
        if app_settings.OPENED_SESSION_COOKIE_NAME in request.COOKIES:
            # get the common domain or guess
            common_domain = app_settings.OPENED_SESSION_COOKIE_DOMAIN
            if not common_domain:
                host = request.get_host()
                # accept automatic common domain selection if domain has at least three components
                # and is not an IP address
                if not host.count('.') > 1 or host.replace('.', '').isdigit():
                    return
                common_domain = request.get_host().split('.', 1)[1]
            params = {
                'next': request.build_absolute_uri(),
                'passive': '',
            }
            url = reverse('mellon_login') + '?%s' % urlencode(params)
            response = HttpResponseRedirect(url)
            # prevent loops
            response.set_cookie(PASSIVE_TRIED_COOKIE, value='1', max_age=None)
            return response
