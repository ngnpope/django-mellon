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

from httmock import all_requests, response


@all_requests
def error_500(url, request):
    return response(500, reason='Internal Server Error', request=request)


@all_requests
def html_response(url, request):
    return response(200, '<html></html>', headers={'content-type': 'text/html'}, request=request)


@all_requests
def metadata_response(url, request):
    return response(200, content=open('tests/metadata.xml').read())


def reset_caplog(cap):
    cap.handler.stream.truncate(0)
    cap.handler.records = []
