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

from lxml import etree as ET


def assert_xml_constraints(content, constraint, namespaces={}):
    d = ET.fromstring(content)
    def check(constraint, prefix=''):
        path, count = constraint[:2]
        path = prefix + path
        if not count is None:
            l = d.xpath(path, namespaces=namespaces)
            assert len(l) == count, 'len(xpath(%s)) is not %s but %s' % (path, count, len(l))
        if len(constraint) > 2:
            for constraint in constraint[2:]:
                check(constraint, prefix=path)
    check(constraint)
