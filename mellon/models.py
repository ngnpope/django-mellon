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

from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.conf import settings


class UserSAMLIdentifier(models.Model):
    user = models.ForeignKey(
        verbose_name=_('user'),
        to=settings.AUTH_USER_MODEL,
        related_name='saml_identifiers',
        on_delete=models.CASCADE)
    issuer = models.TextField(
        verbose_name=_('Issuer'))
    name_id = models.TextField(
        verbose_name=_('SAML identifier'))
    created = models.DateTimeField(
        verbose_name=_('created'),
        auto_now_add=True)

    class Meta:
        verbose_name = _('user SAML identifier')
        verbose_name_plural = _('users SAML identifiers')
        unique_together = (('issuer', 'name_id'),)
