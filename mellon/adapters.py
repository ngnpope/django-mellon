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

from xml.etree import ElementTree as ET
import hashlib

import logging
import os
import threading
import time
import uuid

import lasso
import requests
import requests.exceptions
from atomicwrites import atomic_write

from django.core.exceptions import PermissionDenied, FieldDoesNotExist
from django.core.files.storage import default_storage
from django.contrib import auth
from django.contrib.auth.models import Group
from django.utils import six
from django.utils.encoding import force_text
from django.utils.six.moves.urllib.parse import urlparse

from . import utils, app_settings, models

User = auth.get_user_model()

logger = logging.getLogger(__name__)


class UserCreationError(Exception):
    pass


def display_truncated_list(l, max_length=10):
    s = '[' + ', '.join(map(six.text_type, l))
    if len(l) > max_length:
        s += '..truncated more than %d items (%d)]' % (max_length, len(l))
    else:
        s += ']'
    return s


class DefaultAdapter(object):
    def get_idp(self, entity_id):
        '''Find the first IdP definition matching entity_id'''
        for idp in self.get_idps():
            if entity_id == idp['ENTITY_ID']:
                return idp

    def get_identity_providers_setting(self):
        return app_settings.IDENTITY_PROVIDERS

    def get_users_queryset(self, idp, saml_attributes):
        return User.objects.all()

    def get_idps(self):
        for i, idp in enumerate(self.get_identity_providers_setting()):
            if self.load_idp(idp, i):
                yield idp

    def load_metadata_path(self, idp, i):
        path = idp['METADATA_PATH']
        if not os.path.exists(path):
            logger.warning('metadata path %s does not exist', path)
            return
        last_update = idp.get('METADATA_PATH_LAST_UPDATE', 0)
        try:
            mtime = os.stat(path).st_mtime
        except OSError as e:
            logger.warning('metadata path %s : stat() call failed, %s', path, e)
            return
        if last_update == 0 or mtime >= last_update:
            idp['METADATA_PATH_LAST_UPDATE'] = time.time()
            try:
                with open(path) as fd:
                    metadata = fd.read()
            except OSError as e:
                logger.warning('metadata path %s : open()/read() call failed, %s', path, e)
                return
            entity_id = self.load_entity_id(metadata, i)
            if not entity_id:
                logger.error('invalid metadata file retrieved from %s', path)
                return
            if 'ENTITY_ID' in idp and idp['ENTITY_ID'] != entity_id:
                logger.error('metadata path %s : entityID changed %r != %r', path, entity_id, idp['ENTITY_ID'])
                del idp['ENTITY_ID']
            idp['METADATA'] = metadata

    def load_metadata_url(self, idp, i):
        url = idp['METADATA_URL']
        metadata_cache_time = utils.get_setting(idp, 'METADATA_CACHE_TIME')
        timeout = utils.get_setting(idp, 'METADATA_HTTP_TIMEOUT')

        warning = logger.warning
        if 'METADATA' not in idp:
            # if we have no metadata in cache, we must emit errors
            warning = logger.error

        try:
            hostname = urlparse(url).hostname
        except (ValueError, TypeError) as e:
            warning('invalid METADATA_URL %r: %s', url, e)
            return
        if not hostname:
            warning('no hostname in METADATA_URL %r: %s', url)
            return

        last_update = idp.get('METADATA_URL_LAST_UPDATE', 0)
        now = time.time()

        try:
            url_fingerprint = hashlib.md5(url.encode('ascii')).hexdigest()
            file_cache_key = '%s_%s.xml' % (hostname, url_fingerprint)
        except (UnicodeError, TypeError, ValueError):
            warning('unable to compute file_cache_key')
            return

        cache_directory = default_storage.path('mellon_metadata_cache')
        file_cache_path = os.path.join(cache_directory, file_cache_key)

        if metadata_cache_time:
            # METADATA_CACHE_TIME == 0 disable the file cache
            if not os.path.exists(cache_directory):
                os.makedirs(cache_directory)

            if os.path.exists(file_cache_path) and 'METADATA' not in idp:
                try:
                    with open(file_cache_path) as fd:
                        idp['METADATA'] = fd.read()
                    # use file cache mtime as last_update time, prevent too many loading from different workers
                    last_update = max(last_update, os.stat(file_cache_path).st_mtime)
                except OSError:
                    warning('metadata url %s : error when loading the file cache %s', url, file_cache_path)

        # fresh cache, skip loading
        if last_update and 'METADATA' in idp and (now - last_update) < metadata_cache_time:
            return

        def __http_get():
            try:
                verify_ssl_certificate = utils.get_setting(
                    idp, 'VERIFY_SSL_CERTIFICATE')
                try:
                    response = requests.get(url, verify=verify_ssl_certificate, timeout=timeout)
                    response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    warning('metadata url %s : HTTP request failed %s', url, e)
                    return

                entity_id = self.load_entity_id(response.text, i)
                if not entity_id:
                    warning('invalid metadata file retrieved from %s', url)
                    return

                if 'ENTITY_ID' in idp and idp['ENTITY_ID'] != entity_id:
                    # entityID change is always en error
                    logger.error('metadata url %s : entityID changed %r != %r', url, entity_id, idp['ENTITY_ID'])
                    del idp['ENTITY_ID']

                idp['METADATA'] = response.text
                idp['METADATA_URL_LAST_UPDATE'] = now
                if metadata_cache_time:
                    try:
                        with atomic_write(file_cache_path, mode='wb', overwrite=True) as fd:
                            fd.write(response.text.encode('utf-8'))
                    except OSError as e:
                        logger.error('metadata url %s : could not write file cache %s, %s', url, file_cache_path, e)
                idp['METADATA_PATH'] = file_cache_path
                # prevent reloading of the file cache immediately
                idp['METADATA_PATH_LAST_UPDATE'] = time.time() + 1
                logger.debug('metadata url %s : update throught HTTP', url)
            finally:
                # release thread object
                idp.pop('METADATA_URL_UPDATE_THREAD', None)
                # emit an error if cache is too old
                if metadata_cache_time:
                    stale_timeout = 24 * metadata_cache_time
                    if last_update and (now - idp['METADATA_URL_LAST_UPDATE']) > stale_timeout:
                        logger.error('metadata url %s: not updated since %.1f hours',
                                     url, stale_timeout / 3600.0)

        # we have cache, update in background
        if last_update and 'METADATA' in idp:
            t = threading.Thread(target=__http_get)
            t.start()
            # store thread in idp for tests
            idp['METADATA_URL_UPDATE_THREAD'] = t
            # suspend updates for HTTP timeout + 5 seconds
            idp['METADATA_URL_LAST_UPDATE'] = last_update + timeout + 5
        else:
            # synchronous update
            __http_get()

    def load_metadata(self, idp, i):
        # legacy support
        if 'METADATA' in idp and idp['METADATA'].startswith('/'):
            idp['METADATA_PATH'] = idp['METADATA']
            del idp['METADATA']

        if 'METADATA_PATH' in idp:
            self.load_metadata_path(idp, i)

        if 'METADATA_URL' in idp:
            self.load_metadata_url(idp, i)

        if 'METADATA' in idp:
            if 'ENTITY_ID' not in idp:
                entity_id = self.load_entity_id(idp['METADATA'], i)
                if entity_id:
                    idp['ENTITY_ID'] = entity_id

        if 'ENTITY_ID' in idp:
            return idp['METADATA']

    def load_entity_id(self, metadata, i):
        try:
            doc = ET.fromstring(metadata)
        except (TypeError, ET.ParseError):
            logger.error('METADATA of %d-th idp is invalid', i)
            return None
        if doc.tag != '{%s}EntityDescriptor' % lasso.SAML2_METADATA_HREF:
            logger.error('METADATA of %d-th idp has no EntityDescriptor root tag', i)
            return None

        if 'entityID' not in doc.attrib:
            logger.error(
                'METADATA of %d-th idp has no entityID attribute on its root tag', i)
            return None
        return doc.attrib['entityID']

    def load_idp(self, idp, i):
        self.load_metadata(idp, i)
        return 'ENTITY_ID' in idp

    def authorize(self, idp, saml_attributes):
        if not idp:
            return False
        required_classref = utils.get_setting(idp, 'AUTHN_CLASSREF')
        if required_classref:
            given_classref = saml_attributes['authn_context_class_ref']
            if given_classref is None or \
                    given_classref not in required_classref:
                raise PermissionDenied
        return True

    def format_username(self, idp, saml_attributes):
        realm = utils.get_setting(idp, 'REALM')
        username_template = utils.get_setting(idp, 'USERNAME_TEMPLATE')
        try:
            username = force_text(username_template).format(
                realm=realm, attributes=saml_attributes, idp=idp)[:30]
        except ValueError:
            logger.error('invalid username template %r', username_template)
        except (AttributeError, KeyError, IndexError) as e:
            logger.error(
                'invalid reference in username template %r: %s', username_template, e)
        except Exception:
            logger.exception('unknown error when formatting username')
        else:
            return username

    def create_user(self, user_class):
        return user_class.objects.create(username=uuid.uuid4().hex[:30])

    def finish_create_user(self, idp, saml_attributes, user):
        username = self.format_username(idp, saml_attributes)
        if not username:
            logger.warning('could not build a username, login refused')
            raise UserCreationError
        user.username = username
        user.save()

    def lookup_user(self, idp, saml_attributes):
        transient_federation_attribute = utils.get_setting(idp, 'TRANSIENT_FEDERATION_ATTRIBUTE')
        if saml_attributes['name_id_format'] == lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT:
            if (transient_federation_attribute
                    and saml_attributes.get(transient_federation_attribute)):
                name_id = saml_attributes[transient_federation_attribute]
                if not isinstance(name_id, six.string_types):
                    if len(name_id) == 1:
                        name_id = name_id[0]
                    else:
                        logger.warning('more than one value for attribute %r, cannot federate',
                                       transient_federation_attribute)
                        return None
            else:
                return None
        else:
            name_id = saml_attributes['name_id_content']
        issuer = saml_attributes['issuer']
        try:
            user = self.get_users_queryset(idp, saml_attributes).get(
                saml_identifiers__name_id=name_id,
                saml_identifiers__issuer=issuer)
            logger.info('looked up user %s with name_id %s from issuer %s', user, name_id, issuer)
            return user
        except User.DoesNotExist:
            pass

        user = None
        lookup_by_attributes = utils.get_setting(idp, 'LOOKUP_BY_ATTRIBUTES')
        if lookup_by_attributes:
            user = self._lookup_by_attributes(idp, saml_attributes, lookup_by_attributes)

        created = False
        if not user:
            if not utils.get_setting(idp, 'PROVISION'):
                logger.debug('provisionning disabled, login refused')
                return None
            created = True
            user = self.create_user(User)

        nameid_user = self._link_user(idp, saml_attributes, issuer, name_id, user)
        if user != nameid_user:
            logger.info('looked up user %s with name_id %s from issuer %s', nameid_user, name_id, issuer)
            if created:
                user.delete()
            return nameid_user

        if created:
            try:
                self.finish_create_user(idp, saml_attributes, nameid_user)
            except UserCreationError:
                user.delete()
                return None
            logger.info('created new user %s with name_id %s from issuer %s', nameid_user, name_id, issuer)
        return nameid_user

    def _lookup_by_attributes(self, idp, saml_attributes, lookup_by_attributes):
        if not isinstance(lookup_by_attributes, list):
            logger.error('invalid LOOKUP_BY_ATTRIBUTES configuration %r: it must be a list', lookup_by_attributes)
            return None

        users = set()
        for line in lookup_by_attributes:
            if not isinstance(line, dict):
                logger.error('invalid LOOKUP_BY_ATTRIBUTES configuration %r: it must be a list of dicts', line)
                continue
            user_field = line.get('user_field')
            if not hasattr(user_field, 'isalpha'):
                logger.error('invalid LOOKUP_BY_ATTRIBUTES configuration %r: user_field is missing', line)
                continue
            try:
                User._meta.get_field(user_field)
            except FieldDoesNotExist:
                logger.error('invalid LOOKUP_BY_ATTRIBUTES configuration %r, user field %s does not exist',
                             line, user_field)
                continue
            saml_attribute = line.get('saml_attribute')
            if not hasattr(saml_attribute, 'isalpha'):
                logger.error('invalid LOOKUP_BY_ATTRIBUTES configuration %r: saml_attribute is missing', line)
                continue
            values = saml_attributes.get(saml_attribute)
            if not values:
                logger.error('looking for user by saml attribute %r and user field %r, skipping because empty',
                             saml_attribute, user_field)
                continue
            ignore_case = line.get('ignore-case', False)
            for value in values:
                key = user_field
                if ignore_case:
                    key += '__iexact'
                users_found = self.get_users_queryset(idp, saml_attributes).filter(
                    saml_identifiers__isnull=True, **{key: value})
                if not users_found:
                    logger.debug('looking for users by attribute %r and user field %r with value %r: not found',
                                 saml_attribute, user_field, value)
                    continue
                logger.info('looking for user by attribute %r and user field %r with value %r: found %s',
                            saml_attribute, user_field, value, display_truncated_list(users_found))
                users.update(users_found)
        if len(users) == 1:
            user = list(users)[0]
            logger.info('looking for user by attributes %r: found user %s', lookup_by_attributes, user)
            return user
        elif len(users) > 1:
            logger.warning('looking for user by attributes %r: too many users found(%d), failing',
                           lookup_by_attributes, len(users))
        return None

    def _link_user(self, idp, saml_attributes, issuer, name_id, user):
        saml_id, created = models.UserSAMLIdentifier.objects.get_or_create(
            name_id=name_id, issuer=issuer, defaults={'user': user})
        if created:
            return user
        else:
            return saml_id.user

    def provision(self, user, idp, saml_attributes):
        self.provision_attribute(user, idp, saml_attributes)
        self.provision_superuser(user, idp, saml_attributes)
        self.provision_groups(user, idp, saml_attributes)

    def provision_attribute(self, user, idp, saml_attributes):
        realm = utils.get_setting(idp, 'REALM')
        attribute_mapping = utils.get_setting(idp, 'ATTRIBUTE_MAPPING')
        attribute_set = False
        for field, tpl in attribute_mapping.items():
            try:
                value = force_text(tpl).format(realm=realm, attributes=saml_attributes, idp=idp)
            except ValueError:
                logger.warning('invalid attribute mapping template %r', tpl)
            except (AttributeError, KeyError, IndexError, ValueError) as e:
                logger.warning(
                    'invalid reference in attribute mapping template %r: %s', tpl, e)
            else:
                model_field = user._meta.get_field(field)
                if hasattr(model_field, 'max_length'):
                    value = value[:model_field.max_length]
                if getattr(user, field) != value:
                    old_value = getattr(user, field)
                    setattr(user, field, value)
                    attribute_set = True
                    logger.info('set field %s of user %s to value %r (old value %r)', field, user, value, old_value)
        if attribute_set:
            user.save()

    def provision_superuser(self, user, idp, saml_attributes):
        superuser_mapping = utils.get_setting(idp, 'SUPERUSER_MAPPING')
        if not superuser_mapping:
            return
        attribute_set = False
        for key, values in superuser_mapping.items():
            if key in saml_attributes:
                if not isinstance(values, (tuple, list)):
                    values = [values]
                values = set(values)
                attribute_values = saml_attributes[key]
                if not isinstance(attribute_values, (tuple, list)):
                    attribute_values = [attribute_values]
                attribute_values = set(attribute_values)
                if attribute_values & values:
                    if not (user.is_staff and user.is_superuser):
                        user.is_staff = True
                        user.is_superuser = True
                        attribute_set = True
                        logger.info('flag is_staff and is_superuser added to user %s', user)
                    break
        else:
            if user.is_superuser or user.is_staff:
                user.is_staff = False
                user.is_superuser = False
                logger.info('flag is_staff and is_superuser removed from user %s', user)
                attribute_set = True
        if attribute_set:
            user.save()

    def provision_groups(self, user, idp, saml_attributes):
        group_attribute = utils.get_setting(idp, 'GROUP_ATTRIBUTE')
        create_group = utils.get_setting(idp, 'CREATE_GROUP')
        if group_attribute in saml_attributes:
            values = saml_attributes[group_attribute]
            if not isinstance(values, (list, tuple)):
                values = [values]
            groups = []
            for value in set(values):
                if create_group:
                    group, created = Group.objects.get_or_create(name=value)
                else:
                    try:
                        group = Group.objects.get(name=value)
                    except Group.DoesNotExist:
                        continue
                groups.append(group)
            for group in Group.objects.filter(pk__in=[g.pk for g in groups]).exclude(user=user):
                logger.info(
                    'adding group %s (%s) to user %s (%s)', group, group.pk, user, user.pk)
                User.groups.through.objects.get_or_create(group=group, user=user)
            qs = User.groups.through.objects.exclude(
                group__pk__in=[g.pk for g in groups]).filter(user=user)
            for rel in qs:
                logger.info('removing group %s (%s) from user %s (%s)', rel.group, rel.group.pk, rel.user, rel.user.pk)
            qs.delete()
