from django.contrib.auth.backends import ModelBackend

from . import utils


class SAMLBackend(ModelBackend):
    def authenticate(self, request, saml_attributes):
        # without an issuer we can do nothing
        if not 'issuer' in saml_attributes:
            return
        idp = utils.get_idp(entity_id=saml_attributes['issuer'])
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
