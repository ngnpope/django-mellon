from __future__ import unicode_literals

from django.conf.urls import url
import django

from . import views


urlpatterns = [
    url('login/$', views.login,
        name='mellon_login'),
    url('logout/$', views.logout,
        name='mellon_logout'),
    url('metadata/$', views.metadata,
        name='mellon_metadata')
]
if django.VERSION < (1, 8):
    from django.conf.urls import patterns
    urlpatterns = patterns('', *urlpatterns)
