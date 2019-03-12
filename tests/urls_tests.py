from django.conf.urls import include, url
from django.http import HttpResponse


def homepage(request):
    return HttpResponse('ok')

urlpatterns = [
    url('^', include('mellon.urls')),
    url('^$', homepage, name='homepage'),
]
