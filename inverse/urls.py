from django.contrib.auth.decorators import login_required
from django.conf.urls import patterns, include, url
from django.core.urlresolvers import reverse_lazy
from django.views.generic import RedirectView

from django.contrib import admin
admin.autodiscover()
from pki import views

urlpatterns = patterns('',
    # Examples:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', 'pki.views.logon'),
    url(r'^pki', include('pki.urls')),
    url(r'^logon/$',  'pki.views.logon'),
    url(r'^logout/$', 'pki.views.disconnect'),
    url(r'^user/password/(?P<pk>\d+)/$',       'pki.views.update_user_password'),
    url(r'^users/(?P<pk>\d+)/del/$',           login_required(views.delete_user.as_view(),login_url='/logon/'), name='user_delete'),
    url(r'^users/(?P<pk>\d+)/$',               login_required(views.update_user.as_view(),login_url='/logon/'), name='user_update'),
    url(r'^users/new/$',                       login_required(views.register,login_url='/logon/'), name='user_add'),
    url(r'^users/$',                           login_required(views.list_user.as_view(),login_url='/logon/'), name='user_list'),
)
