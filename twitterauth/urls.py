from django.conf.urls.defaults import *

urlpatterns = patterns('',
    url(r'^twitter_oauth_start/$', 'twitterauth.views.start_auth', name='twitterauth_start'),
    url(r'^twitter_oauth_reply/$', 'twitterauth.views.twitter_oauth_reply', name="twitter_oauth_reply"),
)
