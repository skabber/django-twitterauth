from django.conf import settings
from django.utils.translation import ugettext, ugettext_lazy as _
from django.http import HttpResponseRedirect
from oauth.oauth import OAuthConsumer, OAuthRequest, OAuthSignatureMethod_HMAC_SHA1, OAuthToken
import urllib
import simplejson

TWITTER_REQUEST_TOKEN_URL = 'http://twitter.com/oauth/request_token'
TWITTER_REQUEST_ACCESS_TOKEN_URL = 'http://twitter.com/oauth/access_token'
TWITTER_AUTHORIZE_URL = 'http://twitter.com/oauth/authorize'
TWITTER_VERIFY_CREDENTIALS = 'http://twitter.com/account/verify_credentials.json'

def start_auth(request, fail_redirect='/account/other_services/'):
    consumer = OAuthConsumer(settings.TWITTER_CONSUMER_KEY, settings.TWITTER_CONSUMER_SECRET)
    # Request the OAuth Token
    req = OAuthRequest().from_consumer_and_token(consumer, http_url=TWITTER_REQUEST_TOKEN_URL,
        parameters={}, http_method="POST")
    req.sign_request(OAuthSignatureMethod_HMAC_SHA1(), consumer, None)
    try:
        res = urllib.urlopen(TWITTER_REQUEST_TOKEN_URL, req.to_postdata())
        requestToken = OAuthToken.from_string(res.read())
        # Authorise the OAuth Token
        oauth_request = OAuthRequest().from_consumer_and_token(consumer, http_url=TWITTER_AUTHORIZE_URL, 
            parameters={}, http_method="GET", token=requestToken)
        oauth_request.sign_request(OAuthSignatureMethod_HMAC_SHA1(), consumer, requestToken)
        return HttpResponseRedirect(oauth_request.to_url())
    except IOError:
        request.user.message_set.create(
            message=ugettext(u"Twitter authorization failed.")
        )
        return HttpResponseRedirect(fail_redirect)

def get_credentials_from_request(request):
    token = OAuthToken(request.GET.get("oauth_token"), "")
    consumer = OAuthConsumer(settings.TWITTER_CONSUMER_KEY, settings.TWITTER_CONSUMER_SECRET)
    oauth_request = OAuthRequest().from_consumer_and_token(consumer, http_url=TWITTER_REQUEST_ACCESS_TOKEN_URL,
        parameters={}, http_method="GET", token=token)
    oauth_request.sign_request(OAuthSignatureMethod_HMAC_SHA1(), consumer, token)
    try:
        res = urllib.urlopen(TWITTER_REQUEST_ACCESS_TOKEN_URL, oauth_request.to_postdata())
        accessToken = OAuthToken.from_string(res.read())
        # verify the access token
        verify_request = OAuthRequest().from_consumer_and_token(consumer, http_url=TWITTER_VERIFY_CREDENTIALS,
            http_method="GET", token=accessToken)
        verify_request.sign_request(OAuthSignatureMethod_HMAC_SHA1(), consumer, accessToken)
        res = urllib.urlopen(verify_request.to_url())
        json_response = simplejson.loads(res.read())
        if json_response['screen_name']:
            return accessToken
            request.user.message_set.create(
                message=ugettext(u"Twitter authorization failed.")
            )
    except IOError:
        request.user.message_set.create(
            message=ugettext(u"Twitter authorization failed.")
        )

# You will most likely want to implent this view yourself and do something with the 
# credentials.  Like save them to the database.
def twitter_oauth_reply(request):
    accessToken = get_credentials_from_request(request)
    request.session['twitter_oauth_key'] = accessToken.key
    request.session['twitter_oauth_secret'] = accessToken.secret
    return HttpResponseRedirect(reverse("acct_other_services"))
