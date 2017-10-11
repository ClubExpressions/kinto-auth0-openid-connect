import requests
from kinto.core import Service, logger
from pyramid.httpexceptions import HTTPFound
from urllib import parse

def get_config_value(request, key):
    value = request.registry.settings["auth0." + key]
#    logger.debug("auth0." + key + ": " + value)
    return value

auth0_authorization = Service(name="auth0_authorization",
                 path='/auth/auth0',
                 description="Auth0 Authorization")

@auth0_authorization.get()
def get_auth0_authorization(request):
    clientid = get_config_value(request, "client_id")
    scope = get_config_value(request, "scope")
    redirecturi = get_config_value(request, "redirect_uri")
    authuri = get_config_value(request, "auth_uri")
    audience = get_config_value(request, "audience")

    query_string = ("response_type=code"
                    "&client_id={client_id}"
                    "&scope={scope}"
                    "&redirect_uri={redirect_uri}"
                    "&audience={audience}"
                   ).format(
                     client_id=clientid,
                     scope=parse.quote_plus(scope),
                     redirect_uri=parse.quote_plus(redirecturi),
                     audience=parse.quote_plus(audience)
                    )
    return HTTPFound(location=authuri + "/authorize?" + query_string)


access_token = Service(name="auth0_ access_token",
                 path='/auth/auth0/token',
                 description="Auth0 Access Token back URL")

@access_token.get()
def get_access_token(request):
    code = request.GET['code']

    clientid = get_config_value(request, "client_id")
    clientsecret = get_config_value(request, "client_secret")
    redirecturi = get_config_value(request, "redirect_uri")
    sparedirecturi = get_config_value(request, "spa_redirect_uri")
    authuri = get_config_value(request, "auth_uri")

    try:
        payload = {
            'grant_type': 'authorization_code',
            'client_id': clientid,
            'client_secret': clientsecret,
            'code': code,
            'redirect_uri': redirecturi
        }
        headers = {"Accept": "application/json"}
        resp = requests.post(authuri + '/oauth/token', data=payload, headers=headers)
        resp.raise_for_status()
        respjson = resp.json()
        token = respjson['id_token']
        return HTTPFound(location=sparedirecturi + token)
    except Exception as e:
        logger.exception(e)
        return None

