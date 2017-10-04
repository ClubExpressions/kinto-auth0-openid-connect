import requests
import json
from kinto.core import logger
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.interfaces import IAuthenticationPolicy
from zope.interface import implementer
from jose import jwt

def get_config_value(request, key):
  value = request.registry.settings["auth0." + key]
#  logger.debug("auth0." + key + ": " + value)
  return value

def handle_error(error, status_code):
  logger.debug(error)
  return None

@implementer(IAuthenticationPolicy)
class Auth0OIDCAuthenticationPolicy(CallbackAuthenticationPolicy):
    def __init__(self, realm='Realm'):
        print("Init Auth0OIDCAuthenticationPolicy")
        self.realm = realm

    def unauthenticated_userid(self, request):
        """Return the Auth0 userid or ``None`` if token could not be verified.
        """
        user_id = self._get_credentials(request)
        return user_id

    def forget(self, request):
        auth_method = get_config_value(request, "auth_method")
        return [('WWW-Authenticate', '%s realm="%s"' % (auth_method, self.realm))]

    def _get_credentials(self, request):
        auth_method = get_config_value(request, "auth_method")
        auth_domain = get_config_value(request, "auth_domain")

        authorization = request.headers.get('Authorization', '')
        try:
            authmeth, token = authorization.split(' ', 1)
            authmeth = authmeth.lower()
        except ValueError:
            return None
        if authmeth != auth_method.lower():
            return None

        jwks_resp = requests.get("https://" + auth_domain + "/.well-known/jwks.json")
        jwks = jwks_resp.json()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        algorithm = None
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
                algorithm = key["alg"]
        if rsa_key:
            try:
                profile = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=algorithm,
#                   audience=get_config_value(request, "audience"),
#                   Bug: why audience is set to clientId ??
                    audience=get_config_value(request, "client_id"),
                    issuer="https://" + auth_domain + "/"
                )
            except jwt.ExpiredSignatureError:
                return handle_error({"code": "token_expired",
                                     "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                return handle_error({"code": "invalid_claims",
                                     "description": "incorrect claims,"
                                                    "please check the audience and issuer"}, 401)
            except Exception:
                return handle_error({"code": "invalid_header",
                                     "description": "Unable to parse authentication"
                                                    "token."}, 400)

            return profile["sub"]
        return handle_error({"code": "invalid_header",
                             "description": "Unable to find appropriate key"}, 400)
