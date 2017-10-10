import json
import requests
from kinto.core import logger
from pyramid import httpexceptions
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.interfaces import IAuthenticationPolicy
from zope.interface import implementer
from jose import jwt

def get_config_value(request, key):
  value = request.registry.settings["auth0." + key]
#  logger.debug("auth0." + key + ": " + value)
  return value

def handle_error(error, status_code):
#  logger.debug(error)
  raise httpexceptions.exception_response(status_code)

@implementer(IAuthenticationPolicy)
class Auth0OIDCAuthenticationPolicy(CallbackAuthenticationPolicy):
    def __init__(self, realm='Realm'):
        print("Init Auth0OIDCAuthenticationPolicy")
        self.realm = realm
        self._cache = None

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
            return handle_error({"code": "invalid_header",
                                     "description": "Unable to parse authentication"
                                                    "token."}, 400)
        if authmeth != auth_method.lower():
            return handle_error({"code": "invalid_header",
                                     "description": "Unable to parse authentication"
                                                    "token."}, 400)

        (rsa_key, algorithm) = self._get_crypto_data(request, auth_domain, token)
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

    def _get_cache(self, request):
      """Instantiate cache when first request comes in.
      """
      if self._cache is None:
        if hasattr(request.registry, 'cache'):
          self._cache = request.registry.cache

      return self._cache

    def _get_crypto_data(self, request, auth_domain, token):

      cache = self._get_cache(request)

      unverified_header = jwt.get_unverified_header(token)
      unverified_kid = unverified_header["kid"]

      resp = cache.get(unverified_kid)

      if resp is None:
        jwks_resp = requests.get("https://" + auth_domain + "/.well-known/jwks.json")
        jwks = jwks_resp.json()
        rsa_key = {}
        algorithm = None

        for key in jwks["keys"]:
          if key["kid"] == unverified_kid:
            rsa_key = {
              "kty": key["kty"],
              "kid": key["kid"],
              "use": key["use"],
              "n": key["n"],
              "e": key["e"]
            }
            algorithm = key["alg"]
        resp = (rsa_key, algorithm)
        cache.set(unverified_kid, resp, 43200)

      return resp
