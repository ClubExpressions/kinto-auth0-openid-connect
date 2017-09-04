"""kinto_auth0_openid_connect - Auth0 Authentication support for Kinto with OpenId Connect flow"""

__author__ = 'Damien Lecan <dev@dlecan.com>'
__all__ = []

def includeme(config):
    print("Initiliazing kinto_auth0_openid_connect plugin ...")

    # Activate end-points.
    config.scan('kinto_auth0_openid_connect.views')

