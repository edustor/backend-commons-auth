import jwt
from flask import request, abort
import pkg_resources
from commons_auth.auth import auth


def requires_scope(*required_scopes):
    def requires_scope_decorator(fn):
        def wrapper():
            if "Authorization" not in request.headers:
                return abort(401, "No Authorization header provided")
            token = request.headers["Authorization"]
            key = pkg_resources.resource_string(__name__, "jwk.pub.pem")
            payload = jwt.decode(token, key=key, algorithms=["RS256"])

            auth.account_id = payload['sub']

            scopes = payload["scope"].split(" ")

            authorized = False

            required_scopes_variants = required_scopes
            if len(required_scopes) > 0 and type(required_scopes[0]) is str:
                required_scopes_variants = [[*required_scopes]]

            for required_scopes_variant in required_scopes_variants:
                authorized = all(scope in scopes for scope in required_scopes_variant)
                if authorized:
                    break

            if not authorized:
                abort(403)
            return fn()
        wrapper.__name__ = fn.__name__
        return wrapper

    return requires_scope_decorator
