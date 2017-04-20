import jwt
from flask import request, abort
import pkg_resources


def requires_scope(*required_scopes):
    def requires_scope_decorator(fn):
        def wrapper():
            if "Authorization" not in request.headers:
                return abort(401, "No Authorization header provided")
            token = request.headers["Authorization"]
            key = pkg_resources.resource_string(__name__, "jwk.pub.pem")
            payload = jwt.decode(token, key=key, algorithms=["RS256"])
            scopes = payload["scope"].split(" ")
            authorized = all(scope in scopes for scope in required_scopes)

            if not authorized:
                abort(403)

            return fn()
        return wrapper
    return requires_scope_decorator
