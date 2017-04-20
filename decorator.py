import jwt
from flask import request, abort
import pkg_resources
from commons_auth.auth import auth


def requires_scope(*required_scopes_variants: list):
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
            for required_scopes in required_scopes_variants:
                authorized = all(scope in scopes for scope in required_scopes)
                if authorized:
                    break

            if not authorized:
                abort(403)

            return fn()

        return wrapper

    return requires_scope_decorator
