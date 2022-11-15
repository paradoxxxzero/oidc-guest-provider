import json
import os
from pathlib import Path
from random import choice
import string
from sys import exit, stderr

from flask import Flask, Response, abort, redirect, request, jsonify
from jwkest.jwk import RSAKey, rsa_load
from oic.oic.message import TokenErrorResponse
from pyop.authz_state import AuthorizationState
from pyop.exceptions import (
    InvalidAuthenticationRequest,
    InvalidClientAuthentication,
    OAuthError,
)
from pyop.message import AuthorizationRequest
from pyop.provider import Provider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo
from pyop.util import should_fragment_encode
from oic.oic.message import UserInfoErrorResponse

from pyop.access_token import AccessToken
from pyop.exceptions import BearerTokenError
from pyop.exceptions import InvalidAccessToken

app = Flask(__name__)
sub_hash_salt = "salt"

config_file = Path(
    os.getenv("OIDC_GUEST_PROVIDER_CONFIG", Path(__file__).parent / "config.json")
).absolute()

print(f"Loading configuration from {config_file}", file=stderr)

try:
    with open(config_file) as config:
        config = json.loads(config.read())
except Exception:
    print(f"Could not load config file {config_file}", file=stderr)
    exit(1)


signing_key = RSAKey(
    key=rsa_load(config["signing_key"]), use="sig", alg=config["signing_alg"]
)


issuer = config["issuer"]
configuration_information = {
    "issuer": issuer,
    "authorization_endpoint": f"{issuer}/authorization",
    "token_endpoint": f"{issuer}/token",
    "userinfo_endpoint": f"{issuer}/userinfo",
    "response_types_supported": ["code", "id_token token"],
    "id_token_signing_alg_values_supported": [signing_key.alg],
    "response_modes_supported": ["fragment", "query"],
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": ["authorization_code", "implicit"],
    "claim_types_supported": ["normal"],
    "claims_parameter_supported": True,
    "claims_supported": ["sub", "email"],
    "request_parameter_supported": False,
    "request_uri_parameter_supported": False,
    "scopes_supported": ["openid", "email"],
    "jwks_uri": f"{issuer}/jwks",
}

subject_id_factory = HashBasedSubjectIdentifierFactory(config["salt"])
authz_state = AuthorizationState(
    subject_id_factory,
    {},
    {},
    {},
    {},
)
client_db = {
    "_client_id_": {
        "response_types": ["code"],
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "client_secret_expires_at": 0,
        "redirect_uris": config["client_redirect_uris"],
    }
}

# We use a memory db for now:
user_db = {}
provider = Provider(
    signing_key, configuration_information, authz_state, client_db, Userinfo(user_db)
)


def rnd(size):
    return "".join([choice(string.ascii_letters + string.digits) for _ in range(size)])


@app.route("/")
def check():
    return (
        "oidc-guest-provider is running: %s/.well-known/openid-configuration" % issuer
    )


@app.route("/.well-known/openid-configuration")
def provider_config():
    return jsonify(provider.provider_configuration.to_dict())


@app.route("/authorization")
def authorization():
    try:
        authn_req = provider.parse_authentication_request(
            request.query_string.decode("utf-8")
        )
    except InvalidAuthenticationRequest as e:
        error_url = e.to_error_url()

        if error_url:
            return redirect(error_url, 303)
        else:
            raise abort(400)

    rng_size = config["rng_size"]
    user_id = rnd(rng_size)
    user_db[user_id] = {
        "email": f"anon-{rnd(rng_size)}@example.com",
    }
    authn_response = provider.authorize(
        AuthorizationRequest().from_dict(authn_req), user_id
    )
    return_url = authn_response.request(
        authn_req["redirect_uri"], should_fragment_encode(authn_req)
    )
    return redirect(return_url, 302)


@app.route("/token", methods=["POST", "GET"])
def token():
    try:
        token_response = provider.handle_token_request(
            request.get_data().decode("utf-8"), request.headers
        )
        return jsonify(token_response.to_dict())
    except InvalidClientAuthentication as e:
        error_resp = TokenErrorResponse(
            error="invalid_client", error_description=str(e)
        )
        http_response = Response(
            error_resp.to_json(), status=401, content_type="application/json"
        )
        http_response.headers["WWW-Authenticate"] = "Basic"
        return http_response
    except OAuthError as e:
        error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
        return Response(
            error_resp.to_json(), status=400, content_type="application/json"
        )


@app.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    try:
        response = provider.handle_userinfo_request(
            request.get_data().decode("utf-8"), request.headers
        )
        return jsonify(response.to_dict())
    except (BearerTokenError, InvalidAccessToken) as e:
        error_resp = UserInfoErrorResponse(
            error="invalid_token", error_description=str(e)
        )
        http_response = Response(
            error_resp.to_json(), status=401, content_type="application/json"
        )
        http_response.headers["WWW-Authenticate"] = AccessToken.BEARER_TOKEN_TYPE
        return http_response
