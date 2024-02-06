from flask import Flask, request, abort
from tokenmanager import TokenManager

app = Flask(__name__)
tkm = TokenManager()

@app.route("/.well-known/<kid>", methods=["GET"])
def getJWKS(kid) -> tuple[str, int]:
    """
    If kid is "jwks", returns all JWKs known to the system.
    If kid is anything else, attempts to return that specific JWK (in a JWKS).
    """
    # note that since the generated kids are RFC4122 UUIDs, it can never be "jwks"
    #  and therefore collisions aren't a problem
    if not kid.endswith(".json"): abort(404)
    kid = kid[:-5]
    if kid == "jwks":
        return tkm.getJWKS(), 200
    else:
        jwk = tkm.getJWK(kid)
        if jwk is None: abort(404)
        return f'{{"keys":[{jwk}]}}', 200

@app.route("/auth", methods=["POST"])
def createJWT() -> str:
    return tkm.makeJWT(-3600 if
                       request.args.get("expired") == "true"
                       else 3600)  # default key expiration is 1 hour

if __name__ == "__main__":
    app.run(port=8080)