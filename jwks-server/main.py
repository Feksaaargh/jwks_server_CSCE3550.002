from flask import Flask, request, abort
from tokenmanager import TokenManager
import sys
from os.path import basename

app = Flask(__name__)
tkm = TokenManager()

@app.route("/.well-known/<kid>", methods=["GET"])
def getJWKS(kid) -> tuple[str, int]:
    """
    <kid> needs to end with ".json" for this function to respond to it.
    If kid is "jwks.json", returns all JWKs known to the system.
    If kid is anything else (+.json), attempts to return that specific JWK (in a JWKS).
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
    """Create a JWK and return a corresponding JWT"""
    return tkm.makeJWT(-3600 if
                       request.args.get("expired") == "true"
                       else 3600)  # default key expiration is 1 hour

def main():
    """Run the server"""
    app.run(port=8080)

if __name__ == "__main__":
    args = sys.argv[1:]
    # check for any invalid command line option (including help requests)
    if any(i != '--test' for i in args):
        print(f"Usage: {basename(__file__)} [OPTIONS...]")
        print("  -h --help    Show this screen")
        print("  --test       Run tests")
        exit(0)
    if "--test" in args:
        raise NotImplementedError("Go to a more recent commit.")
        exit(1)  # make absolutely sure it's dead
    else:
        main()
        exit(0)