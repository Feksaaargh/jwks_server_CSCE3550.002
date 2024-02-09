import sys
from os.path import basename
from threading import RLock
from flask import Flask, request, abort
from tokenmanager import TokenManager


app = Flask(__name__)
tkm = TokenManager()
# As Flask calls functions in a threaded manner, this can be used in place
#  of a normal Lock (and I can use "with" syntax with it too!)
tkm_rlock = RLock()
testing = False


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
    with tkm_rlock:  # thread safety for when testing
        if kid == "jwks":
            return tkm.getJWKS(), 200
        else:
            jwk = tkm.getJWK(kid)
            if jwk is None: abort(404)
            return f'{{"keys":[{jwk}]}}', 200


@app.route("/auth", methods=["POST"])
def createJWT() -> str:
    """Create a JWK and return a corresponding JWT"""
    with tkm_rlock:  # thread safety for when testing
        return tkm.makeJWT(-3600 if
                           request.args.get("expired") == "true"
                           else 3600)  # default key expiration is 1 hour


@app.route("/dev", methods=["POST"])
def testingInterface():
    """An endpoint allowing for resetting keys on the server"""
    if not testing: abort(404)  # don't allow access during normal use
    global tkm
    action = request.args.get("action")
    if action == "resetkeys":
        with tkm_rlock:
            tkm = TokenManager()
        return "Ack"
    return "Not found"


def main(enableDev: bool = False):
    """Run the server"""
    global testing
    if enableDev: testing = True
    app.run(port=8080)

if __name__ == "__main__":
    args = sys.argv[1:]
    # check for any invalid command line option (including help requests)
    if len(args) != 0 and "--test" in args:
        sys.argv = [i for i in sys.argv if i != "--test"]  # remove --test from params (unittest borks otherwise)
        from test import *  # is this bad practice? it feels like bad practice.
        run_tests()
    elif len(args) != 0 and "--test" not in args:
        # unknown parameter, print help page
        print(f"Usage: {basename(__file__)} [OPTIONS...]")
        print("  -h --help    Show this screen")
        print("  --test       Run tests")
    else:
        main()