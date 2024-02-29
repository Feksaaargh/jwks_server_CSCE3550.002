import sys, os
from threading import Lock
from flask import Flask, request, abort
from tokenmanager import TokenManager


app = Flask(__name__)
# Use a database called "totally_not_my_privateKeys.db" next to wherever this script is
tkm = TokenManager(os.path.join(os.path.dirname(os.path.realpath(__file__)), "totally_not_my_privateKeys.db"))
# use a lock, notably for when deleting the database during testing
tkm_lock = Lock()
testing = False


@app.route("/.well-known/jwks.json", methods=["GET"])
def getJWKS() -> tuple[str, int]:
    """
    Get all the JWKs or a specific JWK if the "jwk" query parameter is specified
    """
    with tkm_lock:  # thread safety for when testing
        if kid := request.args.get("jwk"):
            # has jwk parameter
            try: kid = int(kid)
            except ValueError: abort(404)
            jwk = tkm.getJWK(kid)
            if jwk is None: abort(404)
            return f'{{"keys":[{jwk}]}}', 200
        else:
            # does not have jwk parameter
            return tkm.getJWKS(), 200


@app.route("/auth", methods=["POST"])
def createJWT() -> str:
    """Create a JWK and return a corresponding JWT"""
    with tkm_lock:  # thread safety for when testing
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
        tkm.recreateDB()
        return "Ack"
    return "Not found"


def main(enableDev: bool = False, recreateDB: bool = False):
    """Run the server"""
    global testing
    if enableDev: testing = True
    if recreateDB: tkm.recreateDB()
    app.run(port=8080)

if __name__ == "__main__":
    args = sys.argv[1:]
    # check for any invalid command line option (including help requests)
    if "--test" in args:
        sys.argv = [i for i in sys.argv if i not in ("--test", "--recreate_db")]  # remove args from params (unittest borks otherwise)
        from test import *  # is this bad practice? it feels like bad practice.
        run_tests()
    elif any([i not in ("--recreate_db",) for i in args]):
        # unknown parameter, print help page
        print(f"Usage: {os.path.basename(__file__)} [OPTIONS...]")
        print("  -h --help       Show this screen")
        print("  --test          Run tests")
        print("  --recreate_db   Delete and recreate the database when running")
    else:
        if "--recreate_db" in args:
            tkm.recreateDB()
        main(False, len(args) != 0 and "--recreate-db" in args)