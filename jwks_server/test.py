import os, signal
import requests
import unittest
import multiprocessing
import json
from time import time, sleep
from base64 import urlsafe_b64decode
from jose import jwk, jwt
from jose.exceptions import JWKError, JWTError
from main import main as run_server

class TestServer(unittest.TestCase):
    """
    Tests the server.
    """
    flask_server = None

    @classmethod
    def setUpClass(cls):
        """Set up server on a different thread"""
        cls.flask_server = multiprocessing.Process(target=run_server, kwargs={'enableDev': True})
        cls.flask_server.start()
        # I looked through Flask's documentation for how I could wait for the server to come up,
        #  but only found that it has its own testing functionality. As I am not rewriting my
        #  entire test suite, this is what you get.
        sleep(0.2)


    @classmethod
    def tearDownClass(cls):
        """Destroy server"""
        # I swear I tried looking around for a nicer way to do it. But I guess Flask is
        #  just built to work with unexpected termination.
        os.kill(cls.flask_server.pid, signal.SIGINT)


    def setUp(self):
        """Reset all keys after each test is run"""
        # This endpoint is only active during testing, don't worry.
        requests.post("http://localhost:8080/dev?action=resetkeys")


    def test_valid_keys(self):
        """Tests if the server is returning good keys"""
        # test initialization
        with self.subTest("Initial test"):
            req = requests.get("http://localhost:8080/.well-known/jwks.json")
            self.assertEqual(req.status_code, 200, "Incorrect status code received")
            parsed_jwks = safeLoadJson(req.content)
            self.assertIsNotNone(parsed_jwks, "Received data was not valid JSON")
            key_count = validateJWKS(parsed_jwks)
            self.assertIsNotNone(key_count, "Response was not a valid JWKS")
            self.assertEqual(key_count, 0, "Found JWK in JWKS when there shouldn't've been any")

        # test getting a JWT
        req = requests.post("http://localhost:8080/auth")
        self.assertEqual(req.status_code, 200, "Incorrect status code received")
        tmp_jwt = req.content.decode('utf-8')
        parsed_jwt = safeLoadJWT(tmp_jwt)
        self.assertIsNotNone(parsed_jwks, "Response data was not a valid JWT")

        # test getting JWKS now that one has been made
        req = requests.get("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(req.status_code, 200, "Incorrect status code received")
        parsed_jwks = safeLoadJson(req.content)
        self.assertIsNotNone(parsed_jwks, "Received data was not valid JSON")
        key_count = validateJWKS(parsed_jwks)
        self.assertEqual(key_count, 1, "JWKS was either invalid or contained no keys")
        tmp_jwk = parsed_jwks["keys"][0]

        # confirm they match each other
        self.assertEqual(str(parsed_jwt[0]["kid"]), tmp_jwk["kid"], "JWT and JWK did not have matching kids")
        self.assertIsNotNone(safeLoadJWT(tmp_jwt, tmp_jwk), "Signature in JWK did not match signature on JWT")


    def test_expiration(self):
        """Test getting an expired key"""
        # get a JWT
        req = requests.post("http://localhost:8080/auth?expired=true")
        self.assertEqual(req.status_code, 200, "Incorrect status code received")
        tmp_jwt = safeLoadJWT(req.content.decode('utf-8'))  # used later
        self.assertIsNotNone(tmp_jwt, "Response data was not a valid JWT")
        self.assertLess(int(tmp_jwt[1]["exp"]), time(), "Expired JWT was not past expiration date")

        # get the JWKS
        kid = tmp_jwt[0]["kid"]
        req = requests.get(f"http://localhost:8080/.well-known/jwks.json?kid={kid}")
        self.assertEqual(req.status_code, 404, "Incorrect status code received for accessing expired JWK")
        req = requests.get(f"http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(req.status_code, 200, "Incorrect status code received")
        parsed_jwks = safeLoadJson(req.content)
        self.assertIsNotNone(parsed_jwks, "Received data was not valid JSON")
        key_count = validateJWKS(parsed_jwks)
        self.assertIsNotNone(key_count, "Response was not a valid JWKS")
        self.assertEqual(key_count, 0, "Found JWK in JWKS when there shouldn't've been any")


    def test_invalid_stuff(self):
        # test jwks endpoint
        req = requests.get("http://localhost:8080/.well-known/jwks.json?kid=0")
        self.assertEqual(req.status_code, 404, "Unexpected response code for invalid JWK kid")
        for func in (requests.post, requests.put, requests.delete):
            req = func("http://localhost:8080/.well-known/jwks.json")
            self.assertEqual(req.status_code, 405, "Unexpected status code for incorrect request type at JWKS endpoint")
        # test auth endpoint
        for func in (requests.get, requests.put, requests.delete):
            req = func("http://localhost:8080/auth")
            self.assertEqual(req.status_code, 405, "Unexpected status code for incorrect request type at auth endpoint")
        # test a nonexistent endpoint
        for func in (requests.get, requests.post, requests.put, requests.delete):
            req = func("http://localhost:8080/just/testing.stuff")
            self.assertEqual(req.status_code, 404, "Unexpected status code for request to nonexistent endpoint")

class FallbackTestServer(TestServer):
    """
    Literally just run all the tests in TestServer but with fallback mode enabled
    """
    def setUp(self):
        """Reset all keys after each test is run"""
        requests.post("http://localhost:8080/dev?action=resetkeysFALLBACK")

def safeLoadJson(in_json: str | bytes) -> dict | None:
    """Loads the supplied JSON. Returns None if it is invalid."""
    try:
        return json.loads(in_json)
    except json.decoder.JSONDecodeError:
        return None


def safeLoadJWK(in_jwk: dict) -> dict | None:
    """
    Loads the supplied JWK. Returns None if it is invalid.

    :param in_jwk: A dictionary containing the JWK (just parse the JSON and pass it in)
    """
    try:
        return jwk.construct(in_jwk)
    except JWKError:
        return None


def validateJWKS(in_jwks: dict) -> int | None:
    """
    Returns the number of valid JWKs in the JWKS. If there are any invalid JWKs, returns -1.
    If the JWKS is of invalid structure, returns None.

    :param in_jwks: A dictionary containing a JWKS (just parse the JSON and pass it in)
    """
    if in_jwks is None: return None
    if "keys" not in in_jwks or type(in_jwks["keys"]) is not list: return None
    good_jwk = 0
    for item in in_jwks["keys"]:
        if safeLoadJWK(item): good_jwk += 1
        else: return -1
    return good_jwk


def safeLoadJWT(in_jwt: str, in_jwk: dict = None) -> tuple[dict, dict] | None:
    """
    Returns a tuple of header and payload as dictionaries like so: (header, payload)

    :param in_jwt: Input JWT
    :param in_jwk: JWK holding public key for JWT signature. Optional
    :return: (header, payload) of the JWT if everything succeeds, None otherwise (including if signature is bad)
    """
    split_jwt = in_jwt.split('.')
    split_jwt = [i+"="*((4-len(i)%4)%4) for i in split_jwt]  # base64 module hates no padding at the end.
    if len(split_jwt) != 3: return None
    header = safeLoadJson(urlsafe_b64decode(split_jwt[0]))
    if header is None: return None
    payload = safeLoadJson(urlsafe_b64decode(split_jwt[1]))
    if payload is None: return None
    try:
        jwt.decode(in_jwt, in_jwk, options={'verify_signature': in_jwk is not None, 'verify_exp': False})
    except JWTError:
        return None
    return header, payload


def run_tests():
    unittest.main()