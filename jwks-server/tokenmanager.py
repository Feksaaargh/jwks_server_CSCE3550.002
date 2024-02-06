from utils import intToB64
from base64 import urlsafe_b64encode
from uuid import uuid4
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from time import time
import jwt

# I decided to do this rather than inherit so it pretends it's a simpler object which better suits my needs
class ExpirableRSAKey:
    """
    Effectively just a Crypto.PublickKey.RSA.RsaKey object, but has a different constructor
    and an 'expired' parameter.
    """
    def __init__(self, expiration: float, length: int = 3072):
        """
        :param expiration: A float representing seconds since epoch when this token should expire
        :param length: How many bits the RSA key should be (default: 3072)
        """
        self._key: RSA.RsaKey = RSA.generate(length)
        self.expiration: float = expiration
        self.private: bytes = self._key.export_key()  # for convenience

    @property
    def expired(self) -> bool:
        """Returns true if the token has expired"""
        return time() > self.expiration

    def __getattr__(self, item):
        """Silly proxying function to pretend this is just an extension of the Rsakey object"""
        return self._key.__getattribute__(item)


class TokenManager:
    """
    A class to create, store, and retrieve JWTs and JWKs.
    Note that keys are stored in memory and are lost when the object is destroyed.
    """
    def __init__(self):
        self._tokens: dict[str, ExpirableRSAKey] = {}
        self._signature: bytes = get_random_bytes(32)  # 256 bit

    def getJWKS(self) -> str:
        """
        :return: a JWKS containing all known JWKs
        """
        # https://datatracker.ietf.org/doc/rfc7517/
        all_jwk = []
        for i in list(self._tokens.keys()):  # need to listify because getJWK could remove a key
            jwk = self.getJWK(i)
            if jwk is not None: all_jwk.append(jwk)
        return '{"keys":[%s]}'%",".join(all_jwk)

    def getJWK(self, kid: str) -> str | None:
        """
        Retrieve and formats a single JWK from the known items.

        :param kid: Identifier for the key being requested
        :return: a string encoding the requested JWK, or None if not found or expired.
        """
        # https://datatracker.ietf.org/doc/rfc7517/
        if kid not in self._tokens: return None
        key = self._tokens[kid]
        if key.expired:
            # since expired tokens are only cleaned upon attempted retrieval, this could get bloated...
            del self._tokens[kid]
            return None
        return f'{{"kty":"RSA","kid":"{kid}","n":"{intToB64(key.n)}","e":"{intToB64(key.e)}"}}'

    def makeJWT(self, timeout: float) -> str:
        """
        Makes a JWK and JWT, then signs the JWT and returns it. It contains a parameter "kid" referring
        to the JWK it was signed with, accessible from issuing a GET to /.well-known/<kid>.json

        :param timeout: Timeout in seconds after which the created JWK will expire
        :return: a signed JWT
        """
        # https://datatracker.ietf.org/doc/rfc7519/
        key = ExpirableRSAKey(int(time()+timeout))  # flooring to be nice, despite the key expiration allowing decimals
        kid = str(uuid4())
        while kid in self._tokens:
            kid = str(uuid4())
        self._tokens[kid] = key
        return jwt.encode({"iss": "feksa", "exp": str(int(key.expiration))}, key.private,
                          algorithm="RS256", headers={"kid": kid})