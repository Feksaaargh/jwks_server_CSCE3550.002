from time import time
from random import randint
from Crypto.PublicKey import RSA
from jose import jwt
import sqlite3

# I decided to do this rather than inherit so it pretends it's a simpler object which better suits my needs
class _ExpirableRSAKey:
    """
    Effectively just a Crypto.PublicKey.RSA.RsaKey object, but has a different constructor
    and an 'expired' parameter.
    """
    def __init__(self, expiration: float, length: int = 3072):
        """
        :param expiration: A float representing seconds since epoch when this token should expire
        :param length: How many bits the RSA key should be (default: 3072)
        """
        self._key: RSA.RsaKey = RSA.generate(length)
        self.expiration: float = expiration
        self.private: str = self._key.export_key().decode('utf-8')  # for convenience

    @property
    def expired(self) -> bool:
        """Returns true if the token has expired"""
        return time() > self.expiration

    def __getattr__(self, item):
        """Silly proxying function to pretend this is just an extension of the Rsakey object"""
        return self._key.__getattribute__(item)

class _KeyDatabaseManager:
    """
    A class for abstracting away the complexities of managing a database.
    Interfaces pretty much like a dictionary, but the keys are always ints
    and the values are always ExpirableRSAKeys.
    """
    def __init__(self, datafile: str):
        """
        :param datafile: Absolute path to where the database file should be located.
        """
        # indicates if the database was successfully loaded
        self._fallback: bool = False
        try:
            raise sqlite3.Error("not yet implemented...")  # TODO: remove this and implement database
            self._db: sqlite3.Connection = sqlite3.connect(datafile)
        except sqlite3.Error as e:
            # print the error messages in bold bright yellow
            print("\033[1;93mAn error occurred when accessing the sqlite database -\033[0m", e)
            print("\033[1;93mUsing fallback mode, keys will not be saved to disk.\033[0m")
            self._fallback = True
            self._fbdb: dict[int, _ExpirableRSAKey] = {}  # fallback database

    def __del__(self):
        """Clean up, clean up, everybody do your share"""
        if not self._fallback: self._db.close()

    def __getitem__(self, key: int) -> _ExpirableRSAKey:
        """Subscript get a key from the database"""
        if self._fallback:
            return self._fbdb[key] if key in self._fbdb else None
        # TODO implement database

    def __setitem__(self, key: int, value: _ExpirableRSAKey):
        """Subscript set a key to the database"""
        if self._fallback:
            self._fbdb[key] = value
            return
        # TODO implement database

    def __delitem__(self, key: int):
        """Delete a key in the database"""
        if self._fallback:
            if key in self._fbdb: del self._fbdb[key]
            return
        # TODO: implement database

    def __contains__(self, key: int):
        """Check if item is in database (with 'in' operator)"""
        if self._fallback:
            return key in self._fbdb
        # TODO: implement database


    def listKIDs(self) -> list[int]:
        if self._fallback:
            return list(self._fbdb.keys())
        # TODO: implement database


class TokenManager:
    """
    A class to create, store, and retrieve JWTs and JWKs.
    Note that keys are stored in memory and are lost when the object is destroyed.
    """
    def __init__(self):
        self._database = _KeyDatabaseManager(None)

    @staticmethod
    def _intToB64(num: int, padEven: bool = True) -> str:
        """Encodes an integer into base64. Expects input to be positive."""
        if num < 0: return ""
        ret = ""
        while num > 0:
            ret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[num%64] + ret
            num = num // 64
        if padEven and len(ret)%2: return "A"+ret
        return ret

    def getJWKS(self) -> str:
        """
        :return: a JWKS containing all known JWKs
        """
        # https://datatracker.ietf.org/doc/rfc7517/
        all_jwk = []
        for i in self._database.listKIDs():  # since it's pretty much a dict, no need to specially handle item removal
            jwk = self.getJWK(i)
            if jwk is not None: all_jwk.append(jwk)
        return '{"keys":[%s]}'%",".join(all_jwk)

    def getJWK(self, kid: int) -> str | None:
        """
        Retrieve and formats a single JWK from the known items.

        :param kid: Identifier for the key being requested
        :return: a string encoding the requested JWK, or None if not found or expired.
        """
        # https://datatracker.ietf.org/doc/rfc7517/
        key = self._database[kid]
        if key is None: return None
        if key.expired:
            # since expired tokens are only cleaned upon attempted retrieval, this could get bloated...
            del self._database[kid]
            return None
        return f'{{"kty":"RSA","alg":"RS256","kid":"{kid}","n":"{self._intToB64(key.n)}","e":"{self._intToB64(key.e)}"}}'

    def makeJWT(self, timeout: float) -> str:
        """
        Makes a JWK and JWT, then signs the JWT and returns it. It contains a parameter "kid" referring
        to the JWK it was signed with, accessible from issuing a GET to /.well-known/<kid>.json

        :param timeout: Timeout in seconds after which the created JWK will expire
        :return: a signed JWT
        """
        # https://datatracker.ietf.org/doc/rfc7519/
        key = _ExpirableRSAKey(int(time() + timeout))  # flooring to be nice, despite the key expiration allowing decimals
        kid = randint(42, 2**31-1)  # up to signed 32 bit int limit
        while kid in self._database:
            kid = kid = randint(42, 2**31-1)
        self._database[kid] = key
        return jwt.encode({"iss": "feksa", "exp": str(int(key.expiration))}, key.private,
                          algorithm="RS256", headers={"kid": kid})