
# JWKS server for CSCE 3550.002  
  
The title says it all. It does JWKS things. And a little bit of JWT to spice it up. But you're probably interested in the JWKS part. That's why I called it a JWKS server and not a JWT server.  
  
## Usage  
Start by running main.py. This starts a server on port 8080 with two endpoints: `/auth` and `/.well-known/jwks.json`.  
  
`/auth` is where you create new keys. If you send a POST request to it, it will create a JWK on the server and return a signed JWT. The JWT contains a key identifier `kid` in its header and an expiration `exp` in its body, both to describe the JWK. The JWT is signed with the JWK that the `kid` is referring to, obtainable from `/.well-known/jwks.json`. Keys expire one hour after creation. You may set the `expired` query parameter (set to "true") when submitting the POST request to indicate you wish to create an already expired JWT. This will create a JWK that has expired one hour in the past.  
  
`/.well-known/jwks.json` is where you retrieve public keys. If you send a GET request to it, a JWKS will be returned containing all keys on the server. If you instead GET to `/.well-known/<kid>.json` (`<kid>` being the key identifier obtained from `/auth`) then a JWKS only containing the requested key will be returned. If the key is not found, a 404 status code will be returned.  
  
There is no mechanism for retrieving private keys, as the assignment either did not make it clear that it was a requirement or it was simply not necessary.  
  
All keys are stored in memory and as such, restarting the server loses all of them. This project is not suitable for any sort of production use, and is even questionably suitable for submission as an assignment.

## Testing
Run main.py with the `--test` flag to run a self test.

During testing it opens another endpoint at `/dev` where you may pass in a query parameter `action` indicating the action you wish to take (the only choice is "resetkeys" which deletes and recreates the internal key store).

If all tests succeed, it will print "OK" at the end. If they do not succeed, I will probably cry.

You may define further parameters alongside `--test` which get passed to unittest. You can find the whole list of options [here](https://docs.python.org/3/library/unittest.html#command-line-options), although they don't seem very useful.