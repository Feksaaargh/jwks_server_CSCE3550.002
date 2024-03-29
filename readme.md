# JWKS server for CSCE 3550.002

The title says it all. It does JWKS things. And a little bit of JWT to spice it up. But you're probably interested in the JWKS part. That's why I called it a JWKS server and not a JWT server.

**This is for project 2, but is compatible with project 1. The original project 1 submission can be found in the tags, but does not have coverage so I would like this to be graded instead.**

## Usage
First you need to install requirements with `pip install -r requirements.txt`. It is recommended to do this in a virtual environment. After this, you can run the server with `python3 main.py` from inside the `jwks_server` folder. This starts the server on port 8080 with two endpoints: `/auth` and `/.well-known/jwks.json`. To stop, hit CTRL+C in the terminal or otherwise kill the process. That's apparently how to stop a Flask server.

`/auth` is where you create new keys. If you send a POST request to it, it will create a JWK on the server and return a signed JWT. The JWT contains a key identifier `kid` in its header and an expiration `exp` in its body, both to describe the created JWK. The JWT is signed with the JWK that the `kid` is referring to, obtainable from `/.well-known/jwks.json`. Keys expire one hour after creation. You may set the `expired` query parameter (set to "true") when submitting the POST request to indicate you wish to create an already expired JWT. This will create a JWK that has expired one hour in the past.

`/.well-known/jwks.json` is where you retrieve public keys. If you send a GET request to it, a JWKS will be returned containing all keys on the server. If you include a query parameter 'kid' like so: `/.well-known/jwks.json?kid=96240`, then a JWKS only containing the requested key will be returned. If the key is not found (or is expired), a 404 status code will be returned.

An sqlite database will be created at "totally_not_my_privateKeys.db" next to `main.py`. This contains the program's keys in a table called "keys" with columns `kid` (int), `key` (blob (text)), and `exp` (int). They are the kid, PEM format private key, and expiration date respectively.
If creation of this database fails, the program will enter a fallback mode where it uses an in-memory database which will be lost upon program exit.

## Testing
Run `python3 main.py --test` to run a self test.

**DO NOT run a self-test with anything important named "totally_not_my_privateKeys.db" in the same folder as the script; it may get deleted.**

During testing it opens another endpoint at `/dev` where you may pass in a query parameter `action` indicating the action you wish to take. The action "resetkeys" deletes and recreates the key database, and "resetkeysFALLBACK" deletes and recreates the key database but forces the fallback mode when recreating it.

If all tests succeed, it will print "OK" at the end. If they do not succeed, I will probably cry.

You may define further parameters alongside `--test` which get passed to unittest. You can find the whole list of options [here](https://docs.python.org/3/library/unittest.html#command-line-options), although they don't seem very useful.

## Other parameters
You may start the program with `python3 main.py --recreate_db` which will attempt to delete and recreate the database during launch.

**DO NOT use this parameter with anything important named "totally_not_my_privateKeys.db" in the same folder as the script; it may get deleted.**

## Coverage
To check coverage, you must run the following commands with your venv active and your working directory inside `jwks_server`:
```shell
export COVERAGE_PROCESS_START=".coveragerc" PYTHONPATH=$PWD
coverage run
coverage combine
coverage html
rm .coverage
```
(Note that this is for Linux, please adapt for Windows as necessary.)

This will generate a `htmlconv` directory in `jwks_server`. This contains a webpage with the coverage data. Open `index.html` in a browser to view it.

## Images
![Software running against provided test suite](images/provided_test_suite.webp "Running against the provided test suite")

![Software running its own test suite](images/own_test_suite.webp "Running its built in test suite")