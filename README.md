# Authentication system based on Chaum-Pedersen ZKP

## Overview
User/password authentication system base on the Chaum-Pedersen ZKP protocol. 
The client is the ZKP prover and the server is the ZKP verifier.

## Requirements
- Python 3
- grpcio
- grpcio tools

## Guidelines
- To run Chaum-Pedersen ZKP unit tests:
```
python test_ChaumPedersenExp.py
```
- To run authentication tests:
```
python test_auth.py
```
- To run client and server authentication system:

In a first console run:
```
python server_setup.py
``` 
In a second console run:
```
python client_setup.py
``` 
When prompted, input R for user registration, A for user authentication.
When prompted input user's name and password.


## Future upgrades
- Replace user dictionary on server by database.
- Generate group using GMP library instead of using toy example for Chaum-Pedersen ZKP.
- Secure client/server communications with TLS.
