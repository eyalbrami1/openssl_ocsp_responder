# OpenSSL OCSP Responder
## _A Python wrapper for OpenSSL OCSP responder server_

This is a basic and simple wrapper in Python for OpenSSL's command-line OCSP responder server

## Features

- Easily bring up the OCSP responder
- Add verified certificates for the responder to approve
- Revoke any certificate

## Tech

The API uses a few packages for its implementations:
- [PyOpenSSL](https://pypi.org/project/pyOpenSSL/) - A Python wrapper for OpenSSL's C API (Used for parsing certificates)

Additionally, it requires having OpenSSL installed on your machine


## Installation
### Getting it
To download openssl_ocsp_responder, either fork this github repo or simply use Pypi via pip

```$ pip install openssl_ocsp_responder```

### Using it
Simply import the package 


## License
MIT
