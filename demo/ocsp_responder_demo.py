from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
import openssl_ocsp_responder
import requests
from urlparse import urlparse

OCSP_CERT_FILENAME = "./ocsp_cert.pem"
OCSP_KEY_FILENAME = "./ocsp_key.pem"
PROXY_CERT_FILENAME = "./proxy_cert.pem"
ISSUER_CERT_FILENAME = "./intermediate_ca_cert.pem"

"""
API for getting OCSP response from a server, for given certificate and issuer certificate
"""


def _get_cert_from_file(certificate_path):
    """
    Load a certificate from a given PEM file path
    :param str certificate_path: path to certificate path
    :return: a cryptography.x509.Certificate
    """
    with open(certificate_path, 'rb') as cert_file:
        cert_str = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_str)
    return cert


def _get_ocsp_server(cert):
    """
    Retrieves the OCSP URI from a certificate
    :param x509.Certificate cert: The certificate to get the OCSP URI from
    :return: the OCSP URI string
    """
    aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    ocsps = [ia for ia in aia if ia.access_method == x509.oid.AuthorityInformationAccessOID.OCSP]
    if not ocsps:
        raise Exception('no ocsp server entry in AIA')
    return ocsps[0].access_location.value


def _get_ocsp_response_from_server(ocsp_server, cert, issuer_cert):
    builder = x509.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
    req = builder.build()
    data = req.public_bytes(serialization.Encoding.DER)
    headers = {
        'Host': urlparse(ocsp_server).netloc,
        'Content-Type': 'application/ocsp-request'
    }
    ocsp_resp = requests.post(url=ocsp_server, data=data, headers=headers)
    if ocsp_resp.ok:
        return ocsp_resp.content
    raise Exception('fetching ocsp cert response from responder failed with HTTP response status: {}'.format(ocsp_resp.status_code))


def get_cert_ocsp_response(cert_path, issuer_cert_path):
    """
    Gets an OCSP response for a given certificate
    Sends an OCSP request to a OCSP responder declared in the certificate and gets the response
    :param str cert_path: path to the relevant certificate PEM file
    :param str issuer_cert_path: path to the issuer's certificate PEM file
    :return: A DER encoded OCSP response
    :rtype: bytes
    """
    cert = _get_cert_from_file(cert_path)
    issuer_cert = _get_cert_from_file(issuer_cert_path)
    ocsp_server = _get_ocsp_server(cert)
    return _get_ocsp_response_from_server(ocsp_server, cert, issuer_cert)


def get_ocsp_response():
    response_der = get_cert_ocsp_response(PROXY_CERT_FILENAME, ISSUER_CERT_FILENAME)
    return x509.ocsp.load_der_ocsp_response(response_der)


def main():
    print("=== OCSP Responder Demo ===")

    # Initialize OCSP Responder
    print("Starting responder")
    responder = openssl_ocsp_responder.OCSPResponder("./", ISSUER_CERT_FILENAME, OCSP_CERT_FILENAME, OCSP_KEY_FILENAME,
                                                     port=11111, log_output_path="./out")
    print("Setting proxy certificate as VERIFIED")
    responder.set_verified_certificate(PROXY_CERT_FILENAME)
    responder.start_responder()

    # Get an OCSP response for the proxy certificate
    ocsp_response = get_ocsp_response()
    print("Certificate OCSP Status: {}".format(ocsp_response.certificate_status))
    assert(ocsp_response.certificate_status == x509.ocsp.OCSPCertStatus.GOOD)

    # Revoke the proxy cert
    print("Setting proxy certificate as REVOKED")
    responder.set_revoked_certificate(PROXY_CERT_FILENAME)
    responder.restart()

    # Check revoked status
    ocsp_response = get_ocsp_response()
    print("Certificate OCSP Status: {}, revocation time: {}".format(ocsp_response.certificate_status, ocsp_response.revocation_time))
    assert (ocsp_response.certificate_status == x509.ocsp.OCSPCertStatus.REVOKED)

    # Removing the certificate from CRL
    print("Removing certificate from CRL")
    responder.delete_certificate(PROXY_CERT_FILENAME)
    responder.restart()

    # Check revoked status
    ocsp_response = get_ocsp_response()
    print("Certificate OCSP Status: {}".format(ocsp_response.certificate_status))
    assert (ocsp_response.certificate_status == x509.ocsp.OCSPCertStatus.UNKNOWN)

    responder.stop_responder()


if __name__ == '__main__':
    main()
