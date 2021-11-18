import datetime
import os.path
import subprocess
import OpenSSL.crypto

CRL_FILE_NAME = "db.crl"
ATTRIBUTE_FILE_SUFFIX = ".attr"


class OCSPResponderException(Exception):
    pass


class OCSPResponder(object):
    """
    This object wraps OpenSSL's basic OCSP responder, and supplies an API to control it
    Please make sure that the OCSP key and certificate match, and that the certificate is issued and signed
    by the CA that the responder is supposed to approve certificates for.
    The responder will only be able to approve certificates issued by the CA
    """
    def __init__(self, crl_dir, ca_certificate_path, ocsp_certificate_path,
                 ocsp_key_path, start_responder=False, port='9999', log_output_path=None):
        """
        Initializes the responder
        :param str crl_dir: The path to the directory to write the CRL file in.
        :param str ca_certificate_path: Path to the certificate PEM file for the CA that issued the certificates the
         responder has to approve
        :param str ocsp_certificate_path: Path to the OCSP Responder's certificate PEM file
        :param str ocsp_key_path: Path to the OCSP Responder's private key file
        :param bool start_responder: Should the responder start upon initialization
        :param str port: Port the responder should listen to
        :param str log_output_path: absolute path to an output file for the responder
        """
        if any(arg is None for arg in [ca_certificate_path, ocsp_certificate_path, ocsp_key_path]):
            raise OCSPResponderException("All certificates must be supplied")
        self.ca_certificate_path = ca_certificate_path
        self.ocsp_certificate_path = ocsp_certificate_path
        self.ocsp_key_path = ocsp_key_path
        self.crl_dir = crl_dir
        self.responder_process = None
        self.ocsp_port = port
        self.crl_file_path = os.path.join(crl_dir, CRL_FILE_NAME)
        self.crl = {}
        self.log_path = log_output_path

    def __del__(self):
        self.stop_responder()
        self.delete_crl_file()

    def start_responder(self):
        """
        Starts the OCSP Responder
        Syntax of shell command:
        openssl ocsp -index <CRL file> -port <port> -rsigner <responder certificate file> -rkey <responder private key file> -CA <ca certificate file>
        """
        if self.is_alive():
            raise OCSPResponderException("Responder already running")

        self.write_crl()
        args = ['openssl', 'ocsp',
                '-index', self.crl_file_path,
                '-port', self.ocsp_port,
                '-rsigner', self.ocsp_certificate_path,
                '-rkey', self.ocsp_key_path,
                '-CA', self.ca_certificate_path]
        if self.log_path is not None:
            args += ['-text', '-out', self.log_path]

        self.responder_process = subprocess.Popen(args=args,
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT)

    def is_alive(self):
        if self.responder_process is not None:
            return True if self.responder_process.poll() is None else False
        return False

    def stop_responder(self):
        if self.is_alive():
            self.responder_process.terminate()
            self.responder_process.wait()

    def restart(self):
        self.stop_responder()
        self.start_responder()

    def delete_crl_file(self):
        if os.path.exists(self.crl_file_path):
            os.remove(self.crl_file_path)
        if os.path.exists(self.crl_file_path + ATTRIBUTE_FILE_SUFFIX):
            os.remove(self.crl_file_path + ATTRIBUTE_FILE_SUFFIX)

    def write_crl(self):
        """
        Creates the CRL file for the OpenSSL OCSP Responder
        """
        self.delete_crl_file()
        with open(self.crl_file_path, 'w') as crl_file:
            for cert in self.crl.values():
                crl_file.write("{}\t{}\t{}\t{}\t{}\t{}\n".format(cert['status'],
                                                                      cert['expiration_time'],
                                                                      cert['revocation_time'],
                                                                      cert['serial_number'],
                                                                      'unknown',
                                                                      cert['subject']))

        with open(self.crl_file_path + ATTRIBUTE_FILE_SUFFIX, 'w') as attribute_file:
            attribute_file.write("unique_subject = no")

    def _add_certificate(self, certificate_path):
        """
        Parses a certificate file to an internal entry in the CRL
        :param str certificate_path: path to the certificate file
        :return: The certificate's serial number (used as a key for CRL entries)
        :rtype: int
        """
        with open(certificate_path, 'rt') as certificate_file:
            certificate_str = certificate_file.read()

        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_str)
        serial_number = certificate.get_serial_number()
        subject = certificate.get_subject()
        subject_str = "".join("/{}={}".format(name.decode(), value.decode()) for name, value in subject.get_components())
        cert_entry = {'serial_number': format(serial_number, 'x'),
                      'expiration_time': certificate.get_notAfter().decode("utf-8")[2:],
                      'revocation_time': '',
                      'subject': subject_str}

        self.crl[serial_number] = cert_entry
        return serial_number

    def set_verified_certificate(self, certificate_path):
        """
        Adds a certificate to the CRL as "Verified"
        :param str certificate_path: path to a PEM certificate file
        """
        serial_number = self._add_certificate(certificate_path)
        self.crl[serial_number]['status'] = 'V'

    def set_revoked_certificate(self, certificate_path, revocation_time=None):
        """
        Adds a certificate to the CRL as "Revoked"
        :param str certificate_path: path to a PEM certificate file
        :param revocation_time: timestamp of the revocation of the certificate (datetime object)
        :type revocation_time: datetime or None for the current time
        """
        serial_number = self._add_certificate(certificate_path)
        self.crl[serial_number]['status'] = 'R'

        if revocation_time is None:
            revocation_time = datetime.datetime.utcnow()
        revocation_time_str = revocation_time.strftime("%y%m%d%H%M%S") + "Z"
        self.crl[serial_number]['revocation_time'] = revocation_time_str

    def delete_certificate(self, certificate_path):
        """
        Removes a certificate from the CRL
        :param certificate_path: path to a PEM certificate file
        """
        serial_number = self._add_certificate(certificate_path)
        self.crl.pop(serial_number, None)
