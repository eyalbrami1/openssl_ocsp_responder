import datetime
import os.path
import subprocess
import OpenSSL.crypto


class OCSPResponderException(Exception):
    pass


class OCSPResponder(object):
    """
    This object wraps OpenSSL's basic OCSP responder, and supplies an API to control it
    """
    def __init__(self, crl_dir, ca_certificate_path, ocsp_certificate_path,
                 ocsp_key_path, start_responder=False, port='9999', log_output_path=None):
        """
        Initializes the responder
        Args:
            crl_dir (str, optional): The path to the directory to write the CRL file in.
            ca_certificate_path (str): Path to the CA certificate file corresponding to the revocation info
            ocsp_certificate_path (str): Path to the OCSP Responder's certificate file
            ocsp_key_path (str): Path to the OCSP Responder's private key file
            start_responder (bool, optional): Should the responder start upon initialization
            port (int, optional): Port the responder should listen to
            log_output_path (str, optional): absolute path to an output file for the responder
        """
        if any(arg is None for arg in [ca_certificate_path, ocsp_certificate_path, ocsp_key_path]):
            raise OCSPResponderException("All certificates must be supplied")
        self.ca_certificate_path = ca_certificate_path
        self.ocsp_certificate_path = ocsp_certificate_path
        self.ocsp_key_path = ocsp_key_path
        self.crl_dir = crl_dir
        self.responder_process = None
        self.ocsp_port = port
        self.crl_file_path = os.path.join(crl_dir, "db.crl")
        self.crl_file = None
        self.crl = {}
        self.log_path = log_output_path

    def start_responder(self):
        """
        Starts the OCSP Responder
        Syntax of shell command:
        openssl ocsp -index <CRL file> -port <port> -rsigner <responder certificate file> -rkey <responder private key file> -CA <ca certificate file>
        """
        self.write_crl()
        args = ['openssl', 'ocsp',
                '-index', self.crl_file_path,
                '-port', self.ocsp_port,
                '-rsigner', self.ocsp_certificate_path,
                '-rkey', self.ocsp_key_path,
                '-CA', self.ca_certificate_path]
        if self.log_path is not None:
            args.append('-text')
            args.append('-out')
            args.append(self.log_path)
        self.responder_process = subprocess.Popen(args=args,
                                                  stdout=subprocess.DEVNULL,
                                                  stderr=subprocess.STDOUT)

    def is_alive(self):
        return True if self.responder_process.poll() is None else False

    def stop_responder(self):
        if self.is_alive():
            self.responder_process.terminate()
            self.responder_process.wait()

    def update(self):
        self.stop_responder()
        self.start_responder()

    def write_crl(self):
        """
        Creates the CRL file for the OpenSSL OCSP Responder
        """
        self.crl_file = open(self.crl_file_path, 'w')
        for cert in self.crl.values():
            self.crl_file.write("{}\t{}\t{}\t{}\t{}\t{}\n".format(cert['status'],
                                                                  cert['expiration'],
                                                                  cert['revocation'],
                                                                  cert['serial_number'],
                                                                  'unknown',
                                                                  cert['subject']))
        self.crl_file.close()

        attribute_file_path = os.path.join(self.crl_file_path, ".attr")
        attribute_file = open(self.crl_file_path + ".attr", 'w')
        attribute_file.write("unique_subject = no")
        attribute_file.close()

    def _add_certificate(self, certificate_path):
        """
        Parses a certificate file to an internal entry in the CRL
        :param certificate_path: path to the certificate file
        """
        certificate_str = open(certificate_path, 'rt').read()
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_str)
        serial_number = certificate.get_serial_number()
        subject = certificate.get_subject()
        subject_str = "".join("/{}={}".format(name.decode(), value.decode()) for name, value in subject.get_components())
        cert_entry = {'serial_number': format(serial_number, 'x'),
                      'expiration': certificate.get_notAfter().decode("utf-8")[2:],
                      'revocation': '',
                      'subject': subject_str}

        self.crl[serial_number] = cert_entry
        return serial_number

    def set_verified_certificate(self, certificate_path):
        """
        Adds a certificate to the CRL as "Verified"
        :param certificate_path: path to a PEM certificate file
        """
        serial_number = self._add_certificate(certificate_path)
        self.crl[serial_number]['status'] = 'V'

    def set_revoked_certificate(self, certificate_path, revocation_time=None):
        """
        Adds a certificate to the CRL as "Revoked"
        :param certificate_path: path to a PEM certificate file
        :param revocation_time: timestamp of the revocation of the certificate (datetime object)
        """
        serial_number = self._add_certificate(certificate_path)
        self.crl[serial_number]['status'] = 'R'

        if revocation_time is None:
            revocation_time = datetime.datetime.utcnow()
        revocation_time_str = revocation_time.strftime("%y%m%d%H%M%S") + "Z"
        self.crl[serial_number]['revocation'] = revocation_time_str

    def delete_certificate(self, certificate_path):
        """
        Removes a certificate from the CRL
        :param certificate_path: path to a PEM certificate file
        """
        self.crl.pop(certificate_path, None)
