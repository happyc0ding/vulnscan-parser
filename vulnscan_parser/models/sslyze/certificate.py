from vulnscan_parser.models.vscertificate import VSCertificate


class SslyzeCertificate(VSCertificate):

    def __init__(self):
        super().__init__()
        self.hpkpSha256Pin = ''
        self.host = None
