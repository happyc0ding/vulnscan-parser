from vulnscan_parser.models.vscertificate import VSCertificate


class SslscanCertificate(VSCertificate):

    def __init__(self):
        super().__init__()
        self.altnames = []
        self.subject = {}
        self.host = None

    @property
    def ip(self):
        return self.host.ip
