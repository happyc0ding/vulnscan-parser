from vulnscan_parser.models.vscertificate import VSCertificate


class NmapCertificate(VSCertificate):

    def __init__(self):
        super().__init__()
        self.extensions = {}
        self.issuer = {}
        self.md5 = ''
        self.pem = ''
        self.pubkey = {}
        self.sha1 = ''
        self.sig_algo = ''
        self.subject = {}
        self.validity = {}
        self.host = None

    @property
    def ip(self):
        return self.host.ip
