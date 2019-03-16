from vulnscan_parser.models.vsbase import VSBaseModel


class VSCertificate(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.host = None
        self.protocol = ''
        self.port = -1
        self.hostname = ''

    @property
    def ip(self):
        return self.host.ip
