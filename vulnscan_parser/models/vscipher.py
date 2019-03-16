from vulnscan_parser.models.vsbase import VSBaseModel


class VSCipher(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.host = None
        self.name = ''
        self.tls_protocol = ''
        self.port = -1
        self.protocol = 'TCP'
        self.hostname = ''
        self.src_file = ''

    @property
    def ip(self):
        return self.host.ip
