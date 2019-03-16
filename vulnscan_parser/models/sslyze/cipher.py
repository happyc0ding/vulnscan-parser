from vulnscan_parser.models.vscipher import VSCipher


class SslyzeCipher(VSCipher):

    def __init__(self):
        super().__init__()
        self.hostname = ''

    @property
    def ip(self):
        return self.host.ip
