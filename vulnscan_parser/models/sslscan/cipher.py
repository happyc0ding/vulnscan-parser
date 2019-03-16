from vulnscan_parser.models.vscipher import VSCipher


class SslscanCipher(VSCipher):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props.append('keyExchange')
        self.port = -1
        self.protocol = 'TCP'
        self.hostname = ''

