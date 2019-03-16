from vulnscan_parser.models.vscipher import VSCipher


class NessusCipher(VSCipher):

    def __init__(self):
        super().__init__()
        self.key_size = -1
