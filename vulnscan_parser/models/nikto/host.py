from vulnscan_parser.models.vshost import VSHost


class NiktoHost(VSHost):

    def __init__(self):
        super().__init__()
        del self.certificates
