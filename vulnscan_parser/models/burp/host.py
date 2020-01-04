from vulnscan_parser.models.vshost import VSHost


class BurpHost(VSHost):

    def __init__(self):
        super().__init__()
        # remove unnecessary attrs
        del self.certificates
        del self.services
