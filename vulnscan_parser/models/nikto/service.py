from vulnscan_parser.models.vsservice import VSService


class NiktoService(VSService):

    def __init__(self):
        super().__init__()
        self.protocol = 'TCP'
        self.port = -1
        self.banner = ''
        self.finding = None

