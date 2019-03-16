from vulnscan_parser.models.vsservice import VSService


class TestsslService(VSService):

    def __init__(self):
        super().__init__()
        self.name = ''
        self.port = -1
        self.protocol = 'TCP'
