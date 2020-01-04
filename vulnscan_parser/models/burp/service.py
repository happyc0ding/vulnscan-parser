from vulnscan_parser.models.vsservice import VSService


class BurpService(VSService):

    def __init__(self):
        super().__init__()
        self.finding = None
        self.name = 'HTTP'

    @property
    def protocol(self):
        return self.finding.protocol

    @property
    def port(self):
        return self.finding.port
