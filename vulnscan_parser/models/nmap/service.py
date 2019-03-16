from vulnscan_parser.models.vsservice import VSService


class NmapService(VSService):

    def __init__(self):
        super().__init__()
        self.name = ''
        self.port = -1
        self.protocol = 'TCP'
        self.product = ''
        self.version = ''
        self.servicefp = ''
        self.tunnel = ''
        self.method = ''
        self.conf = 0
        self.state = ''

    @property
    def ip(self):
        return self.host.ip
