from vulnscan_parser.models.vsservice import VSService


class MetasploitService(VSService):

    def __init__(self):
        super().__init__()
        self.name = ''
        self.port = -1
        self.protocol = ''
        self.info = ''

    @property
    def proto(self):
        return self.protocol

    @proto.setter
    def proto(self, value):
        self.protocol = value
