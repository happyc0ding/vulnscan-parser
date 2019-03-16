from vulnscan_parser.models.vshost import VSHost


# host class
class SslscanHost(VSHost):

    def __init__(self):
        super().__init__()

    @property
    def ports(self):
        return [x.port for x in self.services]

