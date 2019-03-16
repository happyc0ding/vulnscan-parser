from vulnscan_parser.models.vsbase import VSBaseModel


class VSService(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.host = None
        self.src_file = ''

    @property
    def ip(self):
        return self.host.ip
