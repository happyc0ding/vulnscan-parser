from vulnscan_parser.models.vsbase import VSBaseModel


class VSFinding(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.port = -1
        self.protocol = 'TCP'
        self.host = None
        self.hostname = ''
        self.src_file = ''

    @property
    def ip(self):
        return self.host.ip

    def __repr__(self):
        return f'{self.__class__.__name__}(ip={self.ip},port={self.port},protocol={self.protocol},' \
               f'hostname={self.hostname},src_file={self.src_file})'
