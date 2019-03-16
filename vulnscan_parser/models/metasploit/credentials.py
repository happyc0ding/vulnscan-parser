from vulnscan_parser.models.vsbase import VSBaseModel


class MetasploitCredentials(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.username = ''
        self.password = ''
        self.jtr_format = ''
        self.realm = ()
        self.origin = ''
