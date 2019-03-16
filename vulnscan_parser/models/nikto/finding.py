from vulnscan_parser.models.vsfinding import VSFinding


class NiktoFinding(VSFinding):

    def __init__(self):
        super().__init__()
        self.description = ''
        self.uri = ''
        self.namelink = ''
        self.iplink = ''
        self.vulnerability = None
        self.src_file = ''
