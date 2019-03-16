from vulnscan_parser.models.vsfinding import VSFinding


class NmapFinding(VSFinding):

    def __init__(self):
        super().__init__()
        self.name = ''
        self.data = {}
