from vulnscan_parser.models.vsfinding import VSFinding


class BurpFinding(VSFinding):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props = ['host']
        self.serialNumber = ''
        self.type = ''
        self.name = ''
        self.path = ''
        self.location = ''
        self.severity = ''
        self.confidence = ''
        self.issueBackground = ''
        self.remediationBackground = ''
        self.references = []
        self.vulnerabilityClassifications = []
        self.requestresponse = {
            'request_method': '',
            'request': '',
            'response': '',
            'responseRedirected': False,
        }
