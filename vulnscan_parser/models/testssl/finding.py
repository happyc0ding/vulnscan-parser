from vulnscan_parser.models.vsfinding import VSFinding


class TestsslFinding(VSFinding):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props.extend(['vulnerability', 'ports'])
        self.ignored_dict_props.remove('finding')
        self.vulnerability = None
        self._cwe = []
        self._cve = []
        self.finding = ''

    @property
    def cwe(self):
        if not self._cwe:
            return self.vulnerability.cwe
        return self._cwe

    @cwe.setter
    def cwe(self, value):
        if value != self.vulnerability.cwe:
            self._cwe = value

    @property
    def cve(self):
        if not self._cve:
            return self.vulnerability.cve
        return self._cve
    
    @cve.setter
    def cve(self, value):
        if value != self.vulnerability.cve:
            self._cve = value

    @property
    def name(self):
        return self.vulnerability.name

    def to_serializable_dict(self):
        result = self.vulnerability.to_serializable_dict()
        result.update(self.host.to_serializable_dict())
        result.update(super().to_serializable_dict())
        # remove unnecessary attrs
        result.pop('hostnames')

        return result
