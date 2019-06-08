from vulnscan_parser.models.vsfinding import VSFinding


class NessusFinding(VSFinding):

    def __init__(self):
        super().__init__()
        self.plugin = None
        self.svc_name = ''
        # self.solution = ''
        self.plugin_output = ''
        self.risk_factor = ''
        self.severity = 0
        self._description = ''

    @property
    def description(self):
        if self._description:
            return self._description
        return self.plugin.description

    @description.setter
    def description(self, desc):
        if desc != self.plugin.description:
            self._description = desc

    def to_serializable_dict(self):
        result = self.plugin.to_serializable_dict()
        result.update(self.host.to_serializable_dict())
        result.update(super().to_serializable_dict())
        result.pop('hostnames')
        try:
            result['hostname'] = self.host.host_fqdn
        except AttributeError:
            pass

        return result
