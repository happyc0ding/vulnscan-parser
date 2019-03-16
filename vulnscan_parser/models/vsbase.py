
class VSBaseModel:

    IGNORED_DICT_PROPS = [
        'ignored_dict_props',
        'plugin',
        'plugins',
        'host',
        'hosts',
        'finding',
        'findings',
        'services',
        'vulnerability',
        'vulnerabilities'
    ]

    def __init__(self):
        self.id = ''
        self.ignored_dict_props = self.IGNORED_DICT_PROPS.copy()

    def to_dict(self):
        return {k: getattr(self, k) for k in dir(self) if not k.startswith('_') and not callable(getattr(self, k))}

    def to_serializable_dict(self):
        # res = {}
        # for k, v in self.to_dict().items():
        #     if isinstance(v, VSBaseModel):
        #         continue
        #     elif isinstance(v, (list, tuple, set)):
        #         try:
        #             elm = next(iter(v))
        #             if isinstance(elm, VSBaseModel):
        #                 continue
        #         except StopIteration:
        #             pass
        #     res[k] = v
        # return res
        return {k: v for k, v in self.to_dict().items() if k.lower() not in self.ignored_dict_props}
