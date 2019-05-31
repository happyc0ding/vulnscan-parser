

# https://stackoverflow.com/questions/3797957/python-easily-access-deeply-nested-dict-get-and-set
class DotDict(dict):

    def __init__(self, value=None):
        super().__init__()
        self.update(value)

    def update(self, value, **kwargs):
        if value is not None:
            if isinstance(value, dict):
                for key in value:
                    self.__setitem__(key, value[key])
            else:
                raise TypeError('expected dict')

    def __setitem__(self, key, value):
        if '.' in key:
            my_key, rest_of_key = key.split('.', 1)
            target = self.setdefault(my_key, DotDict())
            if not isinstance(target, DotDict):
                raise KeyError('cannot set "{}" in "{}" ({})'.format(rest_of_key, my_key, repr(target)))
            target[rest_of_key] = value
        else:
            if isinstance(value, dict) and not isinstance(value, DotDict):
                value = DotDict(value)
            super().__setitem__(key, value)

    def __getitem__(self, key):
        if '.' not in key:
            return super().__getitem__(key)
        my_key, rest_of_key = key.split('.', 1)
        target = super().__getitem__(my_key)
        if not isinstance(target, DotDict):
            raise KeyError('cannot get "{}" in "{}" ({})'.format(rest_of_key, my_key, repr(target)))
        return target[rest_of_key]

    def __contains__(self, key):
        if '.' not in key:
            return super().__contains__(key)
        my_key, rest_of_key = key.split('.', 1)
        target = super().__getitem__(my_key)
        if not isinstance(target, DotDict):
            return False
        return rest_of_key in target

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

    __setattr__ = __setitem__
    __getattr__ = __getitem__
