import logging
import hashlib
from itertools import islice


LOGGER = logging.getLogger(__name__)


class VSBaseParser(object):

    HASH_BUFFER_SIZE = 8192

    def __init__(self):
        super().__init__()
        self._curr_filename = ''
        self._curr_file_hash = ''
        # set this flag if you want to ignore duplicate findings
        self.add_duplicates = True

    def _save_to_result_dict(self, result_dict, _object):
        is_saved = False
        if self.add_duplicates:
            # add file hash to id, ignore this kind of duplicate (parsing the exact same file twice)
            if not _object.id.endswith(self._curr_file_hash):
                _object.id = self.create_uid(_object.id)
        try:
            # do not overwrite existing results
            result_dict[_object.id]
        except KeyError:
            # save to list
            result_dict[_object.id] = _object
            is_saved = True

        return is_saved

    @staticmethod
    def hash_sha1(data):
        hashsum = hashlib.sha1()
        hashsum.update(data)

        return hashsum.hexdigest()

    def hash_file(self, filepath):
        hashsum = hashlib.sha1()
        with open(filepath, 'rb') as the_file:
            data = the_file.read(self.HASH_BUFFER_SIZE)
            while data:
                hashsum.update(data)
                data = the_file.read(self.HASH_BUFFER_SIZE)
        return hashsum.hexdigest()

    def clear(self):
        raise NotImplemented()

    def create_uid(self, _id):
        return '{}-{}'.format(_id, self._curr_file_hash)

    @staticmethod
    def get_file_head(filepath, num_of_lines):
        head = None
        try:
            with open(filepath, 'r') as file_handle:
                head = list(islice(file_handle, num_of_lines))
        except Exception:
            pass

        return head

    @staticmethod
    def is_valid_file(file):
        return True
