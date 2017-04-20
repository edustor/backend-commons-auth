import threading


class Auth():
    def __init__(self):
        self._storage = threading.local()

    @property
    def account_id(self):
        return self._storage.account_id

    @account_id.setter
    def account_id(self, value):
        self._storage.account_id = value


auth = Auth()
