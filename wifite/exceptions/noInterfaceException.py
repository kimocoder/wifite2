class NoInterfaceException(BaseException):
    """ Unable to find any usable wireless interface """
    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def __new__(*args, **kwargs):
        pass