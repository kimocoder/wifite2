class NoInterfaceException(object):
    """ Common base class for all exceptions """
    def with_traceback(self, tb): # real signature unknown; restored from __doc__
        """
        Exception.with_traceback(tb) --
            set self.__traceback__ to tb and return self.
        """
        pass

    def __delattr__(self, *args, **kwargs): # real signature unknown
        """ Implement delattr(self, name). """
        pass

    def __getattribute__(self, *args, **kwargs): # real signature unknown
        """ Return getattr(self, name). """
        pass

    def __init__(self, *args, **kwargs): # real signature unknown
        pass

    @staticmethod # known case of __new__
    def __new__(*args, **kwargs): # real signature unknown
        """ Create and return a new object.  See help(type) for accurate signature. """
        pass

    def __reduce__(self, *args, **kwargs): # real signature unknown
        pass

    def __repr__(self, *args, **kwargs): # real signature unknown
        """ Return repr(self). """
        pass

    def __setattr__(self, *args, **kwargs): # real signature unknown
        """ Implement setattr(self, name, value). """
        pass

    def __setstate__(self, *args, **kwargs): # real signature unknown
        pass

    def __str__(self, *args, **kwargs): # real signature unknown
        """ Return str(self). """
        pass

    args = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    __cause__ = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default
    """exception cause"""

    __context__ = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default
    """exception context"""

    __suppress_context__ = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    __traceback__ = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default


    __dict__ = None # (!) real value is "mappingproxy({'__repr__': <slot wrapper '__repr__' of 'BaseException' objects>, '__str__': <slot wrapper '__str__' of 'BaseException' objects>, '__getattribute__': <slot wrapper '__getattribute__' of 'BaseException' objects>, '__setattr__': <slot wrapper '__setattr__' of 'BaseException' objects>, '__delattr__': <slot wrapper '__delattr__' of 'BaseException' objects>, '__init__': <slot wrapper '__init__' of 'BaseException' objects>, '__new__': <built-in method __new__ of type object at 0x00007FFE9BD74F50>, '__reduce__': <method '__reduce__' of 'BaseException' objects>, '__setstate__': <method '__setstate__' of 'BaseException' objects>, 'with_traceback': <method 'with_traceback' of 'BaseException' objects>, '__suppress_context__': <member '__suppress_context__' of 'BaseException' objects>, '__dict__': <attribute '__dict__' of 'BaseException' objects>, 'args': <attribute 'args' of 'BaseException' objects>, '__traceback__': <attribute '__traceback__' of 'BaseException' objects>, '__context__': <attribute '__context__' of 'BaseException' objects>, '__cause__': <attribute '__cause__' of 'BaseException' objects>, '__doc__': 'Common base class for all exceptions'})"