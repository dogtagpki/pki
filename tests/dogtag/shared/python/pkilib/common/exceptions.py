"""
    Provide Exceptions for py.test framework
"""
class StandardException(Exception):
    """ Overrides Exception class """
    def __init__(self, msg='', rval=1):
        if msg is None:
            msg = ''
        self.msg = msg
        self.rval = rval
    def __str__(self):
        return (self.msg, self.rval)

class InvalidInput(StandardException):
    """ 
    Override StandardException used mainly when invalid input is passed 
    """
    pass

class DirSrvException(StandardException):
    """
    Override StandardException, This exception s to be used for Directory Server related Errors
    """
    pass

class PkiLibException(StandardException):
    """
    Override StandardException , This exception is to be used for Dogtag/CS related Errors
    """
    pass

class OSException(StandardException):
    """
    Override StandardException, This exception is to be used for Operating system errors.
    """
    pass

