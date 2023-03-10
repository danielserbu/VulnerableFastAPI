from functools import wraps
from .DatabaseUtils import return_user_rights
from .users import rightsDictList

# Create Input Parameter wrappers to validate user inputs in case of secure functions (future) and then decorate sql functions.

# Example
dangerous_stuff = ["OR", "AND", "=", "1==1", "'miau'=='miau'" ";", "--", " ", "&&", "||"]

def sql_generic_security_checks(func):
    @wraps(func)
    def wrapper(*args, **kw):
        if args[1].contains(dangerous_stuff):
            print('Dangerous characters inside input parameters.')
            raise Exception('Exception')

        res = func(*args, **kw)
        return res

    return wrapper

def is_user_allowed_to_run_function(func):
    @wraps(func)
    def wrapper(*args, **kw):
        userObj = args[1]
        userRights = return_user_rights(userObj.username)
        if args[1].username:
            print('Dangerous characters inside input parameters.')
            raise Exception('Exception')

        res = func(*args, **kw)
        return res

    return wrapper

# Other to do
# User rights decorator
# Basic Auth decorator

# Used to decorate all functions of a class.
# Not used yet.
def decorate_all_functions(function_decorator):
    def decorator(cls):
        for name, obj in vars(cls).items():
            if callable(obj):
                try:
                    obj = obj.__func__  # unwrap Python 2 unbound method
                except AttributeError:
                    pass  # not needed in Python 3
                setattr(cls, name, function_decorator(obj))
        return cls

    return decorator