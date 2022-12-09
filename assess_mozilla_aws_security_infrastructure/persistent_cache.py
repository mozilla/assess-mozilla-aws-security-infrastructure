import shelve
import functools
from pathlib import Path
from xdg import xdg_cache_home

MEMOIZE_FILENAME = Path(xdg_cache_home(), 'aws-account-audit-cache.shelve')


class _HashedSeq(list):
    """ This class guarantees that hash() will be called no more than once
        per element.  This is important because the lru_cache() will hash
        the key multiple times on a cache miss.
    """

    __slots__ = 'hashvalue'

    def __init__(self, tup, hash=hash):
        self[:] = tup
        self.hashvalue = hash(tup)

    def __hash__(self):
        return self.hashvalue


def functools_make_key(args, kwds, typed,
             kwd_mark = (object(),),
             fasttypes = {int, str},
             tuple=tuple, type=type, len=len):
    """Make a cache key from optionally typed positional and keyword arguments
    The key is constructed in a way that is flat as possible rather than
    as a nested structure that would take more memory.
    If there is only a single argument and its data type is known to cache
    its hash value, then that argument is returned without a wrapper.  This
    saves space and improves lookup speed.
    """
    # All of code below relies on kwds preserving the order input by the user.
    # Formerly, we sorted() the kwds before looping.  The new way is *much*
    # faster; however, it means that f(x=1, y=2) will now be treated as a
    # distinct call from f(y=2, x=1) which will be cached separately.
    key = args
    if kwds:
        key += kwd_mark
        for item in kwds.items():
            key += item
    if typed:
        key += tuple(type(v) for v in args)
        if kwds:
            key += tuple(type(v) for v in kwds.values())
    elif len(key) == 1 and type(key[0]) in fasttypes:
        return key[0]
    return _HashedSeq(key)


def cache(should_bypass_cache_func=None):
    # https://stackoverflow.com/q/24939403/168874
    if should_bypass_cache_func is None:
        should_bypass_cache_func = lambda x: False
    def decorating_function(user_function):
        def wrapper(*args, **kwds):
            key = str(functools_make_key(args, kwds, typed=False))
            with shelve.open(str(MEMOIZE_FILENAME), writeback=True) as cache:
                if key not in cache or should_bypass_cache_func(cache[key]):
                    print('not using cache')
                    result = user_function(*args, **kwds)
                    cache[key] = result
                    return result
                print('using cache')
                return cache[key]
        return functools.update_wrapper(wrapper, user_function)
    return decorating_function