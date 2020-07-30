import json
from collections import namedtuple


def dict_to_namedtuple(s):
    """Process dictionary to object-like form as namedtuple.

    Args: 
        s (dict)

    Returns:
        Namedtuple object, named "gib".
    """

    def change_keys(obj, convert):
        """Recursively goes through the dictionary obj and replaces keys with the convert function.

        Args:
            obj(any_iterable_type): 
            convert(func): function, that process keys to appropriate value.

        Returns:
            obj: with replaced symbols  
        """
        if isinstance(obj, (str, int, float)):
            return obj
        if isinstance(obj, dict):
            new = obj.__class__()
            for k, v in obj.items():
                new[convert(k)] = change_keys(v, convert)
        elif isinstance(obj, (list, set, tuple)):
            new = obj.__class__(change_keys(v, convert) for v in obj)
        else:
            return obj
        return new

    def replacement_func(obj_key):
        """Replaces bad symbols in keys to process them into namedtuples attribute names.
        """
        return obj_key.replace(":", "_").replace(" ", "_")

    #keys may contain unappropriate symbols in fieldnames.
    try:
        namedtupled_feed = json.loads(json.dumps(s), object_hook=lambda d: namedtuple('gib', d.keys())(*d.values()))
    except ValueError:
        s = change_keys(s, replacement_func)
        namedtupled_feed = json.loads(json.dumps(s), object_hook=lambda d: namedtuple('gib', d.keys())(*d.values()))
    return namedtupled_feed



def namedtuple_to_dict(obj):
    """Process namedtuple back to dictionary.

    Args:
        obj(namedtuple)

    Returns:
        dict

    """

    def _isnamedtupleinstance(x):
        _type = type(x)
        bases = _type.__bases__
        if len(bases) != 1 or bases[0] != tuple:
            return False
        fields = getattr(_type, '_fields', None)
        if not isinstance(fields, tuple):
            return False
        return all(type(i)==str for i in fields)


    if isinstance(obj, dict):
        return {key: namedtuple_to_dict(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [namedtuple_to_dict(value) for value in obj]
    elif _isnamedtupleinstance(obj):
        return {key: namedtuple_to_dict(value) for key, value in obj._asdict().items()}
    elif isinstance(obj, tuple):
        return tuple(namedtuple_to_dict(value) for value in obj)
    else:
        return obj


def find_attrs(sample, attrs):
    """Find attrs in json (won't work with lists), sep by '/'
    Args:
        sample: jsoned python dict
        attrs: list of attrs strings

    Returns:

    """
    def find_attr(s, attr):
        attr = attr.split("/", 1)
        if len(attr) == 1:
            return getattr(s, attr[0])
        else:
            return find_attr(getattr(s, attr[0]), attr[1])
    sample = dict_to_namedtuple(sample)

    ret = [find_attr(sample, i) for i in attrs]

    return ret
