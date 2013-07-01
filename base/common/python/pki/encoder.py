import json
import pki.system

TYPES = {}
NOTYPES = {}

class CustomTypeEncoder(json.JSONEncoder):
    """A custom JSONEncoder class that knows how to encode core custom
    objects.

    Custom objects are encoded as JSON object literals (ie, dicts) with
    one key, 'TypeName' where 'TypeName' is the actual name of the
    type to which the object belongs.  That single key maps to another
    object literal which is just the __dict__ of the object encoded."""

    def default(self, obj):
        for k, v in TYPES.items():
            if isinstance(obj, v):
                return {k: obj.__dict__}
        for k, v in NOTYPES.items():
            if isinstance(obj, v):
                return obj.__dict__
        return json.JSONEncoder.default(self, obj)


def CustomTypeDecoder(dct):
    if len(dct) == 1:
        type_name, value = dct.items()[0]
        if type_name in TYPES:
            return TYPES[type_name].from_dict(value)
    return dct
