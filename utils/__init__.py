import json
from decimal import Decimal


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return super(DecimalEncoder, self).default(obj)


def decimal_decoder(dct):
    for k, v in dct.items():
        if isinstance(v, str):
            try:
                dct[k] = Decimal(v)
            except:
                pass
    return dct


def btc_to_satoshis(btc_value):
    return int(Decimal(str(btc_value)) * Decimal('100000000'))
