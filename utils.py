from py_ecc.optimized_bn128 import add, multiply, G1, G2, neg, pairing, eq, normalize, FQ, FQ2, curve_order, is_on_curve


class GPoint(tuple):
    def __new__(cls, x, y, z):
        return tuple.__new__(cls, (x, y, z))

    def __str__(self):
        return f"({self[0]}, {self[1]}, {self[2]})"

    def __add__(self, other):
        return GPoint(*add(self, other))

    def __iadd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        return GPoint(*add(self, neg(other)))

    def __isub__(self, other):
        return self.__sub__(other)

    def __mul__(self, other):
        return GPoint(*multiply(self, int(other)))

    def __rmul__(self, other):
        return self.__mul__(other)

    def __neg__(self):
        return GPoint(*neg(self))

    def __eq__(self, other):
        return eq(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def pairing(self, other):
        return pairing(self, other)


def generator1():
    return GPoint(*G1)

def generator2():
    return GPoint(*G2)

def validate_point(pt):
    if isinstance(pt[0], FQ):
        assert is_on_curve(pt, FQ(3))
    elif isinstance(pt[0], FQ2):
        assert is_on_curve(pt, FQ2([3, 0]) / FQ2([9, 1]))
    else:
        raise Exception("Invalid point")
