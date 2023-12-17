"""
This module provides a wrapper for the optimized_bn128 module.
It also provides a wrapper for the optimized_bn128 module's G1 and G2 points.
"""
from py_ecc.optimized_bn128 import (
    add,
    multiply,
    G1,
    G2,
    neg,
    pairing,
    eq,
    normalize,
    FQ,
    FQ2,
    curve_order,
    is_on_curve,
)

__all__ = [
    "GPoint",
    "generator1",
    "generator2",
    "validate_point",
    "normalize",
    "curve_order",
    "SRS"
]


class GPoint(tuple):

    """ 
    A point on the BN128 curve. 
    This class is a wrapper G1 and G2 points to provide a more intuitive
    interface. For example, instead of writing `multiply(G1, 5)` you can
    write `G1 * 5` or `5 * G1`. Similarly, instead of writing `add(G1, G2)`
    you can write `G1 + G2`.
    """

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

    def pair(self, other):
        """ Pairing function. """

        return pairing(self, other)


def generator1():
    """ Generator for G1. """
    return GPoint(*G1)


def generator2():
    """ Generator for G2. """
    return GPoint(*G2)


def validate_point(pt):
    """
    Check if a point is on the curve.
    Used in Plonk's verifier. Weak curve attack mitigation.
    """
    if isinstance(pt[0], FQ):
        assert is_on_curve(pt, FQ(3))
    elif isinstance(pt[0], FQ2):
        assert is_on_curve(pt, FQ2([3, 0]) / FQ2([9, 1]))
    else:
        raise Exception("Invalid point")


class SRS:
    """Trusted Setup Class aka Structured Reference String"""
    def __init__(self, tau, n = 2):
        self.tau = tau
        g1 = generator1()
        g2 = generator2()
        self.tau1 = [g1 * int(tau)**i for i in range(0, n + 7)]
        self.tau2 = g2 * int(tau)

    def __str__(self):
        s = f"tau: {self.tau}\n"
        s += "".join([f"[tau^{i}]G1: {str(normalize(point))}\n" for i, point in enumerate(self.tau1)])
        s += f"[tau]G2: {str(normalize(self.tau2))}\n"
        return s