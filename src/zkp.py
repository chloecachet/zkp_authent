import secrets

class ChaumPedersenExp:

    def __init__(self, g, h, q, p):
        self.g = g
        self.h = h
        self.q = q
        self.p = p

    def setup(self, x):
        return pow(self.g, x) % self.p, pow(self.h, x) % self.p

    def commitment(self):
        # generate random int
        k = secrets.randbelow(self.q)
        return pow(self.g, k) % self.p, pow(self.h, k) % self.p

    def challenge(self):
        # generate random challenge c
        c = secrets.randbelow(self.q)
        return c

    def prove(self, k, c, x):
        s = (k - c * x) % self.q
        return s

    def verify(self, y1, y2, r1, r2, c, s):
        res1 = (pow(self.g, s) * pow(y1, c)) % self.p
        res2 = (pow(self.h, s) * pow(y2, c)) % self.p

        if r1 == res1 and r2 == res2:
            return True
        else:
            return False
