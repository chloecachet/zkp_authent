import secrets

class ChaumPedersenExp:

    def __init__(self, g=4, h=9, q=11, p=23):
        self.g = g
        self.h = h
        self.q = q
        self.p = p

    def setup(self, x):
        """
        Chaum-Pedersen ZKP setup function.
        Generates y1 = g^x and y2 = h^x.
        @param x: ZKP input value (int). Will be user's password during authentication.
        @rtype: int, int
        """
        return pow(self.g, x) % self.p, pow(self.h, x) % self.p

    def commitment(self):
        """
        Chaum-Pedersen ZKP commitment function.
        Generates random value k and corresponding commitments r1 = g^k and r2 = h^k.
        @rtype: int, int, int
        """
        # generate random int
        k = secrets.randbelow(self.q)
        return k, pow(self.g, k) % self.p, pow(self.h, k) % self.p

    def challenge(self):
        """
        Chaum-Pedersen ZKP challenge generation function.
        Generates random value c.
        @rtype: int
        """
        # generate random challenge c
        c = secrets.randbelow(self.q)
        return c

    def prove(self, k, c, x):
        """
        Chaum-Pedersen ZKP prove function.
        Generates s = k - cx.
        @param k: ZKP commitment input (int). Will be user's commitment during authentication.
        @param c: ZKP input value (int). Will be user's password during authentication.
        @param x: ZKP challenge (int). Will be server's challenge during authentication.
        @rtype: int
        """
        s = (k - c * x) % self.q
        return s

    def verify(self, y1, y2, r1, r2, c, s):
        """
        Chaum-Pedersen ZKP verify function.
        Generates res1 = g^x and res2 = h^x and verifies that res1 = r1 and res2 = r2.
        @param y1: ZKP public value 1 (int). Will be stored on server for authentication.
        @param y2: ZKP public value 2 (int). Will be stored on server for authentication.
        @param r1: ZKP prover's commitment 1 (int).
        @param r2: ZKP prover's commitment 2 (int).
        @param c: ZKP verifier challenge (int).
        @param s: ZKP verifier witness (int).
        @rtype: Boolean
        """
        res1 = (pow(self.g, s) * pow(y1, c)) % self.p
        res2 = (pow(self.h, s) * pow(y2, c)) % self.p

        if r1 == res1 and r2 == res2:
            return True
        else:
            return False
