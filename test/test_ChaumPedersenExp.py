import unittest
from src.zkp import ChaumPedersenExp

class ChaumPedersenExpTest(unittest.TestCase):

    # Testing with basic parameters, in reality numbers will be much bigger
    g = 4
    h = 9
    q = 11
    p = 23
    x = 6
    k = 7
    c = 4
    y1 = 2
    y2 = 3
    r1 = 8
    r2 = 4
    s = 5

    def test_setup(self):
        cp = ChaumPedersenExp(self.g, self.h, self.q, self.p)
        y1, y2 = cp.setup(self.x)
        self.assertEqual(y1, self.y1)
        self.assertEqual(y2, self.y2)

    def test_prove(self):
        cp = ChaumPedersenExp(self.g, self.h, self.q, self.p)
        s = cp.prove(self.k, self.c, self.x)
        self.assertEqual(s, self.s)

    def test_verify_success(self):
        cp = ChaumPedersenExp(self.g, self.h, self.q, self.p)
        res = cp.verify(self.y1, self.y2, self.r1, self.r2, self.c, self.s)
        self.assertEqual(res, True)

    # Testing verify function when 1st check fails
    def test_verify_fail_1(self):
        cp = ChaumPedersenExp(self.g, self.h, self.q, self.p)
        res = cp.verify(3, self.y2, self.r1, self.r2, self.c, self.s)
        self.assertEqual(res, False)

    # Testing verify function when 2nd check fails
    def test_verify_fail_2(self):
        cp = ChaumPedersenExp(self.g, self.h, self.q, self.p)
        res = cp.verify(self.y1, 2, self.r1, self.r2, self.c, self.s)
        self.assertEqual(res, False)


if __name__ == '__main__':
    unittest.main()
