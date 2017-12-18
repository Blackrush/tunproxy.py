import random


class Counter(object):
    def __init__(self, initial=None, mask=32):
        self._mask = (1 << mask) - 1
        self._value = int(initial or (random.random() * self._mask))

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        self._value = val & self._mask

    def get_inc(self, inc=1):
        res = self.value
        self.inc_get(inc=inc)
        return res

    def inc_get(self, inc=1):
        self.value += inc
        return self.value