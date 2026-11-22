# -*- coding: utf-8 -*-
from __future__ import print_function
import string

def caesar(text, k):
    out = []
    for c in text:
        if c in string.ascii_lowercase:
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif c in string.ascii_uppercase:
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)

for k in range(26):
    print(k, caesar("synt{pnrfne}", k))
