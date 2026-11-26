"""导入全部工具模块，使其中的 @tool 登记生效。新增模块时在这里加一行。"""

from .encoding import base, legacy, morse, esolang, text, magic  # noqa: F401
from .crypto import caesar, railfence, substitution, vigenere, matrix, hashes  # noqa: F401
from .crypto import nt, rsa, symmetric, hashext, ecc  # noqa: F401
from .misc import py2check, flagsearch  # noqa: F401
