"""导入全部工具模块，使其中的 @tool 登记生效。新增模块时在这里加一行。"""

from .encoding import base, legacy, morse, esolang, text, magic  # noqa: F401
from .crypto import caesar, railfence, substitution, vigenere, matrix, hashes  # noqa: F401
from .crypto import nt, rsa, symmetric, hashext, ecc  # noqa: F401
from .forensics import files, archive, pcap  # noqa: F401
from .stego import image as stego_image, text as stego_text  # noqa: F401
from .web import tools as web_tools  # noqa: F401
from .reverse import tools as reverse_tools  # noqa: F401
from .pwn import tools as pwn_tools  # noqa: F401
from .ics import tools as ics_tools  # noqa: F401
from .misc import py2check, flagsearch  # noqa: F401
