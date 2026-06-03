import sys
import os

if sys.platform == 'win32':
    os.system('')


class C:
    RST = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'


def banner(text, char='='):
    line = char * 60
    print(f"\n{C.BOLD}{C.CYAN}{line}{C.RST}")
    print(f"{C.BOLD}{C.CYAN}  {text}{C.RST}")
    print(f"{C.BOLD}{C.CYAN}{line}{C.RST}\n")


def hdr(text):
    print(f"{C.BOLD}{C.BLUE}{text}{C.RST}")


def info(text):
    print(f"{C.CYAN}[INFO]{C.RST} {text}")


def ok(text):
    print(f"{C.GREEN}[ OK ]{C.RST} {text}")


def warn(text):
    print(f"{C.YELLOW}[WARN]{C.RST} {text}")


def err(text):
    print(f"{C.RED}[FAIL]{C.RST} {text}")


def field(label, value):
    print(f"       {C.DIM}{label:<14}{C.RST}{value}")


def step(actor, text, color=None):
    if color is None:
        color = C.WHITE
    print(f"  {color}{actor:>10}{C.RST} │ {text}")


def hex_dump(data, max_bytes=32, label=""):
    truncated = data[:max_bytes]
    hex_str = ' '.join(f"{b:02x}" for b in truncated)
    suffix = f" ... (всего {len(data)} байт)" if len(data) > max_bytes else ""
    if label:
        print(f"  {C.DIM}{label}:{C.RST} {hex_str}{suffix}")
    else:
        print(f"  {hex_str}{suffix}")
