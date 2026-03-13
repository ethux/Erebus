import sys

_NO_COLOR = not sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def green(t):  return _c("32", t)
def red(t):    return _c("31", t)
def yellow(t): return _c("33", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)

ok   = lambda t: green(f"  [+] {t}")
fail = lambda t: red(f"  [-] {t}")
warn = lambda t: yellow(f"  [!] {t}")
info = lambda t: cyan(f"  [>] {t}")
dl   = lambda t: cyan(f"  [~] {t}")
