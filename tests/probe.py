import sys
print("sys.path[0]=", repr(sys.path[0]))
try:
    import keepkeylib
    print("OK", keepkeylib.__file__)
except ImportError as e:
    print("FAIL", e)
