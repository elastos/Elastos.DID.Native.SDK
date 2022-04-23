import os
import platform
from cffi import FFI

# Work around on MacOS
if (platform.system() == "Darwin"):
    os.environ['ARCHFLAGS'] = '-arch x86_64'
    link_args = ['-framework', 'Security']
else:
    link_args = []

ffibuilder = FFI()

with open("ela_did.ffi.h") as f:
    cdef = f.read()

with open("ela_jwt.ffi.h") as f:
    cdef += f.read()

ffibuilder.cdef(cdef)

ffibuilder.set_source("eladid",
"""
    #define DID_DYNAMIC
    #define DID_BUILD
    #include "ela_did.h"
    #include "ela_jwt.h"
""",
    libraries=['eladid', 'hdkey', 'curl', 'ssl', 'crypto', 'jansson', 'cjose', 'zip', 'z'],
    extra_link_args=link_args,
    include_dirs=['include'],
    library_dirs=['lib'])

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
