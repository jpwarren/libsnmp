# libsnmp
A pure Python SNMP library

## Overview

I wrote this library many years ago because I was frustrated by PySNMP and something else that
I can't recall, but that used an overly theoretical CompSci-type implementation of ASN.1 entities mapped
directed to a deep class hierarchy, which made it really slow.

The PySNMP project has now utterly eclipsed the functionality of libsnmp, so you probably want to use it instead.

The code is here mostly for historical reference, and so people who keep downloading it from PyPI for some
unknown reasons can fork and update the code if they so wish.

## Installation
libsnmp is available in PyPI, so you can just use:

```
pip install libsnmp
```
if you want. Or use:

```
python setup.py install
```

There are a bunch of example scripts in the main directory.
