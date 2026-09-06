# opensnoop

`opensnoop` is an eBPF tool that traces file-open attempts made by selected executables.

The loader reads an whitelist from `opensnoop.ini` and stores the executable names in a BPF hash map. The probe checks this map before logging an event, filtering unwanted noise.

Example configuration:
```
[opensnoop]
include=less
include=cat
include=python3
```

Example output:
```
less attempts to open /etc/ld.so.cache
cat attempts to open opensnoop.c
```

Currently, `opensnoop` traces only `openat` calls and reports attempts even when the file fails to open. Executables are matched by their Linux `comm` name, which is limited to 15 visible characters.
