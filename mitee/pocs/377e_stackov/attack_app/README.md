# Oplus alipay crash

tested on oneplus nord: CPH2621_15.0.0.604

alipay service -> binder (1) -> vendor.oplus.hardware.biometrics.fingerprintpay.IFingerprintPay -> ioctl -> alipay TA

stack buffer overflow in ifaa_in_validate_req_sig, when parsing the certchain node, an int32 is read from the user controlled buffer and then in a loop a stack buffer is written to (without any bounds checks). This leads to a buffer overflow.

ghidra decomp:
```c
        node_0x8006 = (node *)find_node_by_tag(param_1,0x8006);
        if (node_0x8006 != (node *)0x0) {
          data = node_0x8006->data;
          some_size? = read32(data);
          /* no bounds check on size read from data */
          if (some_size? != 0) {
            stack_buf_2 = &auStack_b4.data2;
            dataa = data + 4;
            i = 0;
            /* buffer overflow in this loop */
            do {
              i1 = read32(dataa);
              *(int *)(stack_buf_2 + -3) = i1;
              i2 = read32(dataa + 4);
              stack_buf_2[-2] = (void *)(dataa + 8);
              stack_buf_2[-1] = (void *)i2;
              i3 = read32(i2 + dataa + 8);
              *stack_buf_2 = (void *)(dataa + i2 + 0xc);
              i4 = i3 + i2 + 0xc;
              stack_buf_2[1] = (void *)i3;
              i5 = read32(dataa + i4);
              stack_buf_2[2] = (void *)(dataa + i4 + 4);
              i = i + 1;
              stack_buf_2[3] = (void *)i5;
              dataa = dataa + i4 + 4 + i5;
              stack_buf_2 = stack_buf_2 + 7;
            } while (i != some_size?);
          }
          i = IFAA_AuthenticatorVerifyDigest
                        (sha256sum,sha256sum_size,iVar2->data,(uint)iVar2->size,&auStack_b4,
                         some_size?);
```

Can be triggered by calling the TA with command 1
(ifaa_tz_register), the parse_request function takes as 4th argument a callback to a function, which ends up calling ifaa_in_validate_req_sig.

To check:
```
adb shell su
dmesg | grep QSEE
```

Expected log output (-22 means APP_FAULTED):
```
[83677.230266] QSEECOM: qseecom_load_app: App (alipay) does'nt exist, loading apps for first time
[83677.325272] QSEECOM: qseecom_load_app: App with id 62 (alipay) now loaded
[83677.325280] QSEECOM: qseecom_vaddr_unmap: Trying to unmap vaddr
[83677.339593] QSEECOM: __qseecom_send_cmd: scm_call() failed with err: -22 (app_id = 62)
[83677.339613] QSEECOM: qseecom_ioctl: failed qseecom_send_cmd: -22
[83677.340437] QSEECOM: __qseecom_unload_app: App (62) is unloaded
[83677.340444] QSEECOM: qseecom_vaddr_unmap: Trying to unmap vaddr
```

