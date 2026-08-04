#  Arbitrary read vulnerability in 86f623f6-a299-4dfd-b560ffd3e5a62c2 mitee trusted application

Command 0x300 of the TA calls the `cmd_ecc_sign_raw` function. The `cmd_ecc_sign_raw` has a arbitrary read vulnerability since an integer read from the 
attacker controlled buffer is used in pointer arithmetic.

Relveant pseudocode:
```c
uint cmd_ecc_sign_raw(uint* buf1,void* buf2) //buf1 points to the attacker controlled buffer

{
  uint input_size = buf1[1];
  if (input_size != 0) {
    int i = 0;
    do {
      uint uVar1 = buf1[2+i];
      uint uVar2 = buf1[3+i]; 
      uint i = i + 8;
      if (uVar2 != 0) {
        if (buf1[1] - i < uVar2) {
          printf("[%s:%s][%s:%d]length error, invalid length, length=%d, offset=%d, data_size=%d\n",
                 "CardApp","ERROR","cmd_ecc_sign_raw",0x39f,(ulong)uVar2,(ulong)uVar7);
		  break;
        }
        if (uVar1 == 0x202) {
          if (uVar2 == 4) {
            iVar3 = buf1[i+2];
            if (iVar3 == 0) goto LAB_001233f0;
            __format = "[%s:%s][%s:%d]force n_key for external sign\n";
            uVar5 = 0x3bd;
          }
          else {
            __format = "[%s:%s][%s:%d]sign key name is invalid\n";
            uVar5 = 0x3b7;
          }
          printf(__format,"CardApp","ERROR","cmd_ecc_sign_raw",uVar5);
        }
        else if (uVar1 == 0x500) {
          if (0x20 < uVar2) {
            printf("[%s:%s][%s:%d]sign data is too large\n","CardApp","ERROR","cmd_ecc_sign_raw",
                   0x3a7);
            uVar2 = 0xffff0006;
            break;
          }
          if (uVar2 != 0x20) {
            printf("[%s:%s][%s:%d]sign data is too short, force continue\n","CardApp","ERROR",
                   "cmd_ecc_sign_raw",0x3ab);
          }
          memmove1(lVar10 + -0x28,param_1 + (ulong)uVar7 + 8,(ulong)uVar2);
        }
        else {
          printf("[%s:%s][%s:%d]Unknown data type %04x\n","CardApp","ERROR","cmd_ecc_sign_raw",0x3c3
                 ,(ulong)uVar1);
        }
        i = uVar2 + i; // uVar2 is read from attacker controlled buffer, in second iteartion a large uVar2 will cause an oob read!
      }
      uVar2 = 0;
      input_size = buf1[1];
    } while (i < input_size);
```

## Impact

A normal world attacker able to interact with `/dev/teei0` may exploit this vulnerability to leak the TA's memory.

## Notes

2bd394cf946f72c950eb2e5800257eb0

