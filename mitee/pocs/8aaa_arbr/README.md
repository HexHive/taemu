# Arbitrary read in 8aaaf201-2460-0000-7143fe4f7c823c80 mitee trusted application

There is an arbitrary read vulnerability in the `collectAllStatus` function. The following codepath 
goes from `TA_InvokeCommandEntryPoint` to the vulnerability:

Command id 0x9201 calls the `generate_status_auth` function:

```
	unsigned int* buf1 = params[0].memref.buf;
    if (command_id != 0x9201) goto LAB_001238cc;
    printf("[%s:%s][%s:%d]Try use authtoken to generate the status list\n","Miriskm",&DAT_00103767,
           "TA_InvokeCommandEntryPoint",0x101);
    iVar2 = generate_status_auth(buf1 + 4,buf1[2],...);
	...
```

`generate_status_auth` then directly calls `collectAllStatus`:

```
ulong generate_status_auth(long param_1,undefined8 param_2,undefined2 *param_3,int *param_4)

{
  if (((param_1 == 0) || (param_3 == (undefined2 *)0x0)) || (param_4 == (int *)0x0)) {
    printf("[%s:%s][%s:%d]input NULL ptr in generate_status_auth\n","Miriskm","ERROR",
           "generate_status_auth",0x33d);
    uVar6 = 2;
  }
  else {
    *param_3 = 0x7b;
    *(undefined4 *)(lVar8 + -0x70) = 1;
    uVar2 = collectAllStatus(param_1,param_2,(long)param_3 + 1);
	...
```

The arbitrary read vulnerability happens in the `collectAllStatus` function, where an integer dereferenced from the attacker controlled buffer is used in pointer arithmetic and then dereferenced.

```
int collectAllStatus(unsinged int* buf1,uint param_2,long param_3,int *param_4)

{
  if ((((param_2 < 0x10) || (param_1 == 0)) || (param_3 == 0)) || (param_4 == (int *)0x0)) {
    uVar9 = printf("[%s:%s][%s:%d]input NULL ptr\n","Miriskm","ERROR","collectAllStatus",0x167);
    uVar22 = (ulong)uVar9;
    iVar10 = 2;
    goto LAB_0012ceec;
  }
  unsigned int offset = (*param_1)+4;
  if (param_2 - 0xc < uVar9) { // useless check since param_2 is also read from the attacker controlled buffer
    pcVar13 = "[%s:%s][%s:%d]fwk_prop_len is too long:%d\n";
    uVar9 = printf(pcVar13,"Miriskm","ERROR","collectAllStatus",uVar15,uVar22);
  }
  else {
    unsigned int uVar7 = *(param_1 + (ulong)offset); //arbitrary read in integer range (pointer arithmetic with value read from buffer)
```

## Impact

A normal world attacker able to interact with `/dev/teei0` may leverage this vulnerability to leak the TA's memory.

## Notes

4b2438c95a1f236ab5e2168d5fb7dbd1
60cb18848cd88121fbac5e63f3991edf (md5sum of crashing input)
