# Stack overflow in 8aaaf201-2460-0000-7143fe4f7c823c80 mitee trusted application

There is an stack overflow vulnerability in the `collectAllStatus` function. The following codepath 
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

The stack overflow vulnerability happens in the `collectAllStatus` function, where an integer dereferenced from the attacker controlled buffer is used as the size in a `memmove` call writing to a static stack buffer.

```
int collectAllStatus(unsinged int* buf1,uint param_2,long param_3,int *param_4)

{
	char stack_buf[0x100];
	...
	uint off1 = *param_1;
	uint off1_4 = off1 + 4;
	uint off2 = *(param_1 + off1_4);
	uint off3 = off1_4 + 8 + off2;
	if (param_2 - 8 < off3) {
	  pcVar13 = "[%s:%s][%s:%d]daemon_prop_len is too long:%d\n";
	  uVar15 = 0x17c;
	  goto LAB_0012cee4;
	}
	uint memmove_size = *(param_1 + off3); // read from attacker controlled buffer
	uint memmove_size_4 = memmov_size + 4;
	if (param_2 - 4 < memmove_size_4) {
	  pcVar13 = "[%s:%s][%s:%d]challenge_len is too long:%d\n";
	  uVar15 = 0x183;
	  goto LAB_0012cee4;
	}
    memmove(stack_buf,buf1 + 4,memmove_size); //stack overflow here
	...
```

## Impact

A normal world attacker able to interact with `/dev/teei0` may leverage this vulnerability in combination with a memory leak to achieve arbitrary code execution.

## Notes

cb37ed5da1d6264fcb6b08b73bd (md5sum of crashing seed)
