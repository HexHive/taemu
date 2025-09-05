# Bss overflow the 9459b61a-02d3-4d1e-b68be94397e7ca8c T6 TA

When handling command 0x1026 `sf_handle_transmitdata`, if the character at offset 0x10 of the input buffer is 0x1, the TA makes a memcpy using a value read from the attacker controlled buffer. This leads to an overflow in the data section of the TA.

Relveant pseudocode (`param_1` is the attacker-controlled input buffer)

```
big_function(int* param_1){
	...
	if (cmd == 0x1026) {
		cVar14 = (char)param_1[5];
		memset(local_b8,0,0x80);
		if (log_lvl < 2) {
		  ta_logging?(1,"fsfp-tee-v1.4.0.10","(%d) \'%s\' enter.",0xb9f,"sf_handle_transmitdata"
					 );
		}
		if ((char)param_1[4] == '\x01') {
		if (cVar14 == '\0') {
			DAT_002d2154 = 0;
			if (log_lvl < 2) {
			  ta_logging?(1,"fsfp-tee-v1.4.0.10","(%d) PackIndex = %d, tmpCrc = 0x%x",0xba7,0,
						  param_1[7] & 0xff);
			}
		}
		memcpy((void *)(DAT_002d20f0 + DAT_002d2154),param_1 + 6,(void *)(param_1[1] - 8)); //memcpy with length controlled by attacker
```

the `big_function` is called from `TA_InvokeCommandEntryPoint` if the command (first integer in the input buffer is not equal to 0x1005 or 0x1000).

```
TA_InvokeCommandEntryPoint(void *p1,int cmd,int ptypes,void *params)
{
  int* buf1;
  if (log_lvl < 2) {
    ta_logging?(1,"fsfp-tee-entry-tk","(%d) \'%s\' enter.",0x83,"TA_InvokeCommandEntryPoint");
                    /* WARNING: Load size is inaccurate */
    buf1 = params[0].memref.buffer;
  }
  else {
    buf1 = params[0].memref.buffer;
  }
  if (buf1 == (uint *)0x0) {
    uVar2 = perror(0xffffffea,cmd);
    ta_logging?(3,"fsfp-tee-entry-tk","error at %s(%d): \'%s\'.","TA_InvokeCommandEntryPoint",0x89,
                uVar2);
    return 0xffff0006;
  }
  actual_cmd = *buf1;
  if (log_lvl < 2) {
    uVar2 = FUN_0025e1f8(actual_cmd);
    ta_logging?(1,"fsfp-tee-entry-tk","(%d) message->request.cmd = %s",0x96,uVar2);
  }
  if (-1 < (int)actual_cmd) {
    if (actual_cmd == 0x1000) {
		... 
    }
    else if (actual_cmd == 0x1005) {
		.... 
    }
    else {
      if (actual_cmd == 0x1006) {
        FUN_0027a4d4(DAT_002d2004 + 0x60,"v1.4.0.10-Jul 25 2022 17:09:55");
      }
      uVar1 = bif_function(buf1);
  ...
```

