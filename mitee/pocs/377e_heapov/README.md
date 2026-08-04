# heap buffer overflow in the soter (377ee4e8-af0e-474f-a9d636a9268fe85c) mitee trusted application

## Details

command id 0x100c in the TA triggers the `init_sign` function, which in turns calls the `generate_session` function. 
In the `generate_session` function the size of one of the memory references `params[2].memref.size` is used as the 
size in a memmove to a chunk with a static size `0x1b0`. Passing a memory reference with size > 0x1b0 causes a 
buffer overflow.

The relevant pseudocode of the vulnerable function:

`TA_InvokeCommand`

```
switch(cmd){
	case 0x100b:
		init_sign(params[0].memref.buffer, params[1].memref.buffer, params[1].memref.size, params[2].memref.buffer, params[2].memref.size, &stack_var);
```

`init_sign:`

```
init_sign(void* out, void* b1, size_t s1, void* b2, size_t s2, int* state){
	printf("[%s:%s][%s:%d]==func enter==\n","SoterApp",&DAT_0010319c,"init_sign",0x528);
	printf("[%s:%s][%s:%d]session is %lu\n","SoterApp",&DAT_0010319c,"init_sign",0x529,*state?);
	...
	generate_session(out, b1, s1, b2, s2, state);
}
```

`generate_session`

```
generate_session(void* out, void* b1, size_t s1, void* b2, size_t s2, int* state){
	void* vuln_buf = (void *)TEE_Malloc(0x1b0,0);
	...
	void* b1_chunk = (void*)TEE_Malloc(s1, 0);
	void* b2_chunk = (void*)TEE_Malloc(s2, 0);
	memmove(b1_chunk, b1, s1);
	memmove(b2_chunk, b2, s2);
	memmove(vuln_buf + 0x18,b2_chunk,buf2_size); // overflow here (buf2_size is under attacker control)
	memmove(vuln_buf + 0x128,b1_chunk,buf1_size); // second overflow here (buf1_size is under attacker control)
}
```

## Reproduce

We reproduced the poc on the redmi note 15 pro (lapis_images_OS2.0.202.0.VPPCNXM)

compile and run the poc:
```
ANDROID_NDK=$(path to android ndk) make 
adb shell
su
/data/local/tmp/ta_client
```

