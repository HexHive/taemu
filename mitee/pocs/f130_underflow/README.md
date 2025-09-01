# Stack Buffer Overflow in the soter (377ee4e8-af0e-474f-a9d636a9268fe85c) mitee trusted application

## Details

Command id 0x100a in the TA triggers the `remove_auth_key` function, which copies data to a stack buffer using the 
attacker controlled buffer and size. This directly leads to a stack overflow if the attacker invokes the TA with 
a buffer of size > 0x108.

The relevant pseudocode of the vulnerable function:

`TA_InvokeCommand`

```
switch(cmd){
	case 0x100a:
		remove_auth_key(params[0].value.a, params[1].memref.buffer, params[1].memref.size);
```

`remove_auth_key:`

```
remove_auth_key(int a, void* b1, size_t s1){
	char stack_buf[0x108]
	...
	printf("[%s:%s][%s:%d]==func enter==\n","SoterApp",&DAT_0010319c,"remove_auth_key",0x50a);
	...
	memmove(stack_buf, b1, s1); 
}
```

## Reproduce

We reproduced the poc on the redmi note 15 pro (lapis_images_OS2.0.202.0.VPPCNXM)

compile and run the poc:
```
ANDROID_NDK=$(path to android ndk) make 
adb shell
su
```

