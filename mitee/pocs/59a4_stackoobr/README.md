# stack oob read in 59a4867c-9fe5-f7c2-b409a46bae6ff73e mitee trusted application

## Details

In command id 0xf007 the TA calls the `getKeyBagTAPublicKey` function.
This function prints the contents of the stack in a loop, using an attacker provided number as the end condition of the loop. 
This number is not checked and an attacker can use this to other stack content such as the canary or return address.

```
int getKeyBagTAPublicKey(long *buf,int num_in_buf,void *buf2,uint *buf22)

{
   
  length = *buf; 
  long inp_len = buf[1]; //attacker controlled
  if (inp_len != 0) {
    i = 0;
    j = 0;
    char hex_str[0x32];
	char somebuf[0x40];
    do {
      snprintf(hex_str[j * 3],3,"%02x ",
               somebuf[i]);
      j = j + 1;
      if ((j & 0xf) == 0) {
        printf("[%s:%s][%s:%d]%s(%4d): %s\n","MKEYBAG",&DAT_0010338c,"dump_to_hex",0x3b,"Id_indata",
               i & 0xffffffff,hex_str);
        memset1(hex_str,0,0x31);
        j = 0;
      }
      i = i + 1;
    } while (inp_len != i); // inp_len is not checked and can be bigger than the stack buffer leading to the oob
    if (j != 0) {
      printf("[%s:%s][%s:%d]%s(%4d): %s\n","MKEYBAG",&DAT_0010338c,"dump_to_hex",0x41,"Id_indata",
             (ulong)(inp_len - 1),hex_str);
    }
  }
```

## Impact

An normal world attacker that can read the logs can use this vulnerability to leak TA memory.

## Reproduce

We reproduced the poc on the redmi note 15 pro (lapis_images_OS2.0.202.0.VPPCNXM)

compile and run the poc:
```
ANDROID_NDK=$(path to android ndk) make 
adb shell
su
```

## NOTES:
7eef5537b8ff01932e06bd11b6fdb80 (hash of crashing seed)
