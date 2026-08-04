# Double Fetch leading to stack overflow in the 377ee4e8-af0e-474f-a9d636a9268fe85c mitee trusted application

Command id 0x100b of the TA exposes the `has_auth_already` function, whose second argument is params[1].memref.buf.

The function then call `combine_file_name` with a stack buffer as the first argument and the attacker controlled buffer as the second:

```
has_auth_already(void* memref_buf0, void* memref_buf1) {
	char file_name[0x80];
	unsigned int out_len= 0x80;
	...
	combine_file_name(..., memref_buf1, file_name, &out_len);
	...
}
```

The `combine_file_name` function has a double fetch vulnerability. It first obtains the length of string from the shared memory with `strlen` checks if the length is ok and the recalculates `strlen` again which is then used in `memmove` to the stack buffer.
This is unsafe as the `memref_buf1` is shared between the CA and TA. A malicious CA can modify the buffer inbetween the first and second strlen such that the check for the first strlen passes but then the second strlen results in a length long enough for a stack buffer overflow.

```
combine_file_name(char* sth, char* memref_buf1, char* file_name, unsigned int* max_len){
	if(strlen(memref_buf1)+strlen(sth) > *max_len){ //first fetch start of double fetch race window
		printf("[%s:%s][%s:%d]short path_name\n","SoterApp","ERROR","combine_file_name",0xb);
		return 0xffff0006;
	}	
	int sth_len = strlen(sth);
	memmove(file_name, sth, sth_len);
	int buf1_len = strlen(memref_buf1); // second fetch, attacker can change contents of memref_buf1 inbetween first and second strlen call
	memmove(file_name+sth_len, memref_buf1, buf1_len); //stack buffer overflow
	...
}
```

## Impact

An attacker that can interact with `/dev/teei0` can trigger a stack buffer overflow, in combination with a stack canary leak this can be used to achieve arbitrary code execution
