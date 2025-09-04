# T6 TEE

https://www.trustkernel.com/en/products/device/tee/t6.html

Ulephone is running these TAs. (FW: Power_Armor_18_AF6_EEA_V1)

## Figuring out TA_ function address

the elf files have a `ta_head` section, which starting at offset 0x18 have pointers to various wrapper functions (first one probably for when the client calls `TEEC_OpenSession`, second for `TEEC_InvokeCommand` and the third for `TEEC_CloseSession`).
