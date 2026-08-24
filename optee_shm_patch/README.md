# Opt-in shared memory for OP-TEE (Section VII)

The mitigation of Section VII, and nothing else. It is **not an experiment** of
this artifact evaluation — see §6 of [`../README.md`](../README.md).

    optee_os.patch        the mitigation: 140 lines against optee_os. A TA
                          opts a memref parameter in, and the kernel then hands
                          it a private copy taken once at invocation instead of
                          the normal-world buffer, so a second fetch cannot
                          observe a different value.
    optee_examples.patch  an example TA that opts in, used to measure the
                          overhead and to check that the double fetch is gone.
    qemu_v8.xml           the repo manifest pinning the OP-TEE QEMU-v8 tree the
                          two patches apply to.

Applying them needs a built OP-TEE QEMU-v8 tree (~31 GB and hours of
compiling), which is why the section is documented in the paper rather than run
here:

```sh
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
repo sync
cd optee_os      && git apply /path/to/optee_shm_patch/optee_os.patch
cd ../optee_examples && git apply /path/to/optee_shm_patch/optee_examples.patch
cd ../build && make run
```

`wc -l optee_os.patch` is claim C9's "140 LoC".
