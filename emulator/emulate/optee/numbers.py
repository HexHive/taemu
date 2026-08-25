"""OP-TEE TA->kernel syscall (SCN) numbering and TA entry-function codes.

These mirror optee_os `lib/libutee/include/tee_syscall_numbers.h`. The TA's
statically-linked libutee invokes the kernel via `mov x8, #SCN; svc #0` with
arguments in x0..x7 and the result returned in x0. We confirmed the numbering
against the target binaries: `utee_cipher_update` -> 22 and
`utee_authenc_update_payload` -> 36 both match the standard table.
"""

# --- TA entry-function codes (first arg to __utee_entry) --------------------
UTEE_ENTRY_FUNC_OPEN_SESSION = 0
UTEE_ENTRY_FUNC_CLOSE_SESSION = 1
UTEE_ENTRY_FUNC_INVOKE_COMMAND = 2

# --- syscall numbers --------------------------------------------------------
TEE_SCN_RETURN = 0
TEE_SCN_LOG = 1
TEE_SCN_PANIC = 2
TEE_SCN_GET_PROPERTY = 3
TEE_SCN_GET_PROPERTY_NAME_TO_INDEX = 4
TEE_SCN_OPEN_TA_SESSION = 5
TEE_SCN_CLOSE_TA_SESSION = 6
TEE_SCN_INVOKE_TA_COMMAND = 7
TEE_SCN_CHECK_ACCESS_RIGHTS = 8
TEE_SCN_GET_CANCELLATION_FLAG = 9
TEE_SCN_UNMASK_CANCELLATION = 10
TEE_SCN_MASK_CANCELLATION = 11
TEE_SCN_WAIT = 12
TEE_SCN_GET_TIME = 13
TEE_SCN_SET_TA_TIME = 14
TEE_SCN_CRYP_STATE_ALLOC = 15
TEE_SCN_CRYP_STATE_COPY = 16
TEE_SCN_CRYP_STATE_FREE = 17
TEE_SCN_HASH_INIT = 18
TEE_SCN_HASH_UPDATE = 19
TEE_SCN_HASH_FINAL = 20
TEE_SCN_CIPHER_INIT = 21
TEE_SCN_CIPHER_UPDATE = 22
TEE_SCN_CIPHER_FINAL = 23
TEE_SCN_CRYP_OBJ_GET_INFO = 24
TEE_SCN_CRYP_OBJ_RESTRICT_USAGE = 25
TEE_SCN_CRYP_OBJ_GET_ATTR = 26
TEE_SCN_CRYP_OBJ_ALLOC = 27
TEE_SCN_CRYP_OBJ_CLOSE = 28
TEE_SCN_CRYP_OBJ_RESET = 29
TEE_SCN_CRYP_OBJ_POPULATE = 30
TEE_SCN_CRYP_OBJ_COPY = 31
TEE_SCN_CRYP_DERIVE_KEY = 32
TEE_SCN_CRYP_RANDOM_NUMBER_GENERATE = 33
TEE_SCN_AUTHENC_INIT = 34
TEE_SCN_AUTHENC_UPDATE_AAD = 35
TEE_SCN_AUTHENC_UPDATE_PAYLOAD = 36
TEE_SCN_AUTHENC_ENC_FINAL = 37
TEE_SCN_AUTHENC_DEC_FINAL = 38
TEE_SCN_ASYMM_OPERATE = 39
TEE_SCN_ASYMM_VERIFY = 40
TEE_SCN_CRYP_OBJ_GENERATE_KEY = 41
TEE_SCN_STORAGE_OBJ_OPEN = 42
TEE_SCN_STORAGE_OBJ_CREATE = 43
TEE_SCN_STORAGE_OBJ_DEL = 44
TEE_SCN_STORAGE_OBJ_RENAME = 45
TEE_SCN_STORAGE_ALLOC_ENUM = 46
TEE_SCN_STORAGE_FREE_ENUM = 47
TEE_SCN_STORAGE_RESET_ENUM = 48
TEE_SCN_STORAGE_START_ENUM = 49
TEE_SCN_STORAGE_NEXT_ENUM = 50
TEE_SCN_STORAGE_OBJ_READ = 51
TEE_SCN_STORAGE_OBJ_WRITE = 52
TEE_SCN_STORAGE_OBJ_TRUNC = 53
TEE_SCN_STORAGE_OBJ_SEEK = 54

# Names for logging. 55..93 exist in libutee (newer GP additions: secure
# element, monotonic counters, gprof, cache maintenance, ...) but are not
# implemented; they are logged by number and graceful-failed. 74/75/88 are the
# DJI CryptoCell vendor syscalls handled specially in optee_api.
SCN_NAMES = {
    v: k[len("TEE_SCN_"):]
    for k, v in list(globals().items())
    if k.startswith("TEE_SCN_")
}


def scn_name(scn: int) -> str:
    return SCN_NAMES.get(scn, f"SCN_{scn}")
