/* Zero-copy check for Table III / claim C5, shared by the on-device PoCs.
 *
 * If the TEE copied the memref in and out, the TA's writes could only become
 * visible to the normal world after TEEC_InvokeCommand returned. So watch a
 * small window of the buffer from a third thread and record whether it changes
 * *while* the invoke is still blocked, and how far into the call. A change
 * observed in the middle of the call means the TA writes straight into
 * normal-world memory - the same memory the racing thread keeps rewriting,
 * which is what makes a double fetch possible.
 *
 * The window must not overlap the offset the racing thread writes, otherwise
 * it observes the racer instead of the TA.
 */
#ifndef ZEROCOPY_H
#define ZEROCOPY_H

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile int zc_invoke_running;
static volatile long long zc_changed_at = -1;
static volatile long long zc_polls;

struct zc_watch {
    volatile unsigned char *mem;
    size_t len;
};

static void *zc_watch_thread(void *arg)
{
    struct zc_watch *w = (struct zc_watch *)arg;
    unsigned char *snap = malloc(w->len);

    memcpy(snap, (const void *)w->mem, w->len);
    while (zc_invoke_running) {
        zc_polls++;
        if (memcmp(snap, (const void *)w->mem, w->len) != 0) {
            if (zc_changed_at < 0)
                zc_changed_at = zc_polls;
            memcpy(snap, (const void *)w->mem, w->len);
        }
    }
    free(snap);
    return NULL;
}

static pthread_t zc_tid;

static void zc_start(void *mem, size_t off, size_t len)
{
    static struct zc_watch w;

    w.mem = (volatile unsigned char *)mem + off;
    w.len = len;
    zc_invoke_running = 1;
    zc_changed_at = -1;
    zc_polls = 0;
    if (pthread_create(&zc_tid, NULL, zc_watch_thread, &w) != 0)
        perror("pthread_create(zerocopy watcher)");
}

static void zc_stop(void)
{
    zc_invoke_running = 0;
    pthread_join(zc_tid, NULL);
    if (zc_changed_at >= 0)
        printf("ZEROCOPY: yes - the TA changed the buffer while "
               "TEEC_InvokeCommand was still blocked (poll %lld of %lld)\n",
               zc_changed_at, zc_polls);
    else
        printf("ZEROCOPY: no - the buffer did not change during the invoke "
               "(%lld polls)\n", zc_polls);
}

#endif /* ZEROCOPY_H */
