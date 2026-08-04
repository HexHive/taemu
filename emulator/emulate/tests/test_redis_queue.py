import emulate.redis_queue as rq
import os

def test_redis_queue():
    q = rq.create_redis_queue(queue_name="ta_emulator_queue_for_my_test")
    q.put("okay")
    ans = q.command("keys *")
    print(ans)