import emulate.fuzz_record as fuzz_record


def test_dedup_without_reg_hash():
    meta = {
        "key": "run:id:1a0f84be500884e2874a9b51b5977601",
        "meta": {
            "last_accessed": 1763120578.6366577
        },
        "updated_at": 1763120580.63176,
        "full_to_replay": False,
        "records": [
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385692,
                "ret_addr_offset": 154268,
                "is_read": True,
                "reg_hash": "1234567890"
            }
            },
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385816,
                "ret_addr_offset": 154392,
                "is_read": True,
                "reg_hash": "1234567890"
            }
            },
            {
            "addr": 3149651968,
            "size": 59,
            "regs": {
                "PC": 2576978040,
                "ret_addr": 93824992385832,
                "ret_addr_offset": 154408,
                "is_read": True,
                "reg_hash": "1234567890"
            }
            },
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385852,
                "ret_addr_offset": 154428,
                "is_read": True,
                "reg_hash": "1234567890"
            }
            }
        ]
        }
    
    
    meta2 = {
        "key": "run:id:1a0f84be500884e2874a9b51b5977601",
        "meta": {
            "last_accessed": 1763120578.6366577
        },
        "updated_at": 1763120580.63176,
        "full_to_replay": False,
        "records": [
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385692,
                "ret_addr_offset": 154268,
                "is_read": True,
                "reg_hash": "1111"
            }
            },
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385816,
                "ret_addr_offset": 154392,
                "is_read": True,
                "reg_hash": "2222"
            }
            },
            {
            "addr": 3149651968,
            "size": 59,
            "regs": {
                "PC": 2576978040,
                "ret_addr": 93824992385832,
                "ret_addr_offset": 154408,
                "is_read": True,
                "reg_hash": "3333"
            }
            },
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385852,
                "ret_addr_offset": 154428,
                "is_read": True,
                "reg_hash": "4444"
            }
            }
        ]
        }
    fuzz_recorder = fuzz_record.SimpleFilterRecorder(q=None, record_seed_dir=None)
    
    res = fuzz_recorder._filter_handler(meta)
    assert res == True
    res2 = fuzz_recorder._filter_handler(meta2)
    assert res2 == False
    assert "reg_hash" in meta2["records"][0]["regs"]
    assert "reg_hash" in meta["records"][0]["regs"]
    
    
    
    
def test_dedup_without_size():
    meta = {
        "key": "run:id:0b9ed038869860f46c631c9acdae166d",
        "meta": {
            "last_accessed": 1763122712.7164674
        },
        "updated_at": 1763122712.8457205,
        "full_to_replay": False,
        "records": [
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385692,
                "ret_addr_offset": 154268,
                "is_read": True,
                "reg_hash": "147762692186609489026431728440300000149"
            }
            },
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385816,
                "ret_addr_offset": 154392,
                "is_read": True,
                "reg_hash": "11476346845161322203697195266058186263"
            }
            },
            {
            "addr": 3149651968,
            "size": 111,
            "regs": {
                "PC": 2576978040,
                "ret_addr": 93824992385832,
                "ret_addr_offset": 154408,
                "is_read": True,
                "reg_hash": "88004697052803911198231617814777067659"
            }
            },
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385852,
                "ret_addr_offset": 154428,
                "is_read": True,
                "reg_hash": "235699151334603750473974899648542358277"
            }
            }
        ]
    }
    
    meta2 = {
        "key": "run:id:0ce9493e815ce80292c103a1326a9575",
        "meta": {
            "last_accessed": 1763122711.7326636
        },
        "updated_at": 1763122712.8434663,
        "full_to_replay": False,
        "records": [
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385692,
                "ret_addr_offset": 154268,
                "is_read": True,
                "reg_hash": "147762692186609489026431728440300000149"
            }
            },
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385816,
                "ret_addr_offset": 154392,
                "is_read": True,
                "reg_hash": "5748739078687946184450796873342422184"
            }
            },
            {
            "addr": 3149651968,
            "size": 66,
            "regs": {
                "PC": 2576978040,
                "ret_addr": 93824992385832,
                "ret_addr_offset": 154408,
                "is_read": True,
                "reg_hash": "162871244009161107230610891699993179738"
            }
            },
            {
            "addr": 3149651968,
            "size": None,
            "regs": {
                "PC": 2576977952,
                "ret_addr": 93824992385852,
                "ret_addr_offset": 154428,
                "is_read": True,
                "reg_hash": "206758698884837711997471636248984211027"
            }
            }
        ]
    }
    fuzz_recorder = fuzz_record.SimpleFilterRecorder(q=None, record_seed_dir=None)
    res = fuzz_recorder._filter_handler(meta)
    assert res == True
    res2 = fuzz_recorder._filter_handler(meta2)
    assert res2 == False