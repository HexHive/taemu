from common import list_tas
import os
import shutil
import subprocess
from common import parse_drcov

test_path = "/root/TA_GP_emulator"

def test_clean_cov():
    all_tas: set[str] = list_tas(test_path)
    for ta in all_tas:
        ta_dir_name = os.path.dirname(ta)
        cov_dir = os.path.join(test_path, ta_dir_name, "out", "cov")
        if os.path.exists(cov_dir):
            shutil.rmtree(cov_dir)
        assert not os.path.exists(cov_dir)
        df_fuzz_dir = os.path.join(test_path, ta_dir_name, "df_fuzz")
        if os.path.exists(df_fuzz_dir):
            for df_fuzz_file in os.listdir(df_fuzz_dir):
                df_cov_file = os.path.join(df_fuzz_dir, df_fuzz_file, "out", "cov")
                if os.path.exists(df_cov_file):
                    shutil.rmtree(df_cov_file)
        
    result = subprocess.run(f"find {test_path} -path \"*/harness/*/out/cov\" -type d", shell=True, capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout == ""
    
def test_get_foo_only_queue():
    all_tas: set[str] = list_tas(test_path)
    all_foo_only_ta_dirs = []
    for ta in all_tas:
        ta_dir_name = os.path.dirname(ta)
        queue_dir = os.path.join(test_path, ta_dir_name, "out", "default", "queue")
        foo_only_flag = True
        if os.path.exists(queue_dir):
            for file in os.listdir(queue_dir):
                # print(file)
                if "foo" not in file and ".state" != file:
                    foo_only_flag = False
                    break
        if foo_only_flag:
            all_foo_only_ta_dirs.append(ta_dir_name)
    print(all_foo_only_ta_dirs)
    
    
def test_parse_cov():
    
    cov_path = "/root/TA_GP_emulator/qsee/harness/3d08_fuzz/out/cov/id:000005,src:000004,time:1789,execs:153,op:havoc,rep:2,+cov.cov"
    tee = "qsee"
    ta = "/srv/emulator/rootfs/3D08821C-33A6-11E6-A1FA-089E01C83AA2.ta"
    
    bbs = parse_drcov(tee, ta, cov_path)
    print([str(bb) for bb in bbs])
    print(len(bbs))