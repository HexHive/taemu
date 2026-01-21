from common import list_tas
import os
import shutil
import subprocess

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