# 1.Prerequisition 

### 1.1 Generate bbs dir for different tee (Passed if you have)

```shell
cd ghidra
# make -> docker -> ghidra headless mode -> load and run scripts for bb-level coverage
./analyze-bbs.sh 
```

### 1.2 Backup coverage files of suspicious inputs

```shell
$ cd eval/graphs
$ ./bk_suspicious_inputs_covs.sh
Usage: ./bk_suspicious_inputs_covs.sh <root_dir> <back_dir>
Example: ./bk_suspicious_inputs_covs.sh /root/TA_GP_emulator /root/bk_ss_cov

$ ./bk_suspicious_inputs_covs.sh /home/sp1der/code/ta_graph/TA_GP_emulator /home/sp1der/code/ta_graph/ss_cov

# Then the susipicious inputs' coverage files should be under the `ss_cov/{ts}/suspicious_inputs_covs`

# The output of script will show you the right backup dir at the end.
```


# 2. Get coverage graph

There are two stages of Coverage Graph Generation, indicated by `--fuzz_mode`

```shell
$ cd eval/graphs

$ uv run main.py --help  
usage: main.py [-h] [--fuzz_mode {ORG,DF,ALL}] [--tees TEES [TEES ...]] [--regen_coverage] [--path PATH] --ss_cov_rdir SS_COV_RDIR [--org_group_field {tee,None}] [--show_rate]

options:
  -h, --help            show this help message and exit
  --fuzz_mode {ORG,DF,ALL}
  --tees TEES [TEES ...]
                        Filter by TEEs
  --regen_coverage
  --path PATH
  --ss_cov_rdir SS_COV_RDIR
  --org_group_field {tee,None}
  --show_rate

# Usually, ss_cov_rdir and path is required
# ss_cov_rdir is the backup dir of Section 1.2
$ uv run main.py --path /home/sp1der/code/TA_GP_emulator --ss_cov_rdir /home/sp1der/code/ta_graph/ss_cov/20260129_135401/suspicious_inputs_covs

# At least, run with `--regen_coverage` once to generate cov files from queue seeds
# if you generate all the cov files before, delete `--regen_coverage` arg afterwards.
$ uv run main.py --path /home/sp1der/code/TA_GP_emulator --ss_cov_rdir /home/sp1der/code/ta_graph/ss_cov/20260129_135401/suspicious_inputs_covs --regen_coverage

# More configuration
# use --show_rate to get coverage rather than bb count
# re-generate cov files and build graph only relaed to certain tees [check pre_clean flag in code]
$ uv run main.py --path <sth> --ss_cov_rdir <sth> --regen_coverage --tees qsee beanpod
# only generate exploration coverage graph
$ uv run main.py --path <sth> --ss_cov_rdir <sth> --tees qsee beanpod --fuzz_mode ORG
# enable grouping of exploration coverage graph in tee level
$ uv run main.py --path <sth> --ss_cov_rdir <sth> --tees qsee beanpod --fuzz_mode ORG --org_group_field tee
```