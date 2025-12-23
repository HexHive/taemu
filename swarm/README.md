## Usage
Swarm is a tool for fuzzing TAs in a batch mode

```shell
Usage: swarm [OPTIONS] --top-directory <TOP_DIRECTORY>

Options:
  -t, --top-directory <TOP_DIRECTORY>
          
  -p, --pattern <PATTERN>
          pattern required to be contained in the TA name [default: harness]
  -f, --fuzz-script <FUZZ_SCRIPT>
          [default: /root/TA_GP_emulator/emulator/fuzz.sh]
      --filter-df-seed <FILTER_DF_SEED>
          Filter by suspicious df seed name (e.g. 377e_double_fetch_stackov) [default: ]
  -s, --snapshot-based
          
  -d, --duration <DURATION>
          Duration of the fuzzing job in minutes [default: 60]
  -m, --max-parallel <MAX_PARALLEL>
          [default: 56]
  -h, --help
          Print help
  -V, --version
          Print version
```


## Suggested Commands


```shell
# for normal fuzz
cargo run -- -t .. -f /root/TA_GP_emulator/emulator/fuzz.sh -d 60

# for df fuzz (-s) [recommend to prolong the duration of each reg_hash fuzzing to 15mins for some init_fuzz cases]
cargo run -- -t .. -f /root/TA_GP_emulator/emulator/df_fuzz.sh -d 15 -s -m 28

# run with ta filter (-p)
cargo run -- -t .. -f /root/TA_GP_emulator/emulator/df_fuzz.sh -d 15 -s -m 2 -p 377e_double
cargo run -- -t .. -f /root/TA_GP_emulator/emulator/df_fuzz.sh -d 3 -s -m 2 -p 9459_df

# redirect to file-based logs
echo "y" | cargo run -- -t .. -f /root/TA_GP_emulator/emulator/df_fuzz.sh -d 15 -s -m 28  > "df-output$(date +%H_%M_%S).log" 2>&1

```


