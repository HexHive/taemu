# 1. generate bbs dir for different tee

```shell
cd ghidra
# make -> docker -> ghidra headless mode -> load and run scripts for bb-level coverage
./analyze-bbs.sh 
```


# 2. get coverage graph

```shell
cd eval/graphs
uv run main.py
``` 