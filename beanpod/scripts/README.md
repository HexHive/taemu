# Extract beanpod TAs

Download firmware and unpack:

```shell
binwalk -e tee.img
# in soter.dump.py update the offsets of the filenames
python3 soter_dump.py soter.img
```

