#!/usr/bin/python3
import os
import subprocess
import argparse
import json
import re

class Crash():
	def __init__(self, log, full_log):
		self.full_log = full_log
		before_cpu_context = None
		lines = log.splitlines()
		for i, line in enumerate(lines):
			if "CPU Context:" in line and i > 0:
				before_cpu_context = lines[i-1].strip()
				break

		# Extract lr and pc using regex
		lr_match = re.search(r"lr\s+:\s+(0x[0-9a-fA-F]+)", log)
		pc_match = re.search(r"pc\s+:\s+(0x[0-9a-fA-F]+)", log)

		lr = lr_match.group(1) if lr_match else None
		pc = pc_match.group(1) if pc_match else None
		self.pc = pc
		self.lr = lr
		self.message = before_cpu_context
		self.log = log

	def equal_json(self, other):
		return self.pc == other['pc'] and self.lr == other['lr'] and self.message == other['message']

	def __hash__(self):
		return hash((self.pc, self.lr, self.message))
	
	def __eq__(self, other):
		return self.pc == other.pc and self.lr == other.lr and self.message == other.message

def do_triage(harness, do_all=False):
	print(do_all)
	if do_all:
		os.system(f'rm -rf {harness}/triage')
		os.system(f'rm -rf {harness}/notimpl')
	out = {}
	for inst in os.listdir(f'{harness}/out'):
		for d in os.listdir(f'{harness}/out/{inst}'):
			if d == 'crashes' or (do_all and d.startswith('crashes')):
				crash_dir = os.path.join(harness, 'out', inst, d)
				for crash_seed in os.listdir(crash_dir):
					if crash_seed == "README.txt": continue
					proc = subprocess.run(
						["./fuzz.sh", harness, f'{crash_dir}/{crash_seed}'],
						stdout=subprocess.DEVNULL,
						stderr=subprocess.PIPE,
						text=True
					)
					full_log = proc.stderr
					lines = [line for line in proc.stderr.splitlines() if line.startswith("[x]")]
					if len(lines) == 0:
						print(f'{crash_seed} not reproduced!')
						continue	
					lines = '\n'.join(lines)
					print(f'{crash_dir}/{crash_seed}', len(lines))
					crash = Crash(lines, full_log)
					
					if crash not in out:
						out[crash] = []
					out[crash].append(f'{crash_dir}/{crash_seed}')
	triage_dir = f'{harness}/triage'	
	if not os.path.exists(f'{harness}/triage'):
		os.system(f'mkdir {harness}/triage')
	old_dedup_crashes = os.listdir(triage_dir)
	i = 0
	while str(i) in old_dedup_crashes:
		i += 1
	for crash, crashes in out.items():
		if crash.pc == "0xcafecafe":
			continue
		found = False
		for old in old_dedup_crashes:
			if crash.equal_json(json.load(open(f'{triage_dir}/{old}/crash_info.json', 'r'))):
				print(f'duplicate crashes found for {triage_dir}/{old}')
				for c in crashes:
					os.system(f'cp {c} {triage_dir}/{old}/')
				found = True
				break
		if not found:
			print(f'new crash!! writing to {triage_dir}/{i}')	
			os.system(f'mkdir -p {triage_dir}/{i}')
			open(f'{triage_dir}/{i}/crashlog.txt', 'w+').write(crash.full_log)
			open(f'{triage_dir}/{i}/crash_info.json', 'w+').write(json.dumps(crash.__dict__))
			for c in crashes:
				os.system(f'cp {c} {triage_dir}/{i}/')
			i+=1
	
	notimpl_dir = f'{harness}/notimpl'	
	if not os.path.exists(f'{harness}/notimpl'):
		os.system(f'mkdir {harness}/notimpl')
	old_dedup_crashes = os.listdir(notimpl_dir)
	i = 0
	while str(i) in old_dedup_crashes:
		i += 1
	for crash, crashes in out.items():
		if crash.pc != "0xcafecafe":
			continue
		found = False
		for old in old_dedup_crashes:
			if crash.equal_json(json.load(open(f'{notimpl_dir}/{old}/crash_info.json', 'r'))):
				print(f'duplicate crashes found for {notimpl_dir}/{old}')
				for c in crashes:
					os.system(f'cp {c} {notimpl_dir}/{old}/')
				found = True
				break
		if not found:
			print(f'new crash!! writing to {notimpl_dir}/{i}')	
			os.system(f'mkdir -p {notimpl_dir}/{i}')
			open(f'{notimpl_dir}/{i}/crashlog.txt', 'w+').write(crash.full_log)
			open(f'{notimpl_dir}/{i}/crash_info.json', 'w+').write(json.dumps(crash.__dict__))
			for c in crashes:
				os.system(f'cp {c} {notimpl_dir}/{i}/')
			i+=1
					
def setup_args():
    """Returns an initialized argument parser."""
    parser = argparse.ArgumentParser()

    # add flags
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="triage all crashes (not just newest ones)",
    )
        
    parser.add_argument("harness", help="Path to the harness.")

    return parser


if __name__ == "__main__":

	arg_parser = setup_args()
	args = arg_parser.parse_args()
	do_triage(args.harness, args.all)

	
