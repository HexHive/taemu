import argparse
from loguru import logger
from typing import Literal
from common import list_tas

def main(fuzz_mode: Literal["org", "df", "all"] = "all", tees: list[str] = None, regen_coverage: bool = False):
    all_tas: set[str] = list_tas()
    filtered_tas = filter(lambda ta: any(tee in ta for tee in tees), all_tas)
    
    
    if regen_coverage:
        for ta in filtered_tas:
            gen_coverage(fuzz_mode, ta, pre_clean=True)
    
    for ta in filtered_tas:
        
        if fuzz_mode == "org" or fuzz_mode == "all":
            org_graph = org_control_flow_graph(ta)
        
        if fuzz_mode == "df" or fuzz_mode == "all":
            df_graph = df_control_flow_graph(ta)
        
        if fuzz_mode == "all":
            uniq_trace = compare_graphs(org_graph, df_graph)
            logger.info(f"Unique traces: {uniq_trace}")
            
    res = number_statistics(fuzz_mode, filtered_tas)
    logger.info(f"Number statistics: {res}")
    return res

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fuzz_mode", choices=["org", "df", "all"], default="all")
    parser.add_argument("--tees", nargs="+", default=None)
    parser.add_argument("--gen_coverage", action="store_true", default=False)
    args = parser.parse_args()
    
    main(fuzz_mode=args.fuzz_mode, tees=args.tees, gen_coverage=args.gen_coverage)
