import matplotlib.pyplot as plt
import pickle
import hashlib
import json
import numpy as np
from common import RawFuzzingInfo, BB, parse_cov, FuzzMode, parse_drcov
from typing import List
from collect_cov import FuzzingInfo, GroupedFuzzingInfo, Coverage
from loguru import logger
from tqdm import tqdm
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional, Callable
import os

def naming_change(names: list[str] | str) -> list[str] | str:
    names_map = {
        "qsee": "QSEE",
        "mitee": "Mitee",
        "teegris": "TeeGris",
        "beanpod": "Beanpod",
        "mitee": "MiTEE",
    }
    new_names = []
    if isinstance(names, str):
        names = [names]
    for name in names:
        name_lower = name.lower()
        for key, value in names_map.items():
            if key in name_lower:
                idx = name_lower.index(key)
                name = name[:idx] + value + name[idx + len(value) :]

        if isinstance(name, str) and "/" in name:
            name = name.split("/")[-1]
        new_names.append(name)
    return new_names if len(new_names) > 1 else new_names[0]

def _worker(fuzzing_info: FuzzingInfo):
    raw_fuzzing_info: RawFuzzingInfo = fuzzing_info.raw_fuzzing_info
    unique_bbs_ts_based = {}
    unique_bbs_ts_based[0] = set()
    cov_bbs: dict[int, list[BB]] = parse_cov(
        raw_fuzzing_info.tee,
        raw_fuzzing_info.ta_name,
        raw_fuzzing_info.cov_dir,
    )
    
    for timestamp, bbs in cov_bbs.items():
        if timestamp not in unique_bbs_ts_based:
            unique_bbs_ts_based[timestamp] = set()
        unique_bbs_ts_based[timestamp].update(bbs)
        fuzzing_info.raw_bbs.append(bbs)
    fuzzing_info.unique_cov_bbs_distribution = unique_bbs_ts_based

    timestamp_strs = list(unique_bbs_ts_based.keys())
    timestamp_strs_sorted = sorted(
        timestamp_strs, key=lambda x: int(x) if str(x).isdigit() else 0
    )
    accumulated_bbs = set()
    for ts in timestamp_strs_sorted:
        accumulated_bbs.update(unique_bbs_ts_based[ts])
    fuzzing_info.accumulated_cov_bbs = accumulated_bbs

def parse_unique_bbs(fuzzing_info_list: List[FuzzingInfo]):
    with ProcessPoolExecutor(max_workers=50) as ex:
        futures = [
            ex.submit(_worker, fuzzing_info) for fuzzing_info in fuzzing_info_list
        ]
        for fut in tqdm(
            as_completed(futures),
            total=len(fuzzing_info_list),
            desc="Parsing unique bbs for each TA",
        ):
            _ = fut.result()
    logger.info(f"[+] Finished parsing unique bbs for all TAs")


def _merge(
    new: GroupedFuzzingInfo,
    old: FuzzingInfo,
    cov_update_func: Callable[[Coverage, Coverage], Coverage] = lambda x, y: Coverage(
        uniq_identity=f"{x.uniq_identity}_{y.uniq_identity}",
        max_nodes=x.max_nodes + y.max_nodes,
        cfg=None,
    ),
):
    def _merge_distribution(
        distribution1: dict[str, set[BB]], distribution2: dict[str, set[BB]]
    ):
        for timestamp, bbs in distribution2.items():
            if timestamp not in distribution1:
                distribution1[timestamp] = set()
            distribution1[timestamp].update(bbs)
        return distribution1

    new.unique_cov_bbs_distribution = _merge_distribution(
        new.unique_cov_bbs_distribution,
        old.unique_cov_bbs_distribution,
    )
    new.fuzzing_infos.append(old)
    new.accumulated_cov_bbs = new.accumulated_cov_bbs | old.accumulated_cov_bbs
    new.raw_covs = cov_update_func(
        new.raw_covs,
        old.raw_covs,
    )


def _group_fuzzing_info_list(
    fuzzing_info_list: List[FuzzingInfo],
    field_name: str,
) -> dict[str, GroupedFuzzingInfo]:

    new_fuzzing_imap_by_field: dict[str, GroupedFuzzingInfo] = {}
    for fuzzing_info in fuzzing_info_list:
        field_value = getattr(fuzzing_info.raw_fuzzing_info, field_name)
        if field_value not in new_fuzzing_imap_by_field:
            new_fuzzing_imap_by_field[field_value] = GroupedFuzzingInfo(
                RawFuzzingInfo(
                    id=field_value,
                    harness_path=fuzzing_info.raw_fuzzing_info.harness_path,
                ),
                Coverage(uniq_identity=field_value, max_nodes=0, cfg=None),
                [],
                {},
                set(),
            )
        _merge(new_fuzzing_imap_by_field[field_value], fuzzing_info)
    return new_fuzzing_imap_by_field


def org_dump_info(y_values, name, path):
    info_path = os.path.join(path, "eval/graphs/rawinfo/")
    if not os.path.exists(info_path):
        os.makedirs(info_path)
    open(os.path.join(info_path, f'org_{name}.json'), 'w+').write(
        json.dumps(y_values)
    )

def org_control_flow_graph(
    fuzzing_info_list: List[FuzzingInfo],
    max_timestamps: int,
    *,
    grouping_field_name: Optional[str] = None,
    show_rate: bool = False,
    path: str = None,
):
    fuzzing_info_list = [
        each
        for each in fuzzing_info_list
        if each.raw_fuzzing_info.fuzz_mode == FuzzMode.ORG
    ]
    if grouping_field_name is not None:
        fuzzing_info_list = _group_fuzzing_info_list(
            fuzzing_info_list, grouping_field_name
        ).values()

    num_plots = len(fuzzing_info_list)
    if num_plots == 0:
        return plt.figure()

    # Calculate grid dimensions for subplots
    cols = int(np.ceil(np.sqrt(num_plots)))
    rows = int(np.ceil(num_plots / cols))

    # Adjust figure size based on number of subplots to avoid tight_layout warnings
    base_width = 15
    base_height = 10

    # Increase height for more rows
    fig_height = base_height + (rows - 1) * 3
    fig_width = base_width + (cols - 1) * 2

    whole_fig, axes = plt.subplots(
        rows, cols, figsize=(fig_width, fig_height), constrained_layout=True
    )
    whole_fig.suptitle(
        "Unique BBs Coverage Over Time", fontsize=16, fontweight="bold"
    )

    # Flatten axes array if needed
    if num_plots == 1:
        axes = [axes]
    else:
        axes = axes.flatten() if hasattr(axes, "flatten") else [axes]

    colors = plt.cm.viridis(np.linspace(0, 1, num_plots))

    idx = 0
    for fuzzing_info in fuzzing_info_list:
        ax = axes[idx]
        color = colors[idx]
        idx += 1
        unique_cov_bbs = fuzzing_info.unique_cov_bbs_distribution

        if not unique_cov_bbs:
            ax.text(
                0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes
            )
            ax.set_title(
                f"{naming_change(fuzzing_info.raw_fuzzing_info.id)}", fontsize=10
            )
            ax.axis("off")
            continue

        """
        # check for bbs not in ghidra cfg
        def in_cfg(bb, cfg):
            nodes = cfg.nodes # ONLY WORKS FOR TA  ONLY
            for n in nodes:
                if not "start" in cfg.nodes[n] or not "end" in cfg.nodes[n]: 
                    continue
                if bb.start == int(cfg.nodes[n]["start"],16) or bb.start + bb.size == int(cfg.nodes[n]["start"],16) or bb.start >= int(cfg.nodes[n]["start"],16) and bb.start + bb.size<= int(cfg.nodes[n]["end"],16):
                    return True
            return False
        print("helllo???????")
        unique_bbs = set()
        for ts, bbs in fuzzing_info.unique_cov_bbs_distribution.items():
            for bb in bbs:
                unique_bbs.add(bb)
        print(fuzzing_info.raw_fuzzing_info)
        if "a985_fuzz" in fuzzing_info.raw_fuzzing_info.harness_path:
            for bb in unique_bbs:
                if not in_cfg(bb, fuzzing_info.raw_covs.cfg):
                    print(f'not in cfg {bb}')
            print(fuzzing_info.raw_covs.cfg.nodes)
        """

        # Extract timestamps and counts, convert timestamps to int for proper sorting
        timestamp_strs = list(unique_cov_bbs.keys())
        # Sort by integer value of timestamp
        timestamp_strs_sorted = sorted(
            timestamp_strs, key=lambda x: int(x) if str(x).isdigit() else 0
        )
        accumulated_bbs = set()
        counts = []
        for ts in timestamp_strs_sorted:
            accumulated_bbs.update(unique_cov_bbs[ts])
            counts.append(len(accumulated_bbs))

        # add end point
        timestamp_strs_sorted.append(max_timestamps)
        counts.append(len(accumulated_bbs))

        fuzzing_info.accumulated_cov_bbs = accumulated_bbs  # update for org graph

        timestamp_ints = [int(ts) for ts in timestamp_strs_sorted]
        x_values = [ts / 3600.0 for ts in timestamp_ints]  # Convert seconds to hours

        # Plot curve
        y_values = (
            counts
            if not show_rate
            else [count / fuzzing_info.raw_covs.max_nodes * 100 for count in counts]
        )
        org_dump_info(y_values, naming_change(fuzzing_info.raw_fuzzing_info.id), path)
        ax.plot(
            x_values,
            y_values,
            color=color,
            linewidth=2.5,
            # marker="o",
            # markersize=5,
            # markerfacecolor=color,
            # markeredgecolor="white",
            # markeredgewidth=1,
            alpha=0.85,
            linestyle="-",
            label=f"{naming_change(fuzzing_info.raw_fuzzing_info.id)}",
        )

        # Formatting
        ax.set_xlabel("Duration (hour(s))", fontsize=10, fontweight="bold")
        ax.set_ylabel(
            "Unique BB Count" if not show_rate else "Coverage Rate (%)",
            fontsize=10,
            fontweight="bold",
        )
        ax.set_title(
            f"{fuzzing_info.raw_fuzzing_info.id}",
            fontsize=11,
            fontweight="bold",
            pad=10,
        )
        ax.grid(True, alpha=0.3, linestyle="--", linewidth=0.8)
        ax.tick_params(axis="y", labelsize=9)

        # Format y-axis as percentage when show_rate is enabled
        if show_rate:
            ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{x:.0f}%"))

        ax.set_xlim(0, 24)

        # Set x-axis ticks at 4 hour intervals: 0, 4, 8, 12, 16, 20, 24
        tick_positions = list(range(0, 25, 4))
        ax.set_xticks(tick_positions)
        ax.set_xticklabels(
            [str(t) for t in tick_positions], rotation=45, ha="right", fontsize=8
        )

    # Hide unused subplots
    for idx in range(num_plots, len(axes)):
        axes[idx].axis("off")

    plt.tight_layout()
    return whole_fig


def _group_df_fuzzing_info_list(
    fuzzing_info_list: List[FuzzingInfo], field_name: str, bar_field_name: str
) -> tuple[dict[str, GroupedFuzzingInfo], dict[str, dict[str, GroupedFuzzingInfo]]]:
    # key: vanilla id, value: list of df fuzzing_info objects
    # TODO: here is the shitty and legacy code. Still works but should be refactored
    grouped_df_bbs = {}

    vanilla_fuzzing_info_map = {}
    for fuzzing_info in fuzzing_info_list:
        if fuzzing_info.raw_fuzzing_info.fuzz_mode == FuzzMode.ORG:
            field_value = getattr(fuzzing_info.raw_fuzzing_info, field_name)
            if field_value not in vanilla_fuzzing_info_map:
                vanilla_fuzzing_info_map[field_value] = GroupedFuzzingInfo(
                    RawFuzzingInfo(
                        id=field_value,
                        tee=fuzzing_info.raw_fuzzing_info.tee,
                        ta_name=fuzzing_info.raw_fuzzing_info.ta_name,
                        harness_path=fuzzing_info.raw_fuzzing_info.harness_path,
                    ),
                    Coverage(uniq_identity=field_value, max_nodes=0, cfg=None),
                    [],
                    {},
                    set(),
                )
            _merge(vanilla_fuzzing_info_map[field_value], fuzzing_info)

    for fuzzing_info in fuzzing_info_list:
        if fuzzing_info.raw_fuzzing_info.fuzz_mode != FuzzMode.DF:
            continue
        curr_linked_ta_finfo: RawFuzzingInfo = fuzzing_info.linked_ta_finfo  # org
        field_value = getattr(curr_linked_ta_finfo, field_name)
        if field_value not in grouped_df_bbs:
            grouped_df_bbs[field_value] = {}
        bar_field_value = getattr(fuzzing_info.raw_fuzzing_info, bar_field_name)
        if bar_field_value not in grouped_df_bbs[field_value]:
            grouped_df_bbs[field_value][bar_field_value] = GroupedFuzzingInfo(
                RawFuzzingInfo(
                    id=bar_field_value,
                    tee=fuzzing_info.raw_fuzzing_info.tee,
                    ta_name=fuzzing_info.raw_fuzzing_info.ta_name,
                    harness_path=fuzzing_info.raw_fuzzing_info.harness_path,
                ),
                Coverage(uniq_identity=bar_field_value, max_nodes=0, cfg=None),
                [],
                {},
                set(),
            )
        _merge(grouped_df_bbs[field_value][bar_field_value], fuzzing_info)

    return vanilla_fuzzing_info_map, grouped_df_bbs


def gather_suspicious_inputs_covs(df_bar_key: str, df_group_finfo: GroupedFuzzingInfo, bar_field_name: str, bk_suspicious_inputs_cov_rdir: str) -> list[BB]:
    # align with x axis, so should be id or harness_path
    suspicious_inputs_bbs = list()
    harness_path = df_group_finfo.raw_fuzzing_info.harness_path
    suspicious_inputs_covs = os.path.join(bk_suspicious_inputs_cov_rdir, 
        harness_path[harness_path.rfind("TA_GP_emulator/")+len("TA_GP_emulator/"):], 
        "out", 
        "cov"
    )
    print("bk sus dir???", bk_suspicious_inputs_cov_rdir, suspicious_inputs_covs)
    if bar_field_name == "id":
        file = df_bar_key.split("_")[-2] + ".cov"
        suspicious_inputs_bbs=parse_drcov(tee=df_group_finfo.raw_fuzzing_info.tee,
            ta=df_group_finfo.raw_fuzzing_info.ta_name,
            path=os.path.join(suspicious_inputs_covs, file)
        )
    # elif bar_field_name == "harness_path":
    #     assert df_bar_key == harness_path
    #     for file in os.listdir(suspicious_inputs_covs):
    #         if file.endswith(".cov"):
    #             suspicious_inputs_bbs.extend(
    #                 parse_drcov(tee=df_group_finfo.raw_fuzzing_info.tee,
    #                 ta=df_group_finfo.raw_fuzzing_info.ta_name,
    #                 path=os.path.join(suspicious_inputs_covs, file)
    #             ))        
    else:
        raise ValueError(f"Invalid bar field name: {bar_field_name}")
    return suspicious_inputs_bbs

def longest_overlapped_bbs_trace(suspicious_inputs_bbs: list[BB], df_fuzzing_dir: GroupedFuzzingInfo) -> list[BB]:
    # df_fuzzing_dir is one snapshot df-fuzz dir.
    
    df_bbs_lists: list[list[BB]] = []
    longest_overlapped_bbs = []
    df_bbs_lists.append(suspicious_inputs_bbs)
    for each in df_fuzzing_dir.fuzzing_infos:
        for each_bb in each.raw_bbs:
            df_bbs_lists.append(each_bb)
    
    min_len = min(len(a) for a in df_bbs_lists)        
    for i in range(min_len):
        v = df_bbs_lists[0][i]
        if all(a[i] == v for a in df_bbs_lists):
            longest_overlapped_bbs.append(v)
        else:
            break
    return longest_overlapped_bbs


def df_control_flow_graph(
    fuzzing_info_list: List[FuzzingInfo],
    *,
    bk_suspicious_inputs_cov_rdir: str,
    show_rate: bool = False,
):
    bar_field_name = "id"
    grouping_field_name = "harness_path"
    # vanilla_fuzzing_info_map: merged sth in same subgraph
    # grouped_df_bbs: merged sth in same bar
    vanilla_fuzzing_info_map, grouped_df_bbs = _group_df_fuzzing_info_list(
        fuzzing_info_list, grouping_field_name, bar_field_name
    )

    # paint the grouped_df_bbs
    num_groups = len(grouped_df_bbs)
    if num_groups == 0:
        return plt.figure()

    # Calculate grid dimensions for subplots
    cols = int(np.ceil(np.sqrt(num_groups)))
    rows = int(np.ceil(num_groups / cols))

    # Adjust figure size based on number of subplots
    base_width = 15
    base_height = 10
    fig_height = base_height + (rows - 1) * 3
    fig_width = base_width + (cols - 1) * 2

    whole_fig, axes = plt.subplots(
        rows, cols, figsize=(fig_width, fig_height), constrained_layout=True
    )

    # whole_fig.suptitle("DF Fuzzing Coverage Comparison", fontsize=16, fontweight="bold")

    # Flatten axes array if needed
    if num_groups == 1:
        axes = [axes]
    else:
        axes = axes.flatten() if hasattr(axes, "flatten") else [axes]

    # Color palette for the four segments
    basic_color = "#4A5568"      # Gray for basic (bottom wide bar)
    part_one_color = "#E63946"   # Red for part_one
    part_two_color = "#2E86AB"   # Blue for part_two
    part_three_color = "#A23B72" # Purple for part_three

    for idx, (vanilla_id, df_fuzzing_dir) in enumerate(grouped_df_bbs.items()):
        # vanilla_id: harness_path
        # df_fuzzing_dir: dict, which key is df_snapshot_dir, value is GroupedFuzzingInfo
        
        # put all df jobs of one ta harness inside a subplot
        ax = axes[idx]

        # Find the vanilla FuzzingInfo
        vanilla_fuzzing_info: GroupedFuzzingInfo | None = vanilla_fuzzing_info_map.get(
            vanilla_id
        )
        if vanilla_fuzzing_info is None:
            logger.error(f"[-] No vanilla fuzzing info for {vanilla_id}")
            ax.text(
                0.5,
                0.5,
                f"No vanilla fuzzing info\nfor {vanilla_id}",
                ha="center",
                va="center",
                transform=ax.transAxes,
            )
            ax.set_title(f"Group: {vanilla_id}", fontsize=10)
            ax.axis("off")
            continue

        # Prepare data for bars
        bar_labels = []
        bar_id = 0
        bar_prefix = "S" if bar_field_name == "id" else ""

        # Data lists for the new bar structure
        basic_segments = []      # Wide bottom bar
        part_one_segments = []   # Thin bar 1 on top
        part_two_segments = []   # Thin bar 2 on top
        part_three_segments = [] # Thin bar 3 on top
        coverage_denominators = []
        
        
        def _worker(df_snapshot):
            current_harness_path = df_fuzzing_dir[
                df_snapshot
            ].raw_fuzzing_info.harness_path
            # print(f"current_harness_path: {current_harness_path}")

            # Calculate total unique BBs from vanilla (across all timestamps)
            vanilla_all_bbs = set()
            coverage_denominator = 0
            for each_vanilla in vanilla_fuzzing_info.fuzzing_infos:
                vanilla_field_value = each_vanilla.raw_fuzzing_info.harness_path
                if vanilla_field_value == current_harness_path:
                    vanilla_all_bbs.update(each_vanilla.accumulated_cov_bbs)
                    coverage_denominator += each_vanilla.raw_covs.max_nodes

            df_snapshot_bbs = set(df_fuzzing_dir[df_snapshot].accumulated_cov_bbs)
            
            # Calculate covs related to suspicious_inputs
            suspicious_inputs_bbs = gather_suspicious_inputs_covs(df_snapshot, df_fuzzing_dir[df_snapshot], bar_field_name, bk_suspicious_inputs_cov_rdir)
        
            
            # before df snapshot
            part_basic = set(longest_overlapped_bbs_trace(suspicious_inputs_bbs, df_fuzzing_dir[df_snapshot]))
            
            
            part_one = set(suspicious_inputs_bbs) - part_basic
            part_two = (set(vanilla_all_bbs) & (df_snapshot_bbs - set(suspicious_inputs_bbs))) - part_basic
            part_three = df_snapshot_bbs - part_two - part_one - part_basic

            assert coverage_denominator > 0
            
            return len(part_basic), len(part_one), len(part_two), len(part_three), coverage_denominator

        # launch for one harness
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(_worker, df_snapshot): df_snapshot  for df_snapshot in df_fuzzing_dir}
            
            bar_id = 0
            for future in tqdm(as_completed(futures.keys()), total=len(futures), desc=f"Processing DF snapshots on {vanilla_id}"):
                df_snapshot = futures[future]
                basic_segment_cnt, part_one_segment_cnt, part_two_segment_cnt, part_three_segment_cnt, coverage_denominator = future.result()
                basic_segments.append(basic_segment_cnt)
                part_one_segments.append(part_one_segment_cnt)
                part_two_segments.append(part_two_segment_cnt)   
                part_three_segments.append(part_three_segment_cnt)
                coverage_denominators.append(coverage_denominator)
                
                # Store data
                bar_labels.append(
                    f"{bar_prefix}{bar_id if bar_field_name == 'id' else naming_change(df_snapshot)}"
                )
                bar_id += 1
                
                
        # df_snapshot: like qsee_a985_fuzz_run:id:7ecbd9e7c8dff69ac598e8c9bdcba57d_62849841960499769081805646165961192109
        # df_fuzzing_dir[df_snapshot]: df_fuzzing queue seed covs related to df_snapshot
            
        

        if len(bar_labels) == 0:
            ax.text(
                0.5,
                0.5,
                "No DF fuzzing info",
                ha="center",
                va="center",
                transform=ax.transAxes,
            )
            ax.set_title(f"Group: {vanilla_id}", fontsize=10)
            ax.axis("off")
            continue

        # Create the bar chart with wide bottom bar and three thin bars on top
        x_pos = np.arange(len(bar_labels))
        wide_width = 0.7       # Width for the basic (bottom) bar
        thin_width = 0.2       # Width for each of the three thin bars on top

        # Plot the wide basic bar at the bottom
        basic_values = (
            basic_segments
            if not show_rate
            else [b / d * 100 for b, d in zip(basic_segments, coverage_denominators)]
        )
        ax.bar(
            x_pos,
            basic_values,
            wide_width,
            label="BBs up to Double Fetch",
            color=basic_color,
            alpha=0.8,
        )

        # Calculate the offset for the three thin bars to be centered above the wide bar
        # The three thin bars together span: 3 * thin_width = 0.6
        # Center them: offsets are -thin_width, 0, +thin_width
        thin_offsets = [-thin_width, 0, thin_width]

        # Plot the three thin bars on top of the basic bar
        # Part One (left thin bar)
        part_one_values = (
            part_one_segments
            if not show_rate
            else [p / d * 100 for p, d in zip(part_one_segments, coverage_denominators)]
        )
        ax.bar(
            x_pos + thin_offsets[0],
            part_one_values,
            thin_width,
            bottom=basic_values,
            label="BBs Overlapping With Triggering Seed",
            color=part_one_color,
            alpha=0.8,
        )

        # Part Two (center thin bar)
        part_two_values = (
            part_two_segments
            if not show_rate
            else [p / d * 100 for p, d in zip(part_two_segments, coverage_denominators)]
        )
        ax.bar(
            x_pos + thin_offsets[1],
            part_two_values,
            thin_width,
            bottom=basic_values,
            label="BBs Overlapping With Remaining Exploration BBs",
            color=part_two_color,
            alpha=0.8,
        )

        # Part Three (right thin bar)
        part_three_values = (
            part_three_segments
            if not show_rate
            else [p / d * 100 for p, d in zip(part_three_segments, coverage_denominators)]
        )
        ax.bar(
            x_pos + thin_offsets[2],
            part_three_values,
            thin_width,
            bottom=basic_values,
            label="Double Fetch Unique BBs",
            color=part_three_color,
            alpha=0.8,
        )

        # Calculate max bar height and set y-axis limit with some padding
        max_bar_height = 0
        for i in range(len(bar_labels)):
            base = basic_values[i]
            # Find the tallest thin bar for this x position
            max_thin = max(part_one_values[i], part_two_values[i], part_three_values[i])
            total_height = base + max_thin
            if total_height > max_bar_height:
                max_bar_height = total_height

        # Formatting
        ax.set_xlabel(
            "Double Fetch Snapshot IDs", fontsize=10, fontweight="bold", labelpad=10
        )
        ax.set_ylabel(
            "Unique BB Count" if not show_rate else "Coverage Rate (%)",
            fontsize=10,
            fontweight="bold",
        )
        ax.set_title(
            f"Harness: {naming_change(vanilla_id)}",
            fontsize=11,
            fontweight="bold",
            pad=10,
        )
        ax.set_xticks(x_pos)
        ax.set_xticklabels(bar_labels, rotation=50, ha="right", fontsize=8)

        # Stagger x-axis labels when there are many bars to avoid overlap
        if len(bar_labels) > 25:
            tick_labels = ax.get_xticklabels()
            for i, label in enumerate(tick_labels):
                if i % 2 == 1:
                    label.set_y(label.get_position()[1] - 0.03)
                    # label.set_rotation(90)

        if show_rate:
            ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{x:.0f}%"))
        ax.set_ylim(0, max_bar_height * 1.15)  # Add some padding at the top
        ax.legend(loc="upper right", fontsize=8)
        ax.grid(True, alpha=0.3, linestyle="--", linewidth=0.8, axis="y")
        ax.tick_params(axis="y", labelsize=9)

    # Hide unused subplots
    for idx in range(num_groups, len(axes)):
        axes[idx].axis("off")

    plt.tight_layout()
    return whole_fig
