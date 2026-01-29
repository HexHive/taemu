from eval.graphs.collect_cov import GroupedFuzzingInfo
import matplotlib.pyplot as plt
import numpy as np
from common import RawFuzzingInfo, BB, parse_cov, FuzzMode
from typing import List
from collect_cov import FuzzingInfo, GroupedFuzzingInfo, Coverage
from loguru import logger
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Callable
import os
from collect_cov import gen_coverage_files
from common import parse_drcov

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


def parse_unique_bbs(fuzzing_info_list: List[FuzzingInfo]):

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
        fuzzing_info.unique_cov_bbs_distribution = unique_bbs_ts_based

        timestamp_strs = list(unique_bbs_ts_based.keys())
        timestamp_strs_sorted = sorted(
            timestamp_strs, key=lambda x: int(x) if str(x).isdigit() else 0
        )
        accumulated_bbs = set()
        for ts in timestamp_strs_sorted:
            accumulated_bbs.update(unique_bbs_ts_based[ts])
        fuzzing_info.accumulated_cov_bbs = accumulated_bbs

    with ThreadPoolExecutor(max_workers=30) as ex:
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


def org_control_flow_graph(
    fuzzing_info_list: List[FuzzingInfo],
    max_timestamps: int,
    *,
    grouping_field_name: Optional[str] = None,
    show_rate: bool = False,
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
        "Unique Coverage Basic Blocks Over Time", fontsize=16, fontweight="bold"
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
            "Unique Basic Block Count" if not show_rate else "Coverage Rate (%)",
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
    grouped_df_bbs = {}

    vanilla_fuzzing_info_map = {}
    for fuzzing_info in fuzzing_info_list:
        if fuzzing_info.raw_fuzzing_info.fuzz_mode == FuzzMode.ORG:
            field_value = getattr(fuzzing_info.raw_fuzzing_info, field_name)
            if field_value not in vanilla_fuzzing_info_map:
                vanilla_fuzzing_info_map[field_value] = GroupedFuzzingInfo(
                    RawFuzzingInfo(
                        id=field_value,
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
                    harness_path=fuzzing_info.raw_fuzzing_info.harness_path,
                ),
                Coverage(uniq_identity=bar_field_value, max_nodes=0, cfg=None),
                [],
                {},
                set(),
            )
        _merge(grouped_df_bbs[field_value][bar_field_value], fuzzing_info)

    return vanilla_fuzzing_info_map, grouped_df_bbs


def gather_suspicious_inputs_covs(df_bar_key: str, df_group_finfo: GroupedFuzzingInfo, bar_field_name: str, bk_suspicious_inputs_cov_rdir: str) -> set[BB]:
    # align with x axis, so should be id or harness_path
    suspicious_inputs_bbs = set()
    harness_path = df_group_finfo.raw_fuzzing_info.harness_path
    suspicious_inputs_covs = os.path.join(bk_suspicious_inputs_cov_rdir, 
        harness_path[harness_path.rfind("TA_GP_emulator/")+len("TA_GP_emulator/"):], 
        "out", 
        "cov"
    )
    if bar_field_name == "id":
        file = df_bar_key.split("_")[0] + ".cov"
        suspicious_inputs_bbs=parse_drcov(tee=df_group_finfo.raw_fuzzing_info.tee,
            ta=df_group_finfo.raw_fuzzing_info.ta_name,
            path=os.path.join(suspicious_inputs_covs, file)
        )
    elif bar_field_name == "harness_path":
        assert df_bar_key == harness_path
        for file in os.listdir(suspicious_inputs_covs):
            if file.endswith(".cov"):
                suspicious_inputs_bbs.update(
                    parse_drcov(tee=df_group_finfo.raw_fuzzing_info.tee,
                    ta=df_group_finfo.raw_fuzzing_info.ta_name,
                    path=os.path.join(suspicious_inputs_covs, file)
                ))
        
    else:
        raise ValueError(f"Invalid bar field name: {bar_field_name}")
    return suspicious_inputs_bbs

def df_control_flow_graph(
    fuzzing_info_list: List[FuzzingInfo],
    *,
    grouping_field_name: str,
    bar_field_name: str,
    bk_suspicious_inputs_cov_rdir: str,
    show_rate: bool = False,
):
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

    # Color palette for the three segments
    old_color = "#E63946"
    overlapped_color = "#2E86AB"  # Blue for overlapped coverage
    new_color = "#A23B72"  # Purple for new coverage

    for idx, (vanilla_id, df_fuzzing_dir) in enumerate[tuple[str, dict[str, GroupedFuzzingInfo]]](grouped_df_bbs.items()):
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

        overlapped_segments = []
        new_segments = []
        old_segments = []

        for df_bar_key in df_fuzzing_dir:
            current_harness_path = df_fuzzing_dir[
                df_bar_key
            ].raw_fuzzing_info.harness_path
            print(f"current_harness_path: {current_harness_path}")
            print(f"df_bar_key: {df_bar_key}")

            # Calculate total unique BBs from vanilla (across all timestamps)
            vanilla_all_bbs = set()
            coverage_denominator = 0
            for each_vanilla in vanilla_fuzzing_info.fuzzing_infos:
                vanilla_field_value = each_vanilla.raw_fuzzing_info.harness_path
                if vanilla_field_value == current_harness_path:
                    vanilla_all_bbs.update(each_vanilla.accumulated_cov_bbs)
                    coverage_denominator += each_vanilla.raw_covs.max_nodes

            # Calculate covs related to suspicious_inputs
            suspicious_inputs_bbs = gather_suspicious_inputs_covs(df_bar_key, df_fuzzing_dir[df_bar_key], bar_field_name, bk_suspicious_inputs_cov_rdir)

            org_all_bbs = suspicious_inputs_bbs
            # org_all_bbs = vanilla_all_bbs


            # Calculate total unique BBs from DF fuzzing_info
            each_bar_all_bbs = df_fuzzing_dir[df_bar_key].accumulated_cov_bbs

            # Calculate new unique BBs (those in DF but not in vanilla)
            new_bbs = each_bar_all_bbs - org_all_bbs
            old_bbs = org_all_bbs - each_bar_all_bbs
            new_count = len(new_bbs)
            old_count = len(old_bbs)

            # Store data
            bar_labels.append(
                f"{bar_prefix}{bar_id if bar_field_name == 'id' else naming_change(df_bar_key)}"
            )
            bar_id += 1
            overlapped_count = len(each_bar_all_bbs & org_all_bbs)
            overlapped_segments.append(overlapped_count)
            new_segments.append(new_count)
            old_segments.append(old_count)

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

        # Create stacked bar chart
        x_pos = np.arange(len(bar_labels))
        width = 0.6

        # Plot stacked bars: old (bottom), overlapped (middle), new (top)
        bars1 = ax.bar(
            x_pos,
            (
                old_segments
                if not show_rate
                else [old / coverage_denominator * 100 for old in old_segments]
            ),
            width,
            label="Exploration-only Coverage",
            color=old_color,
            alpha=0.8,
        )
        bars2 = ax.bar(
            x_pos,
            (
                overlapped_segments
                if not show_rate
                else [ovl / coverage_denominator * 100 for ovl in overlapped_segments]
            ),
            width,
            bottom=(
                old_segments
                if not show_rate
                else [old / coverage_denominator * 100 for old in old_segments]
            ),
            label="Exploration-Snapshot Shared Coverage",
            color=overlapped_color,
            alpha=0.8,
        )
        bars3 = ax.bar(
            x_pos,
            (
                new_segments
                if not show_rate
                else [new / coverage_denominator * 100 for new in new_segments]
            ),
            width,
            bottom=(
                [old + ovl for old, ovl in zip(old_segments, overlapped_segments)]
                if not show_rate
                else [
                    (old + ovl) / coverage_denominator * 100
                    for old, ovl in zip(old_segments, overlapped_segments)
                ]
            ),
            label="Snapshot Fuzzing-only Coverage",
            color=new_color,
            alpha=0.8,
        )

        # Calculate max bar height and set y-axis limit with some padding
        if not show_rate:
            max_bar_height = max(
                old + ovl + new
                for old, ovl, new in zip(
                    old_segments, overlapped_segments, new_segments
                )
            )
        else:
            max_bar_height = max(
                (old + ovl + new) / coverage_denominator * 100
                for old, ovl, new in zip(
                    old_segments, overlapped_segments, new_segments
                )
            )

        # Formatting
        ax.set_xlabel(
            "Double Fetch Snapshot IDs", fontsize=10, fontweight="bold", labelpad=10
        )
        ax.set_ylabel(
            "Unique Basic Block Count" if not show_rate else "Coverage Rate (%)",
            fontsize=10,
            fontweight="bold",
        )
        ax.set_title(
            f"{grouping_field_name}: {naming_change(vanilla_id)}",
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
        ax.legend(loc="upper right", fontsize=9)
        ax.grid(True, alpha=0.3, linestyle="--", linewidth=0.8, axis="y")
        ax.tick_params(axis="y", labelsize=9)

        # Add value labels on bars
        """
        for i, (old, ovl, new) in enumerate(
            zip(old_segments, overlapped_segments, new_segments)
        ):
            # Old segment label
            if old > 0:
                ax.text(
                    i,
                    old / 2,
                    str(old),
                    ha="center",
                    va="center",
                    fontsize=8,
                    fontweight="bold",
                    color="white",
                )
            # Overlapped segment label
            if ovl > 0:
                ax.text(
                    i,
                    old + ovl / 2,
                    str(ovl),
                    ha="center",
                    va="center",
                    fontsize=8,
                    fontweight="bold",
                    color="white",
                )
            # New segment label
            if new > 0:
                ax.text(
                    i,
                    old + ovl + new / 2,
                    str(new),
                    ha="center",
                    va="center",
                    fontsize=8,
                    fontweight="bold",
                    color="white",
                )
        """

    # Hide unused subplots
    for idx in range(num_groups, len(axes)):
        axes[idx].axis("off")

    plt.tight_layout()
    return whole_fig
