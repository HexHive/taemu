import matplotlib.pyplot as plt
import numpy as np
from common import RawFuzzingInfo, BB, parse_cov, FuzzMode
from typing import List
from collect_cov import FuzzingInfo
from loguru import logger


def parse_unique_bbs(fuzzing_info_list: List[FuzzingInfo]):
    for fuzzing_info in fuzzing_info_list:
        raw_fuzzing_info: RawFuzzingInfo = fuzzing_info.raw_fuzzing_info
        unique_bbs_ts_based = {}
        cov_bbs: dict[str, list[BB]] = parse_cov(
            raw_fuzzing_info.tee,
            raw_fuzzing_info.ta_name,
            raw_fuzzing_info.cov_dir,
        )
        for timestamp, bbs in cov_bbs.items():
            if timestamp not in unique_bbs_ts_based:
                unique_bbs_ts_based[timestamp] = set()
            unique_bbs_ts_based[timestamp].update(bbs)
        fuzzing_info.unique_cov_bbs_distribution = unique_bbs_ts_based


        
def org_control_flow_graph(fuzzing_info_list: List[FuzzingInfo]):
    num_plots = len([each for each in fuzzing_info_list if each.raw_fuzzing_info.fuzz_mode == FuzzMode.ORG])
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
    
    whole_fig, axes = plt.subplots(rows, cols, figsize=(fig_width, fig_height), 
                                    constrained_layout=True)
    whole_fig.suptitle('Unique Coverage Basic Blocks Over Time', fontsize=16, fontweight='bold')
    
    # Flatten axes array if needed
    if num_plots == 1:
        axes = [axes]
    else:
        axes = axes.flatten() if hasattr(axes, 'flatten') else [axes]
    
    colors = plt.cm.viridis(np.linspace(0, 1, num_plots))
    
    idx = 0
    for fuzzing_info in fuzzing_info_list:
        if fuzzing_info.raw_fuzzing_info.fuzz_mode != FuzzMode.ORG:
            continue
        ax = axes[idx]
        color = colors[idx]
        idx += 1
        unique_cov_bbs = fuzzing_info.unique_cov_bbs_distribution
        
        if not unique_cov_bbs:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax.transAxes)
            ax.set_title(f"{fuzzing_info.raw_fuzzing_info.ta_name}", fontsize=10)
            ax.axis('off')
            continue
        
        # Extract timestamps and counts, convert timestamps to int for proper sorting
        timestamp_strs = list(unique_cov_bbs.keys())
        # Sort by integer value of timestamp
        timestamp_strs_sorted = sorted(timestamp_strs, key=lambda x: int(x) if str(x).isdigit() else 0)
        accumulated_bbs = set()
        counts = []
        for ts in timestamp_strs_sorted:
            accumulated_bbs.update(unique_cov_bbs[ts])
            counts.append(len(accumulated_bbs))
        
        fuzzing_info.accumulated_cov_bbs = accumulated_bbs
        # Convert to numeric for better plotting (use indices if timestamps are not numeric)
        try:
            # Try to convert timestamps to integers for x-axis
            timestamp_ints = [int(ts) for ts in timestamp_strs_sorted]
            x_values = timestamp_ints
            x_labels = timestamp_strs_sorted
        except (ValueError, TypeError):
            # If conversion fails, use string indices
            x_values = range(len(timestamp_strs_sorted))
            x_labels = timestamp_strs_sorted
        
        # Plot curve with beautiful styling
        ax.plot(x_values, counts, 
                color=color, 
                linewidth=2.5, 
                marker='o', 
                markersize=5,
                markerfacecolor=color,
                markeredgecolor='white',
                markeredgewidth=1,
                alpha=0.85,
                linestyle='-',
                label=f"{fuzzing_info.raw_fuzzing_info.ta_name}")
        
        # Formatting
        ax.set_xlabel('Timestamp', fontsize=10, fontweight='bold')
        ax.set_ylabel('Unique BB Count', fontsize=10, fontweight='bold')
        ax.set_title(f"{fuzzing_info.raw_fuzzing_info.ta_name}", fontsize=11, fontweight='bold', pad=10)
        ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.8)
        ax.tick_params(axis='y', labelsize=9)
        
        # Handle x-axis labels
        if len(x_labels) > 15:
            # Show fewer labels to avoid crowding
            step = max(1, len(x_labels) // 15)
            tick_positions = x_values[::step]
            tick_labels = [x_labels[i] for i in range(0, len(x_labels), step)]
            ax.set_xticks(tick_positions)
            ax.set_xticklabels(tick_labels, rotation=45, ha='right', fontsize=8)
        else:
            ax.set_xticks(x_values)
            ax.set_xticklabels(x_labels, rotation=45, ha='right', fontsize=8)
    
    
    # Hide unused subplots
    for idx in range(num_plots, len(axes)):
        axes[idx].axis('off')
    
    plt.tight_layout()
    return whole_fig


def df_control_flow_graph(fuzzing_info_list: List[FuzzingInfo]):
    # key: vanilla id, value: list of df fuzzing_info objects
    grouped_df_bbs = {}
    # Create a mapping from id to vanilla FuzzingInfo for quick lookup
    vanilla_fuzzing_info_map = {}
    for fuzzing_info in fuzzing_info_list:
        if fuzzing_info.raw_fuzzing_info.fuzz_mode == FuzzMode.ORG:
            vanilla_fuzzing_info_map[fuzzing_info.raw_fuzzing_info.id] = fuzzing_info
    
    for fuzzing_info in fuzzing_info_list:
        if fuzzing_info.raw_fuzzing_info.fuzz_mode != FuzzMode.DF:
            continue
        curr_linked_ta_finfo: RawFuzzingInfo = fuzzing_info.linked_ta_finfo
        if curr_linked_ta_finfo.id not in grouped_df_bbs:
            grouped_df_bbs[curr_linked_ta_finfo.id] = []
            
        grouped_df_bbs[curr_linked_ta_finfo.id].append(fuzzing_info)

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
    
    whole_fig, axes = plt.subplots(rows, cols, figsize=(fig_width, fig_height), 
                                    constrained_layout=True)
    
    whole_fig.suptitle('DF Fuzzing Coverage Comparison', fontsize=16, fontweight='bold')
    
    # Flatten axes array if needed
    if num_groups == 1:
        axes = [axes]
    else:
        axes = axes.flatten() if hasattr(axes, 'flatten') else [axes]
    
    # Color palette for the three segments
    old_color = '#E63946'       # Red for old coverage (lost from vanilla)
    overlapped_color = '#2E86AB'  # Blue for overlapped coverage
    new_color = '#A23B72'      # Purple for new coverage
    
    for idx, (vanilla_id, df_fuzzing_infos) in enumerate(grouped_df_bbs.items()):
        # put all df jobs of one ta harness inside a subplot
        ax = axes[idx]
        
        # Find the vanilla FuzzingInfo
        vanilla_fuzzing_info: FuzzingInfo | None = vanilla_fuzzing_info_map.get(vanilla_id)
        if vanilla_fuzzing_info is None:
            logger.error(f"[-] No vanilla fuzzing info for {vanilla_id}")
            ax.text(0.5, 0.5, f'No vanilla fuzzing info\nfor {vanilla_id}', 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title(f"Group: {vanilla_id}", fontsize=10)
            ax.axis('off')
            continue
        
        # Calculate total unique BBs from vanilla (across all timestamps)
        vanilla_all_bbs = vanilla_fuzzing_info.accumulated_cov_bbs
        vanilla_count = len(vanilla_all_bbs)
        
        # Prepare data for bars
        bar_labels = []
        overlapped_segments = []
        new_segments = []
        old_segments = []
        
        for df_fuzzing_info in df_fuzzing_infos:
            # Calculate total unique BBs from DF fuzzing_info
            each_df_all_bbs = set()
            if df_fuzzing_info.unique_cov_bbs:
                for bbs_set in df_fuzzing_info.unique_cov_bbs.values():
                    each_df_all_bbs.update(bbs_set)
            
            # Calculate new unique BBs (those in DF but not in vanilla)
            new_bbs = each_df_all_bbs - vanilla_all_bbs
            old_bbs = vanilla_all_bbs - each_df_all_bbs
            new_count = len(new_bbs)
            old_count = len(old_bbs)
            
            # Store data
            bar_labels.append(df_fuzzing_info.raw_fuzzing_info.ta_name)
            overlapped_count = len(each_df_all_bbs & vanilla_all_bbs)
            overlapped_segments.append(overlapped_count)
            new_segments.append(new_count)
            old_segments.append(old_count)
            
        if len(bar_labels) == 0:
            ax.text(0.5, 0.5, 'No DF fuzzing info', 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title(f"Group: {vanilla_id}", fontsize=10)
            ax.axis('off')
            continue
        
        # Create stacked bar chart
        x_pos = np.arange(len(bar_labels))
        width = 0.6
        
        # Plot stacked bars: old (bottom), overlapped (middle), new (top)
        bars1 = ax.bar(x_pos, old_segments, width, label='Old Coverage', 
                       color=old_color, alpha=0.8)
        bars2 = ax.bar(x_pos, overlapped_segments, width, bottom=old_segments, 
                       label='Overlapped Coverage', color=overlapped_color, alpha=0.8)
        bars3 = ax.bar(x_pos, new_segments, width, 
                       bottom=[old + ovl for old, ovl in zip(old_segments, overlapped_segments)], 
                       label='New Coverage', color=new_color, alpha=0.8)
        
        # Formatting
        ax.set_xlabel('DF Fuzzing Info', fontsize=10, fontweight='bold')
        ax.set_ylabel('Unique BB Count', fontsize=10, fontweight='bold')
        ax.set_title(f"Group: {vanilla_id}", fontsize=11, fontweight='bold', pad=10)
        ax.set_xticks(x_pos)
        ax.set_xticklabels(bar_labels, rotation=45, ha='right', fontsize=8)
        ax.legend(loc='upper right', fontsize=9)
        ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.8, axis='y')
        ax.tick_params(axis='y', labelsize=9)
        
        # Add value labels on bars
        for i, (old, ovl, new) in enumerate(zip(old_segments, overlapped_segments, new_segments)):
            # Old segment label
            if old > 0:
                ax.text(i, old / 2, str(old), ha='center', va='center', 
                       fontsize=8, fontweight='bold', color='white')
            # Overlapped segment label
            if ovl > 0:
                ax.text(i, old + ovl / 2, str(ovl), ha='center', va='center', 
                       fontsize=8, fontweight='bold', color='white')
            # New segment label
            if new > 0:
                ax.text(i, old + ovl + new / 2, str(new), ha='center', va='center', 
                       fontsize=8, fontweight='bold', color='white')
    
    # Hide unused subplots
    for idx in range(num_groups, len(axes)):
        axes[idx].axis('off')
    
    plt.tight_layout()
    return whole_fig
