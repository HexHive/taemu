import matplotlib.pyplot as plt
import numpy as np
from common import RawFuzzingInfo, BB, parse_cov, FuzzMode
from typing import List
from collect_cov import FuzzingInfo


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
        fuzzing_info.unique_cov_bbs = unique_bbs_ts_based


def org_control_flow_graph(fuzzing_info_list: List[FuzzingInfo]):
    ## plt
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
    
    whole_fig, axes = plt.subplots(rows, cols, figsize=(fig_width, fig_height), 
                                    constrained_layout=True)
    whole_fig.suptitle('Unique Coverage Basic Blocks Over Time', fontsize=16, fontweight='bold')
    
    # Flatten axes array if needed
    if num_plots == 1:
        axes = [axes]
    else:
        axes = axes.flatten() if hasattr(axes, 'flatten') else [axes]
    
    # Use a beautiful color palette
    colors = plt.cm.viridis(np.linspace(0, 1, num_plots))
    
    for idx, fuzzing_info in enumerate(fuzzing_info_list):
        ax = axes[idx]
        unique_cov_bbs = fuzzing_info.unique_cov_bbs
        
        if not unique_cov_bbs:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax.transAxes)
            ax.set_title(f"{fuzzing_info.raw_fuzzing_info.ta_name}", fontsize=10)
            ax.axis('off')
            continue
        
        # Extract timestamps and counts, convert timestamps to int for proper sorting
        timestamp_strs = list(unique_cov_bbs.keys())
        # Sort by integer value of timestamp
        timestamp_strs_sorted = sorted(timestamp_strs, key=lambda x: int(x) if str(x).isdigit() else 0)
        counts = [len(unique_cov_bbs[ts]) for ts in timestamp_strs_sorted]
        
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
                color=colors[idx], 
                linewidth=2.5, 
                marker='o', 
                markersize=5,
                markerfacecolor=colors[idx],
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
    # key: vanilla id, value: set of dfs
    grouped_df_bbs = {}
    for fuzzing_info in fuzzing_info_list:
        if fuzzing_info.raw_fuzzing_info.fuzz_mode != FuzzMode.DF:
            continue
        curr_linked_ta_finfo: RawFuzzingInfo = fuzzing_info.linked_ta_finfo
        if curr_linked_ta_finfo.id not in grouped_df_bbs:
            grouped_df_bbs[curr_linked_ta_finfo.id] = []
            
        grouped_df_bbs[curr_linked_ta_finfo.id].append(fuzzing_info.unique_cov_bbs)

    # paint the grouped_df_bbs
    whole_fig = plt.figure()
    return whole_fig
