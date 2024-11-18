import pandas as pd
import matplotlib.pyplot as plt

# Input file paths
summary_file = "benchmark_summary.csv"

def plot_graphs():
    # Load the summary CSV
    df = pd.read_csv(summary_file)

    # Set the index to FileSystem for easier plotting
    df.set_index("FileSystem", inplace=True)

    # Create bar plots for each metric
    metrics = ["WriteTime(s)", "ReadTime(s)", "DeleteTime(s)", "StorageSize(KB)"]
    
    for metric in metrics:
        plt.figure(figsize=(8, 6))
        df[metric].plot(kind="bar", title=f"{metric} by File System", ylabel=metric, xlabel="File System")
        plt.xticks(rotation=45)
        plt.tight_layout()
        # Save the plot to a file
        plt.savefig(f"{metric}_comparison.png")
        plt.show()

if __name__ == "__main__":
    plot_graphs()
