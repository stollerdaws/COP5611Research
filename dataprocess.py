import pandas as pd

# Input and output file paths
results_file = "benchmark_results.csv"
summary_file = "benchmark_summary.csv"

def calculate_averages():
    # Load the results CSV into a DataFrame
    df = pd.read_csv(results_file)
    
    # Group by FileSystem and calculate the average of the relevant columns
    averages = df.groupby("FileSystem")[["WriteTime(s)", "ReadTime(s)", "DeleteTime(s)"]].mean().reset_index()
    
    # Add a column for StorageSize(KB) (assuming it's constant across iterations)
    storage_size = df.groupby("FileSystem")["StorageSize(KB)"].first().reset_index()
    averages = averages.merge(storage_size, on="FileSystem")
    
    # Save the averages to a new CSV file
    averages.to_csv(summary_file, index=False)
    print(f"Averages saved to {summary_file}")

if __name__ == "__main__":
    calculate_averages()
