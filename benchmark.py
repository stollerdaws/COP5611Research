import subprocess
import time

# Configuration
file_systems = {
    "PQC": ("pqc_fs", "str"),
    "AES": ("aes_fs", "rts"),
    "No_Encryption": ("plain_fs", "rrr")
}
test_file = "/tmp/test_file"
test_file_size = 1 * 1024  # 1 KB, can be adjusted as needed
results_file = "benchmark_results.csv"
num_iterations = 5000

def run_shell_command(command):
    """Run a shell command and return the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed: {command}\nError: {result.stderr}")
        return None
    return result.stdout.strip()

def create_test_file():
    """Create a test file of the specified size."""
    print("Creating test file...")
    # Generate a file with repeated 'A's of the desired size
    run_shell_command(f"truncate -s {test_file_size}K {test_file}")

def get_directory_size(directory):
    """Get the size of the specified directory."""
    size_output = run_shell_command(f"ls -l {directory} | awk '{{total += $5}} END {{print total}}'")
    if not size_output or not size_output.isdigit():
        print(f"Failed to retrieve size for directory: {directory}. Output: {size_output}")
        return "Error"
    return int(size_output)  # Size in bytes

def test_file_system(fs_name, mount_point, storage_dir):
    results = []
    test_path = f"{mount_point}/test_file"
    storage_path = f"{storage_dir}"
    
    # Test Write
    print(f"Testing write on {fs_name}...")
    start_time = time.time()
    for i in range(10):  # Write 10 smaller files
        run_shell_command(f"echo 'Test data {i}' > {test_path}_{i}")
    write_time = time.time() - start_time
    results.append(write_time)
    
    # Test Read
    print(f"Testing read on {fs_name}...")
    start_time = time.time()
    for i in range(10):
        run_shell_command(f"cat {test_path}_{i} > /dev/null")
    read_time = time.time() - start_time
    results.append(read_time)
    
    # Test Space
    print(f"Measuring storage directory size for {fs_name}...")
    storage_size = get_directory_size(storage_path)
    results.append(storage_size)

    # Test Delete
    print(f"Testing delete on {fs_name}...")
    start_time = time.time()
    for i in range(10):
        run_shell_command(f"rm {test_path}_{i}")
    delete_time = time.time() - start_time
    results.append(delete_time)
    
    return results

def main():
    # Prepare test file
    create_test_file()

    # Write header for results
    with open(results_file, "w") as f:
        f.write("Iteration,FileSystem,WriteTime(s),ReadTime(s),StorageSize(KB),DeleteTime(s)\n")
    
    for iteration in range(1, num_iterations + 1):
        for fs_name, (mount_point, storage_dir) in file_systems.items():
            print(f"Iteration {iteration}: Testing {fs_name}...")
            
            # Check if the file system is mounted
            mount_status = run_shell_command(f"mount | grep {mount_point}")
            if not mount_status:
                print(f"{fs_name} is not mounted. Please mount and retry.")
                continue

            results = test_file_system(fs_name, mount_point, storage_dir)
            print(f"{fs_name} results: {results}")
            
            # Log results
            with open(results_file, "a") as f:
                f.write(f"{iteration},{fs_name},{','.join(map(str, results))}\n")
    
    print("Benchmark completed. Results saved to", results_file)

if __name__ == "__main__":
    main()
