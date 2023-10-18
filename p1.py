import subprocess
import os


def process_live_data():
    # Specify the file path
    file_path = "output.csv"

    # Check if the file exists
    if os.path.exists(file_path):
        # Delete the file
        os.remove(file_path)
        print("File deleted successfully.")
    else:
        print("File does not exist.")
    # Run argus command and capture output to a CSV file
    command = "echo 'ubuntu' | sudo -S argus -i wlo1 -w - | ra -s saddr,sport,daddr,dport,dload,spkts,sbytes,dloss,dbytes,smeansz,sload,dmeansz,rate -c , -u - > output.csv"
    subprocess.run(command, shell=True)


process_live_data()