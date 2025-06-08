import os
import subprocess
from rich import print

from google.cloud import storage

PROJECT_ROOT = os.getcwd()

DISKANN_DATA_ROOT = PROJECT_ROOT + "/data"
COMPASS_DATA_ROOT = os.path.dirname(PROJECT_ROOT) + "/compass/data"

DISKANN_ORAM_ROOT = PROJECT_ROOT + "/oram_data"
COMPASS_ORAM_ROOT = os.path.dirname(PROJECT_ROOT) + "/compass/data"

SUPPORTED_DATASETS = ["sift", "laion100k", "trip", "marco"]

# Usage
bucket_name = 'compass_osdi'

diskann_paths = {
    "marco": [
        "dataset/msmarco_bert/passages.fvecs",
        "dataset/msmarco_bert/queries.fvecs",
    ],
}

compass_paths = {
    "marco": [
        # dataset
        #"dataset/msmarco_bert/passages.fvecs",
        #"dataset/msmarco_bert/queries.fvecs",
        #"dataset/msmarco_bert/gt_10.ivecs",
        
        # index
        "dataset/msmarco_bert/hnsw_128_200_2_ip.index",
        "dataset/msmarco_bert/pq_full_32_ip.index",
        
        # oram
        #"snap/client/msmarco/block_mapping.bin",
        #"snap/client/msmarco/graph_cache.bin",
        #"snap/client/msmarco/hash.bin",
        #"snap/client/msmarco/metadata.bin",
        #"snap/client/msmarco/position_map.bin",
        #"snap/server/msmarco/buckets.bin",
    ]
}


def download_data(bucket_name, dataset, download_compass):
    client = storage.Client.create_anonymous_client()
    bucket = client.bucket(bucket_name)
    blobs = bucket.list_blobs()

    dest_file_path = ""
    for blob in blobs:
        if download_compass:
            dest_file_path = os.path.join(COMPASS_DATA_ROOT, blob.name)
        else:
            dest_file_path = os.path.join(DISKANN_DATA_ROOT + "/datasets", dataset)
            filename = blob.name.split('/')[-1]

            dest_file_path = os.path.join(dest_file_path, filename)    
        
        os.makedirs(os.path.dirname(dest_file_path), exist_ok=True)

        # Check if file already exists locally
        if not os.path.exists(dest_file_path):
            if download_compass and (blob.name not in compass_paths[dataset]):
                continue
            elif not download_compass and (blob.name not in diskann_paths[dataset]):
                continue
            
            print(f"Downloading {dest_file_path}...")
            blob.download_to_filename(dest_file_path)
        else:
            print(f"{dest_file_path} already exists, skipping download.")


def build_oram(dataset, r, efc, pq_bytes):
    oram_dir = os.path.join(DISKANN_ORAM_ROOT, dataset)
    if not os.path.exists(oram_dir):
        print(f"ORAM directory for {dataset} does not exist. Please initialize it first.")
        exit(0)

    dir_for_this_index = os.path.join(oram_dir, f"R{r}_L{efc}_PQ{pq_bytes}")
    os.makedirs(dir_for_this_index, exist_ok=True)

    command = [
        "./oram_initializer",
        " d=", dataset,
        " r=", str(r),
        " e=", str(efc),
        " p=", str(pq_bytes),
    ]
    command = "".join(command)

    print(f"Building ORAM for {dataset} with r={r}, efc={efc}, pq_bytes={pq_bytes}...")
    try:
        subprocess.run(command, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error building ORAM for {dataset}: {e}")
        exit(1)
        
    
def initialize_empty_diskann_directories():
    os.makedirs(DISKANN_DATA_ROOT, exist_ok=True)
    os.makedirs(DISKANN_ORAM_ROOT, exist_ok=True)
    
    DATASET_ROOT = os.path.join(DISKANN_DATA_ROOT, "datasets")
    os.makedirs(DATASET_ROOT, exist_ok=True)

    INDEX_ROOT = os.path.join(DISKANN_DATA_ROOT, "index")
    os.makedirs(INDEX_ROOT, exist_ok=True)

    GRAPH_ROOT = os.path.join(DISKANN_DATA_ROOT, "graphs")    
    os.makedirs(GRAPH_ROOT, exist_ok=True)
    
    RESULTS_ROOT = os.path.join(os.getcwd(), "results")
    os.makedirs(RESULTS_ROOT, exist_ok=True)
    
    # datsets and indexes
    for dataset in SUPPORTED_DATASETS:
        dataset_dir = os.path.join(DATASET_ROOT, dataset)
        os.makedirs(dataset_dir, exist_ok=True)
        print(f"Initialized empty directory: {dataset_dir}")
        
        index_dir = os.path.join(INDEX_ROOT, dataset)
        os.makedirs(index_dir, exist_ok=True)
        print(f"Initialized empty directory: {index_dir}")
        
        graph_dir = os.path.join(GRAPH_ROOT, dataset)
        os.makedirs(graph_dir, exist_ok=True)
        print(f"Initialized empty directory: {graph_dir}")


    # oram
    for dataset in SUPPORTED_DATASETS:
        oram_dir = os.path.join(DISKANN_ORAM_ROOT, dataset)
        os.makedirs(oram_dir, exist_ok=True)
        print(f"Initialized empty directory: {oram_dir}")
        
        
def initialize_empty_compass_directories():
    os.makedirs(COMPASS_DATA_ROOT, exist_ok=True)
    os.makedirs(COMPASS_ORAM_ROOT, exist_ok=True)
        

def make_executables():
    # make server
    server_make_command = "make -j server"
    subprocess.run(server_make_command, shell=True)
    
    # make oram_initializer
    oram_make_command = "make -j oram_initializer"
    subprocess.run(oram_make_command, shell=True)


def process_downloaded_data(dataset):
    dataset_dir = DISKANN_DATA_ROOT + "/datasets/" + dataset
    
    if dataset == "marco":
        # check passages.fvecs
        raw_data_path = dataset_dir + "/passages.fvecs"
        bin_data_path = dataset_dir + "/base.bin"

        if not os.path.exists(raw_data_path):
            print(f"Raw data file: passages.fvecs does not exist. Please download it first...")
            exit(0)

        

def server_menu():
    print("Setup Server")
    print("1. Download Compass Data")
    print("2. Download DiskANN Data")
    print("3. Build ORAM")
    print("4. Initialize Empty DiskANN Directories")
    print("5. Initialize Empty Compass Directories")
    print("6. Make executables")
    print("0. Exit")

    choice = "-1"

    while choice not in ["1", "2", "3", "4", "5"]:
        choice = input("Enter your choice: ")

        if choice == "1":
            dataset = input(f"Enter dataset name ({', '.join(SUPPORTED_DATASETS)}): ")
            download_data(bucket_name, dataset, download_compass=True)
        elif choice == "2":
            dataset = input(f"Enter dataset name ({', '.join(SUPPORTED_DATASETS)}): ")
            download_data(bucket_name, dataset, download_compass=False)
        elif choice == "3":
            dataset = input(f"Enter dataset name ({', '.join(SUPPORTED_DATASETS)}): ")
            r = int(input("Enter R value: "))
            efc = int(input("Enter EFC value: "))
            pq_bytes = int(input("Enter PQ bytes: "))
            build_oram(dataset, r, efc, pq_bytes)
        elif choice == "4":
            initialize_empty_diskann_directories()
        elif choice == "5":
            initialize_empty_compass_directories()
        elif choice == "6":
            make_executables()
        elif choice == "0":
            exit(0)
        else:
            print("Invalid choice. Please try again.")
            
            
if __name__ == "__main__":
    server_menu()
