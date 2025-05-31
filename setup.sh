#!/bin/bash

sudo apt update

sudo apt install -y python3-pip
pip3 install google-cloud-storage google-cloud-compute paramiko gdown
pip3 install tcconfig 


mkdir -p data/dataset
mkdir -p data/index
mkdir -p data/graphs
mkdir results

# build diskann
mkdir src/diskann/build
cd src/diskann/build
cmake -DCMAKE_BUILD_TYPE=Release .. && make -Bj

# come back to root
cd ../../..

# Setup SIFT: Base, Query, Index, Ground Truth
mkdir -p data/dataset/sift
src/diskann/build/apps/utils/fvecs_to_bin float ../compass/data/dataset/sift/base.fvecs data/dataset/sift/base.fbin
src/diskann/build/apps/utils/fvecs_to_bin float ../compass/data/dataset/sift/query.fvecs data/dataset/sift/query.fbin
src/diskann/build/apps/utils/compute_groundtruth --data_type float --dist_fn l2 --base_file data/dataset/sift/base.fbin --query_file  data/dataset/sift/query.fbin --gt_file data/dataset/sift/sift_query_base_gt_100 --K 100
./apps/build_disk_index --data_type float --dist_fn l2 --data_path data/dataset/sift/base.fbin --index_path_prefix data/index/sift/disk_index_sift_base_R128_L50_A1.2 -R 128 -L 50 -B 0.05 -M 10000

# Setup TRIP: Base, Query, Index, Ground Truth

mkdir -p data/dataset/trip
./apps/utils/fvecs_to_bin float data/dataset/trip_distilbert/passages.fvecs data/dataset/trip/passages.fbin
./apps/utils/fvecs_to_bin float data/dataset/trip_distilbert/queries.fvecs data/dataset/trip/queries.fbin
./apps/utils/compute_groundtruth --data_type float --dist_fn l2 --base_file data/dataset/trip/passages.fbin --query_file  data/dataset/trip/queries.fbin --gt_file data/dataset/trip/trip_query_base_gt_100 --K 100
./apps/build_disk_index --data_type float --dist_fn l2 --data_path data/dataset/trip/passages.fbin --index_path_prefix data/index/trip/disk_index_trip_base_R128_L50_A1.2 -R 128 -L 50 -B 0.05 -M 10000