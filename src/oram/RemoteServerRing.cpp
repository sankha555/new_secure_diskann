#include "RemoteServerRing.h"
#include <iostream>
#include <string>
#include <sstream>
#include <cassert>
#include <omp.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <chrono>
#include <omp.h>
#include <cstring> 
#include <iomanip> // For std::hex, std::setw, std::setfill

#define NUM_THREADS 1
#define SHA256_DIGEST_LENGTH 32

enum RequestType {
    Read,
    Write,
    ReadBatch,
	WriteBatch,
	ReadBatchBlock,
	ReadBatchBlockXor,
	WriteBatchBlock,
	Init,
	End // End the remote server
};

size_t get_sibling3(size_t me){
	if(me % 2 == 1){
		// odd
		return me + 1;
	} else if (me == 0){
		return 0;
	} else{
		return me - 1;
	}
}

inline double interval(std::chrono::_V2::system_clock::time_point start){
    auto end = std::chrono::high_resolution_clock::now();
    auto interval = (end - start)/1e+9;
    return interval.count();
}

RemoteServerRing::RemoteServerRing(NetIO* io, size_t capacity, size_t bucket_size, bool in_memory, bool integrity)
    : io(io), capacity(capacity), bucket_size(bucket_size), in_memory(in_memory), integrity(integrity) {

	assert(in_memory);
	// assert(!integrity);

	block_size = SBucket::getCipherSize();
	data = new unsigned char [capacity * bucket_size * block_size];

	// for(int i = 0; i < capacity*bucket_size; i++){
	// 	SBucket* sbkt = new SBucket(integrity);
	// 	buckets.push_back(sbkt);
	// }

    cout << "> Remote storage server config: " << endl;
    cout << " -> in memory: " << in_memory << endl;
    cout << " -> integrity: " << integrity << endl;
	cout << " -> # buckets: " << capacity << endl;
	cout << " -> # Z: " << bucket_size << endl;
	cout << " -> block size: " << block_size << endl;
	cout << " -> total: " << capacity * bucket_size * block_size << endl;
    // cout << endl;
}

void RemoteServerRing::RunServer(){
    RunServerInMemory();
}

// void RemoteServerRing::sync_root(){
// 	io->send_data(root.data(), SHA256_DIGEST_LENGTH*sizeof(uint8_t));
// }

void RemoteServerRing::send_hash(std::vector<int> &position, std::vector<int> &offset){

	// cout << "send_hash..." << endl;
	
	size_t num_hashes = position.size() * (per_bucket_tree_height - 1);
	uint8_t* payload = new uint8_t[num_hashes*SHA256_DIGEST_LENGTH];

	#pragma omp parallel for num_threads(NUM_THREADS)
	for(size_t i = 0; i < position.size(); i++){
		size_t pos = position[i];
		size_t cur_offset = offset[i] + (per_bucket_hashes + 1) / 2 - 1;
		for(int cur_height = per_bucket_tree_height; cur_height > 1; cur_height --){
			size_t sib_offset = get_sibling3(cur_offset);
			uint8_t* src = per_bucket_hash + pos * per_bucket_hashes * SHA256_DIGEST_LENGTH + sib_offset * SHA256_DIGEST_LENGTH;
			uint8_t* dst = payload + i * (per_bucket_tree_height - 1) * SHA256_DIGEST_LENGTH + (per_bucket_tree_height - cur_height) * SHA256_DIGEST_LENGTH;
			memcpy(dst, src, SHA256_DIGEST_LENGTH);

			// if(i == 0){
			// 	cout << "sib_hash for height - " << cur_height << " cur_offset: " << cur_offset << ": " ;
			// 	for(int j = 0; j < SHA256_DIGEST_LENGTH; j++){
			// 		cout << (int)(dst[j]) << " ";
			// 	}
			// 	cout << endl;
			// }

			cur_offset = (cur_offset - 1) / 2;
		}
	}

	io->send_data(payload, num_hashes*SHA256_DIGEST_LENGTH);
	// cout << "send_hash: done!" << endl;

	delete[] payload;
}


void RemoteServerRing::RunServerInMemory(){
	// cout << "Remote storage server running ..." << endl;
    
	while(1) {
		int rt;
		io->recv_data(&rt, sizeof(int));
		switch (rt){
			case -1: {
				long comm = io->counter - bookmark_comm;
				long rounds = io->num_rounds - bookmark_rounds;

				// cout << "Received req to send comm: " << comm << " bytes" << endl;
				io->send_data(&comm, sizeof(long));
				io->send_data(&rounds, sizeof(long));

				io->counter -= 2*sizeof(long);
				io->num_rounds--;
				break;
			}
			
			case Read:{
                // Legacy branch, disabled
				assert(0);
				break;
			}
			case Write:{
                // Legacy branch, disabled
				assert(0);
				break;
			}
			case ReadBatchBlock:{
				size_t num_blocks;
				io->recv_data(&num_blocks, sizeof(size_t));

				// auto t_fetch = std::chrono::high_resolution_clock::now();
				
				std::vector<int> position(num_blocks);
				std::vector<int> offset(num_blocks);
				io->recv_data(position.data(), sizeof(int)*num_blocks);
				io->recv_data(offset.data(), sizeof(int)*num_blocks);

				size_t len = num_blocks * (block_size);
				// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
				unsigned char* payload = new unsigned char[len];
				// cout << "ReadBucketBatch allocate done" << endl;

				#pragma omp parallel for num_threads(NUM_THREADS)
				for(size_t bucket_id = 0; bucket_id < num_blocks; bucket_id++){
					size_t bucket_pos = position[bucket_id]*bucket_size + offset[bucket_id]; 
					size_t bucket_offset = bucket_id * block_size;
					// this->buckets[bucket_pos]->data_to_ptr(payload + bucket_offset);
					unsigned char* tmp_data = data + bucket_pos*block_size;
					mempcpy(payload + bucket_offset, tmp_data, block_size);
				} 

				// cout << "ReadBucketBatch write to payload done" << endl;

				long comm = io->counter;
				io->send_data(payload, sizeof(unsigned char)*len);
				// cout << (io->counter - comm) << " B (reshuffle), ";


				if(integrity){
					send_hash(position, offset);
				}

				// cout << "ReadBucketBatch send to client done" << endl;

				delete[] payload;

				break;
			}
			case ReadBatchBlockXor:{
				// cout << "ReadBatchBlockXor" << endl;
				size_t num_blocks;
				size_t num_real_blocks;
				io->recv_data(&num_blocks, sizeof(size_t));
				io->recv_data(&num_real_blocks, sizeof(size_t));
				
				std::vector<int> position(num_blocks);
				std::vector<int> offset(num_blocks);
				io->recv_data(position.data(), sizeof(int)*num_blocks);
				io->recv_data(offset.data(), sizeof(int)*num_blocks);

				size_t path_len = num_blocks / num_real_blocks;

				// no need for ivs
				size_t len = num_real_blocks * (block_size - 16);

				unsigned char* payload = new unsigned char[len];
				unsigned char* ivs = new unsigned char[num_blocks*16];
				std::memset(payload, 0, len); 

				#pragma omp parallel for num_threads(NUM_THREADS)
				for(size_t block_id = 0; block_id < num_real_blocks; block_id++){
					size_t bucket_offset = block_id * (block_size - 16);
					for(int i = 0; i < path_len; i++){
						size_t bucket_id = block_id * path_len + i;
						size_t bucket_pos = position[bucket_id]*bucket_size + offset[bucket_id]; 
						// this->buckets[bucket_pos]->data_xor_to_ptr(payload + bucket_offset);

						unsigned char* ptr = payload + bucket_offset;
						unsigned char* tmp_data = data + bucket_pos*block_size;
						
						// first 16 goes to iv
						memcpy(ivs + bucket_id*16, tmp_data, 16);

						// 16 - block_size goes to xor
						for(size_t j = 16; j < block_size; j++){
							ptr[j - 16] = tmp_data[j] ^ ptr[j - 16]; 
						}
					}
					
				}

				long comm = io->counter;
				io->send_data(payload, sizeof(unsigned char)*len);
				io->send_data(ivs, sizeof(unsigned char)*num_blocks*16);
				// cout << (io->counter - comm) << " B" << endl;

				if(integrity){
					send_hash(position, offset);
				}

				// cout << "ReadBatchBlockXor send to client done" << endl;

				delete[] payload;

				break;
			}
			case WriteBatchBlock:{
				assert(0);
				break;
			}
			case ReadBatch:{

				assert(0);

				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));

				// auto t_fetch = std::chrono::high_resolution_clock::now();
				
				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				size_t len = num_buckets * bucket_size * (block_size);
				// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
				unsigned char* payload = new unsigned char[len];
				// cout << "ReadBucketBatch allocate done" << endl;

				#pragma omp parallel for num_threads(NUM_THREADS)
				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					for(size_t block_id = 0; block_id < bucket_size; block_id++){
						size_t block_pos = position[bucket_id]*bucket_size + block_id;
						size_t block_offset = (bucket_id*bucket_size + block_id) * block_size;
						// this->buckets[block_pos]->data_to_ptr(payload + block_offset);
						unsigned char* tmp_data = data + block_pos*block_size;
						mempcpy(payload + block_offset, tmp_data, block_size);
					}
				} 

				io->send_data(payload, sizeof(unsigned char)*len);

				delete[] payload;
				break;
			}
			case WriteBatch:{

				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));

				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				size_t len = num_buckets * bucket_size * (block_size);

				unsigned char* payload = new unsigned char[len];
				// cout << "WriteBatch allocate done" << endl;

				io->recv_data(payload, sizeof(unsigned char)*len);


				#pragma omp parallel for num_threads(NUM_THREADS)
				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					for(size_t block_id = 0; block_id < bucket_size; block_id++){
						size_t block_pos = position[bucket_id]*bucket_size + block_id;
						size_t block_offset = (bucket_id*bucket_size + block_id) * block_size;
						// this->buckets[block_pos]->data_from_ptr(payload + block_offset);
						unsigned char* tmp_data = data + block_pos*block_size;
						mempcpy(tmp_data, payload + block_offset, block_size);
					}
				} 

				if(integrity){
					size_t hash_payload_size = position.size() * per_bucket_hashes * SHA256_DIGEST_LENGTH;
					uint8_t* hash_payload = new uint8_t[hash_payload_size];
					io->recv_data(hash_payload, hash_payload_size);
					#pragma omp parallel for num_threads(NUM_THREADS)
					for(size_t i = 0 ; i < position.size(); i++){
						memcpy(
							per_bucket_hash + position[i] * per_bucket_hashes * SHA256_DIGEST_LENGTH,
							hash_payload + i * per_bucket_hashes * SHA256_DIGEST_LENGTH,
							per_bucket_hashes * SHA256_DIGEST_LENGTH
						);
					}
					delete[] hash_payload;
				}
				
				delete[] payload;
				break;
			}
			case Init:{
				cout << "Remote storage server Initializing ..." ;
				assert(0);
				cout << " done!" << endl;
				break;
			}
			case End:{
				cout << "Remote storage server closing ..." << endl;
				return;
			}
			default:{
				assert(0);
			}
			
		}
	}
}

void RemoteServerRing::load_hash(const char* fname){
	per_bucket_tree_height = ceil(log10(bucket_size) / log10(2)) + 1;
	per_bucket_hashes = pow(2, per_bucket_tree_height) - 1;
	size_t per_bucket_hash_size = SHA256_DIGEST_LENGTH * per_bucket_hashes * capacity;

	per_bucket_hash = new uint8_t[per_bucket_hash_size];

	int fd = open(fname, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "could not open %s\n", fname);
        perror("");
        abort();
    }

	ssize_t target_size = per_bucket_hash_size;
	ssize_t total_read = 0;
	ssize_t bytes_read;
	while (total_read < target_size) {
		bytes_read = read(fd, per_bucket_hash + total_read, target_size - total_read);
		if (bytes_read < 0) {
			// Handle error
			cout << "error"  << endl;
			perror("read failed");
			break;
		}
		if (bytes_read == 0) {
			// EOF reached
			cout << "eof"  << endl;
			break;
		}
		total_read += bytes_read;
	}

	cout << "total_read: " << total_read << endl;

	assert(total_read == target_size);

	return;
}

void RemoteServerRing::sync_hash(){
	// Send the root hash of every bucket back to the client

	cout << "sync hash start ..." << endl;

	uint8_t* payload = new uint8_t[capacity*SHA256_DIGEST_LENGTH];
	for(size_t bucket_id = 0; bucket_id < capacity; bucket_id++){
		memcpy(
			payload + bucket_id*SHA256_DIGEST_LENGTH,
			per_bucket_hash + bucket_id*per_bucket_hashes*SHA256_DIGEST_LENGTH,
			SHA256_DIGEST_LENGTH
		);
	}

	io->send_data(payload, capacity*SHA256_DIGEST_LENGTH);

	cout << "sync hash start done" << endl;

	delete[] payload;
}

void RemoteServerRing::load(const char* fname){
	int fd = open(fname, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "could not open %s\n", fname);
        perror("");
        abort();
    }

    // File check
    
	// Read capacity
	int c;
	read(fd, &c, sizeof(int));
	if(c != capacity){
		assert(0);
	}
	// Read SBucket size
	int sb_size;
	read(fd, &sb_size,sizeof(int));
	if(sb_size != block_size){
		assert(0);
	}

	bool i;
	read(fd, &i, sizeof(bool));
	// if(i != integrity){
	// 	assert(0);
	// }

	// size_t mmap_size = capacity * bucket_size * block_size + sizeof(int)*2 + sizeof(bool);

	// // mmap optimization
	// // Memory-map the file with read-write permissions
    // unsigned char* mmap_data = static_cast<unsigned char*>(mmap(nullptr, mmap_size, PROT_READ, MAP_PRIVATE, fd, 0));
    // if (mmap_data == MAP_FAILED) {
    //     perror("Error mapping file");
    //     close(fd);
    //     assert(0);
    // }

	// if (madvise(mmap_data, mmap_size, POSIX_MADV_SEQUENTIAL) == -1) {
    //     perror("Error advising kernel");
    //     munmap(mmap_data, mmap_size);
    //     close(fd);
    //     assert(0);
    // }
	
	// unsigned char* mmap_payload = mmap_data + sizeof(int)*2 + sizeof(bool);

	// #pragma omp parallel num_threads(NUM_THREADS)
	// for(size_t i = 0; i < capacity; i++){
	// 	memcpy(data + i * bucket_size * block_size, mmap_payload + i * bucket_size * block_size, bucket_size * block_size);
	// }

	// munmap(mmap_data, mmap_size);


    if(in_memory){
		// read(fd, data, capacity * bucket_size * block_size);

		ssize_t target_size = capacity * bucket_size * block_size;
		ssize_t total_read = 0;
		ssize_t bytes_read;
		while (total_read < target_size) {
			bytes_read = read(fd, data + total_read, target_size - total_read);
			if (bytes_read < 0) {
				// Handle error
				cout << "error"  << endl;
				perror("read failed");
				break;
			}
			if (bytes_read == 0) {
				// EOF reached
				cout << "eof"  << endl;
				break;
			}
			total_read += bytes_read;
		}

		// cout << "total_read: " << total_read << endl;

		assert(total_read == target_size);

        // for (size_t i = 0; i < capacity*bucket_size; i++){
        //     read(fd, this->buckets[i]->data, SBucket::getCipherSize());
        //     // if(integrity){
		// 	// 	read(fd, this->buckets[i]->hash, 32*sizeof(uint8_t));
		// 	// }
        // }

		// if(integrity){
		// 	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
		// 		root[i] = this->buckets[0]->hash[i];
		// 	}
		// }

    } else {
		assert(0);
        // buckets_fname = (char *)malloc(strlen(fname) + 1);
	    // strcpy(buckets_fname, fname);
    }
    close(fd);
}
