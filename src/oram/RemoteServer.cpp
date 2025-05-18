#include "RemoteServer.h"
#include "utils_uring.cpp"
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

#define NUM_THREADS 8
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
int get_sibling2(int me){
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

RemoteServer::RemoteServer(NetIO* io, int capacity, bool in_memory, bool integrity)
    : io(io), capacity(capacity), in_memory(in_memory), integrity(integrity) {
    buckets_fname = NULL;
    mmap_data = NULL;
    mmap_size = 0;
    mmap_bkts = NULL;
    fd = -1;

    if(in_memory){
        for(int i = 0; i < capacity; i++){
			SBucket* sbkt = new SBucket(integrity);
			buckets.push_back(sbkt);
		}
    }

	if(integrity){
		root.resize(SHA256_DIGEST_LENGTH);
	}

    cout << "> Remote storage server config: " << endl;
    cout << " -> in memory: " << in_memory << endl;
    cout << " -> integrity: " << integrity << endl;
    // cout << endl;
}

void RemoteServer::RunServer(){
    if(in_memory){
        RunServerInMemory();
    } else{
        RunServerInDiskRing();
    }
}

void RemoteServer::sync_root(){
	io->send_data(root.data(), SHA256_DIGEST_LENGTH*sizeof(uint8_t));
}


void RemoteServer::RunServerInMemory(){
	// cout << "Remote storage server running ..." << endl;
    
	while(1) {
		int rt;
		io->recv_data(&rt, sizeof(int));
		switch (rt){
			case Read:{
                // Legacy branch, disabled
				assert(0);
				int bucket_id;
				io->recv_data(&bucket_id, sizeof(int));
				// this->buckets[bucket_id]->to_io(io);
				break;
			}
			case Write:{
                // Legacy branch, disabled
				assert(0);
				int bucket_id;
				io->recv_data(&bucket_id, sizeof(int));
				// this->buckets[bucket_id]->from_io(io);
				break;
			}
			case ReadBatch:{

				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));

				// auto t_fetch = std::chrono::high_resolution_clock::now();
				
				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				// {
				// 	// for demo
				// 	std::cout << "[READ][" << num_buckets << "]: ";

				// 	if (num_buckets <= 6) {
				// 		// If the vector has 6 or fewer elements, print them all
				// 		for (const int& element : position) {
				// 			std::cout << element << " ";
				// 		}
				// 	} else {
				// 		std::cout << "[";
				// 		// Print the first 3 elements
				// 		for (int i = 0; i < 3; ++i) {
				// 			std::cout << position[i] << ", ";
				// 		}

				// 		// Print "..." in the middle
				// 		std::cout << "... ";

				// 		// Print the last 3 elements
				// 		for (int i = num_buckets - 3; i < num_buckets; ++i) {
				// 			std::cout << ", " << position[i];
				// 		}
				// 	}

				// 	std::cout << "]" << endl;
				// }

				size_t len = num_buckets * (SBucket::getCipherSize());
				// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
				unsigned char* payload = new unsigned char[len];
				// cout << "ReadBucketBatch allocate done" << endl;

				#pragma omp parallel for num_threads(NUM_THREADS)
				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					size_t bucket_pos = position[bucket_id]; 
					size_t bucket_offset = bucket_id * SBucket::getCipherSize();
					this->buckets[bucket_pos]->data_to_ptr(payload + bucket_offset);
				} 

				// cout << "ReadBucketBatch write to payload done" << endl;

				{
					// xor bench
					unsigned char* xor_payload = new unsigned char[SBucket::getCipherSize()];
					#pragma omp parallel for num_threads(NUM_THREADS)
					for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
						for(size_t j = 0; j < SBucket::getCipherSize(); j++){
							size_t bucket_offset = bucket_id * SBucket::getCipherSize();
							unsigned char* bkt = payload + bucket_offset;
							xor_payload[j] = xor_payload[j] ^ bkt[j];
						}
					} 

					delete[] xor_payload;
				}

				io->send_data(payload, sizeof(unsigned char)*len);

				// cout << "ReadBucketBatch send to client done" << endl;

				if(integrity){
					int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
					unsigned char* hash_payload = new unsigned char[hash_len];

					#pragma omp parallel for num_threads(NUM_THREADS)
					for(int bucket_id = 0; bucket_id < num_buckets; bucket_id++){
						int bucket_pos = position[bucket_id]; 
						int bucket_offset = bucket_id * SHA256_DIGEST_LENGTH;
						this->buckets[get_sibling2(bucket_pos)]->hash_to_ptr(hash_payload + bucket_offset);
					} 

					io->send_data(hash_payload, sizeof(unsigned char)*hash_len);
					delete[] hash_payload;
				}

				delete[] payload;
				break;
			}
			case WriteBatch:{

				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));

				// auto t_fetch = std::chrono::high_resolution_clock::now();

				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				// {
				// 	// for demo
				// 	std::cout << "[WRITE][" << num_buckets << "]: ";

				// 	if (num_buckets <= 6) {
				// 		// If the vector has 6 or fewer elements, print them all
				// 		for (const int& element : position) {
				// 			std::cout << element << " ";
				// 		}
				// 	} else {
				// 		std::cout << "[";

				// 		// Print the first 3 elements
				// 		for (int i = 0; i < 3; ++i) {
				// 			std::cout << position[i] << ", ";
				// 		}

				// 		// Print "..." in the middle
				// 		std::cout << "... ";

				// 		// Print the last 3 elements
				// 		for (int i = num_buckets - 3; i < num_buckets; ++i) {
				// 			std::cout << ", " << position[i];
				// 		}
				// 	}

				// 	std::cout << "]" << endl;
				// 	std::cout << endl;
				// }

				size_t len = num_buckets * (SBucket::getCipherSize());
				// cout << "WriteBatch allocate payload for size: " << len << endl;

				unsigned char* payload = new unsigned char[len];
				// cout << "WriteBatch allocate done" << endl;

				io->recv_data(payload, sizeof(unsigned char)*len);

				// auto t_write = interval(t_fetch);

				// cout << "WriteBatch allocate done" << endl;

				#pragma omp parallel for num_threads(NUM_THREADS)
				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					size_t bucket_pos = position[bucket_id]; 
					size_t bucket_offset = bucket_id * SBucket::getCipherSize();
					this->buckets[bucket_pos]->data_from_ptr(payload + bucket_offset);
				}

				if(integrity){
					int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
					unsigned char* hash_payload = new unsigned char[hash_len];
					io->recv_data(hash_payload, sizeof(unsigned char)*hash_len);
					
					#pragma omp parallel for num_threads(NUM_THREADS)
					for(int bucket_id = num_buckets -1; bucket_id >= 0; bucket_id--){
						int bucket_pos = position[bucket_id]; 
						int bucket_offset = bucket_id * SHA256_DIGEST_LENGTH;
						this->buckets[bucket_pos]->hash_from_ptr(hash_payload + bucket_offset);
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

void RemoteServer::fileMap(){
    // Load file into memory
    fd = open(buckets_fname, O_RDWR);
    if (fd == -1) {
        perror("Error opening file");
        assert(0);
    }

    // Get the size of the file
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("Error getting file size");
        close(fd);
        assert(0);
    }
    mmap_size = st.st_size;

    // Memory-map the file with read-write permissions
    mmap_data = static_cast<unsigned char*>(mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
    if (mmap_data == MAP_FAILED) {
        perror("Error mapping file");
        close(fd);
        assert(0);
    }

	if (madvise(mmap_data, mmap_size, POSIX_MADV_SEQUENTIAL) == -1) {
        perror("Error advising kernel");
        munmap(mmap_data, mmap_size);
        close(fd);
        assert(0);
    }

    mmap_bkts = mmap_data + sizeof(int) + sizeof(int) + sizeof(bool);
}

void RemoteServer::fileUnMap(){
    if (munmap(mmap_data, mmap_size) == -1) {
        perror("Error unmapping file");
    }

	auto t_0 = std::chrono::high_resolution_clock::now();
	// Advise the kernel to drop the cache
    if (posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) != 0) {
        perror("Error advising kernel");
        close(fd);
        assert(0);
    }
	auto t_drop = interval(t_0);

	cout << "Clear Page Time: " << t_drop << endl;

    close(fd);

    // Reset states
    mmap_data = NULL;
    mmap_size = 0;
    mmap_bkts = NULL;
    fd = -1;
}

void RemoteServer::RunServerInDisk(){
	cout << "Remote storage servers running ..." << endl;

	while(1) {
		int rt;
		io->recv_data(&rt, sizeof(int));
		switch (rt){
			case Read:{
				assert(0);
			}
			case Write:{
				assert(0);
			}
			case ReadBatch:{
                if(fd == -1){
                    fileMap();
                }
				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));
				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				size_t len = num_buckets * (SBucket::getCipherSize());
				// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
				unsigned char* payload = new unsigned char[len];
				// cout << "ReadBucketBatch allocate done" << endl;

				#pragma omp parallel for num_threads(NUM_THREADS)
				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					size_t bucket_pos = position[bucket_id]; 
					size_t bucket_offset = bucket_id * SBucket::getCipherSize();
					unsigned char* sbkt = mmap_bkts + bucket_pos * SBucket::getCipherSize();
					memcpy(payload + bucket_offset, sbkt, SBucket::getCipherSize());
					// this->buckets[bucket_pos]->data_to_ptr(payload + bucket_offset);
				} 

				// cout << "ReadBucketBatch write to payload done" << endl;

				io->send_data(payload, sizeof(unsigned char)*len);

				// cout << "ReadBucketBatch send to client done" << endl;

				if(integrity){
					assert(0);
					int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
					unsigned char* hash_payload = new unsigned char[hash_len];

					for(int bucket_id = 0; bucket_id < num_buckets; bucket_id++){
						int bucket_pos = position[bucket_id]; 
						int bucket_offset = bucket_id * SHA256_DIGEST_LENGTH;
						this->buckets[get_sibling2(bucket_pos)]->hash_to_ptr(hash_payload + bucket_offset);
					} 

					io->send_data(hash_payload, sizeof(unsigned char)*hash_len);
					delete[] hash_payload;
				}

				delete[] payload;
				break;
			}
			case WriteBatch:{

				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));
				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				size_t len = num_buckets * (SBucket::getCipherSize());
				// cout << "WriteBatch allocate payload for size: " << len << endl;
				unsigned char* payload = new unsigned char[len];
				// cout << "WriteBatch allocate done" << endl;

				io->recv_data(payload, sizeof(unsigned char)*len);

				// cout << "WriteBatch allocate done" << endl;

				#pragma omp parallel for num_threads(NUM_THREADS)
				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					size_t bucket_pos = position[bucket_id]; 
					size_t bucket_offset = bucket_id * SBucket::getCipherSize();
					unsigned char* sbkt = mmap_bkts + bucket_pos * SBucket::getCipherSize();
					memcpy(sbkt, payload + bucket_offset, SBucket::getCipherSize());
					// this->buckets[bucket_pos]->data_from_ptr(payload + bucket_offset);
				}

				if(integrity){
					assert(0);
					int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
					unsigned char* hash_payload = new unsigned char[hash_len];
					io->recv_data(hash_payload, sizeof(unsigned char)*hash_len);
					for(int bucket_id = num_buckets -1; bucket_id >= 0; bucket_id--){
						int bucket_pos = position[bucket_id]; 
						int bucket_offset = bucket_id * SHA256_DIGEST_LENGTH;
						this->buckets[bucket_pos]->hash_from_ptr(hash_payload + bucket_offset);
					}
					delete[] hash_payload;
				}

                // Assume reset after write
                fileUnMap();

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

void RemoteServer::RunServerInDiskRing(){
	cout << "Remote storage servers running ..." << endl;

	// Load file into memory
    fd = open(buckets_fname, O_RDWR);
    if (fd == -1) {
        perror("Error opening file");
        assert(0);
    }

	// Advise the kernel to drop the cache
	if (posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) != 0) {
		perror("Error advising kernel");
		close(fd);
		assert(0);
	}


	while(1) {
		int rt;
		io->recv_data(&rt, sizeof(int));
		switch (rt){
			case Read:{
				assert(0);
			}
			case Write:{
				assert(0);
			}
			case ReadBatch:{

				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));
				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				size_t len = num_buckets * (SBucket::getCipherSize());
				// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
				unsigned char* payload = new unsigned char[len];
				// cout << "ReadBucketBatch allocate done" << endl;

				buckets_io_wrapper_mt(position, SBucket::getCipherSize(), fd, payload, true);
				// cout << "ReadBucketBatch write to payload done" << endl;

				io->send_data(payload, sizeof(unsigned char)*len);

				// cout << "ReadBucketBatch send to client done" << endl;

				if(integrity){
					assert(0);
					int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
					unsigned char* hash_payload = new unsigned char[hash_len];

					for(int bucket_id = 0; bucket_id < num_buckets; bucket_id++){
						int bucket_pos = position[bucket_id]; 
						int bucket_offset = bucket_id * SHA256_DIGEST_LENGTH;
						this->buckets[get_sibling2(bucket_pos)]->hash_to_ptr(hash_payload + bucket_offset);
					} 

					io->send_data(hash_payload, sizeof(unsigned char)*hash_len);
					delete[] hash_payload;
				}

				delete[] payload;
				break;
			}
			case WriteBatch:{

				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));
				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				size_t len = num_buckets * (SBucket::getCipherSize());
				cout << "WriteBatch allocate payload for size: " << len << endl;
				unsigned char* payload = new unsigned char[len];
				// cout << "WriteBatch allocate done" << endl;

				io->recv_data(payload, sizeof(unsigned char)*len);

				// cout << "WriteBatch allocate done" << endl;

				buckets_io_wrapper_mt(position, SBucket::getCipherSize(), fd, payload, false);

				if(integrity){
					assert(0);
					int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
					unsigned char* hash_payload = new unsigned char[hash_len];
					io->recv_data(hash_payload, sizeof(unsigned char)*hash_len);
					for(int bucket_id = num_buckets -1; bucket_id >= 0; bucket_id--){
						int bucket_pos = position[bucket_id]; 
						int bucket_offset = bucket_id * SHA256_DIGEST_LENGTH;
						this->buckets[bucket_pos]->hash_from_ptr(hash_payload + bucket_offset);
					}
					delete[] hash_payload;
				}

                // Advise the kernel to drop the cache
				if (posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) != 0) {
					perror("Error advising kernel");
					close(fd);
					assert(0);
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

void RemoteServer::load(const char* fname){
	int fd = open(fname, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "could not open %s\n", fname);
        perror("");
        abort();
    }

    // File check
    
	// Write capacity
	int c;
	read(fd, &c, sizeof(int));
	if(c != capacity){
		assert(0);
	}
	// Write SBucket size
	int sb_size;
	read(fd, &sb_size,sizeof(int));
	if(sb_size != SBucket::getCipherSize()){
		assert(0);
	}

	bool i;
	read(fd, &i, sizeof(bool));
	if(i != integrity){
		assert(0);
	}

    if(in_memory){
        for (size_t i = 0; i < capacity; i++){
            read(fd, this->buckets[i]->data, SBucket::getCipherSize());
            if(integrity){
				read(fd, this->buckets[i]->hash, 32*sizeof(uint8_t));
			}
        }

		if(integrity){
			for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
				root[i] = this->buckets[0]->hash[i];
			}
		}

    } else {
        buckets_fname = (char *)malloc(strlen(fname) + 1);
	    strcpy(buckets_fname, fname);
    }
    close(fd);
}
