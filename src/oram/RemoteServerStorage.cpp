
#include "RemoteServerStorage.h"
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
#include <iomanip> // For std::hex, std::setw, std::setfill

#include "evp.h"

#define NUM_THREADS 1

using namespace std;

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

int get_sibling(int me){
	if(me % 2 == 1){
		// odd
		return me + 1;
	} else if (me == 0){
		return 0;
	} else{
		return me - 1;
	}
}

// int get_sibling3(size_t me){
// 	if(me % 2 == 1){
// 		// odd
// 		return me + 1;
// 	} else if (me == 0){
// 		return 0;
// 	} else{
// 		return me - 1;
// 	}
// }

RemoteServerStorage::RemoteServerStorage(int block_size, NetIO* io, bool isServer, int num_levels, bool integrity) {
	
	this->is_initialized = true;
	this->is_capacity_set = false;
	this->io = io;
	this->isServer = isServer;
	this->block_size = block_size;
	this->num_levels = num_levels;
	this->integrity = integrity;
	this->root.resize(SHA256_DIGEST_LENGTH);
}

void RemoteServerStorage::sync_hash(RingOramConfig config){

	// cout << "sync hash start ..." << endl;

	per_bucket_tree_height = ceil(log10(config.bucket_size) / log10(2)) + 1;
	per_bucket_hashes = pow(2, per_bucket_tree_height) - 1;
	size_t buckets_hash_size = SHA256_DIGEST_LENGTH * config.num_buckets;
	per_bucket_hash = new uint8_t[buckets_hash_size];
	io->recv_data(per_bucket_hash, buckets_hash_size);

	// cout << "sync hash start done" << endl;
}

void RemoteServerStorage::recv_and_verify_hash(const std::vector<int> &position, const std::vector<int> &offset, unsigned char* payload, std::vector<bool> &valid){

	// cout << "recv_and_verify_hash..." << endl;

	size_t num_hashes = position.size() * (per_bucket_tree_height - 1);
	uint8_t* hash_payload = new uint8_t[num_hashes*SHA256_DIGEST_LENGTH];

	io->recv_data(hash_payload, num_hashes*SHA256_DIGEST_LENGTH);
	size_t valid_cnt = 0;

	for(size_t i = 0; i < position.size(); i++){
		if(valid[i]){
			// this block is a real block
			size_t pos = position[i];
			size_t cur_offset = offset[i] + (per_bucket_hashes + 1) / 2 - 1;
			unsigned char* ctx = payload + valid_cnt*SBucket::getCipherSize();
			uint8_t* hash = new uint8_t[SHA256_DIGEST_LENGTH];
			sha256_wrapper(ctx, SBucket::getCipherSize(), hash);


			// cout << "verifying fail pos: " << pos << " offset: " << offset[i] << endl;

			for(int cur_height = per_bucket_tree_height; cur_height > 1; cur_height --){
				uint8_t* sib_hash = hash_payload + i * (per_bucket_tree_height - 1) * SHA256_DIGEST_LENGTH + (per_bucket_tree_height - cur_height) * SHA256_DIGEST_LENGTH;

				// determine left and right
				uint8_t* l_hash = hash;
				uint8_t* r_hash = sib_hash;

				if(cur_offset % 2 == 0){
					l_hash = sib_hash;
					r_hash = hash;
				} 

				sha256_twin_input_wrapper(
					l_hash, SHA256_DIGEST_LENGTH,
					r_hash, SHA256_DIGEST_LENGTH,
					hash
				);
				cur_offset = (cur_offset - 1) / 2;

			}

			// Now the hash should contain root hash
			uint8_t* ref = per_bucket_hash + pos*SHA256_DIGEST_LENGTH;
			for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
				if(ref[i] != hash[i]){
					// Hash verification fails!
					cout << "ref: ";
					for(int j = 0; j < SHA256_DIGEST_LENGTH; j++){
						cout << (int)(ref[j]) << " ";
					}
					cout << endl;
					cout << "hash: ";
					for(int j = 0; j < SHA256_DIGEST_LENGTH; j++){
						cout << (int)(hash[j]) << " ";
					}
					cout << endl;
					assert(0);
					break;
				}
			}

			valid_cnt ++;
		}
	}

	// cout << "recv_and_verify_hash: success!" << endl;

}

void RemoteServerStorage::setCapacity(int totalNumOfBuckets, bool integrity = false) {
	// cout << "Set capacity going" << endl; 
	if (this->is_capacity_set) {
		throw new runtime_error("Capacity of RemoteServerStorage cannot be changed");
	}
	this->is_capacity_set = true;
	this->capacity = totalNumOfBuckets;

	if(isServer){
		// this->buckets.assign(totalNumOfBuckets, new SBucket());
		// for(int i = 0; i < capacity; i++){
		// 	SBucket* sbkt = new SBucket(integrity);
		// 	buckets.push_back(sbkt);
		// }
	}
}

int RemoteServerStorage::P(int leaf, int level) {
    return (1<<level) - 1 + (leaf >> (this->num_levels - level - 1));
}

bool RemoteServerStorage::verify_and_insert(int pos, uint8_t* hash){
	auto it = hash_map.find(pos);
	if(it == hash_map.end()){
		// This bucket is new to the merkle tree
		hash_map.insert(make_pair(pos, vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH)));
	} else{
		vector<uint8_t> ref = it->second;
		for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
			if(ref[i] != hash[i]){
				// Hash verification fails!
				cout << "ref: ";
				for(int j = 0; j < SHA256_DIGEST_LENGTH; j++){
					cout << (int)(ref[j]) << " ";
				}
				cout << endl;
				cout << "hash: ";
				for(int j = 0; j < SHA256_DIGEST_LENGTH; j++){
					cout << (int)(hash[j]) << " ";
				}
				cout << endl;
				return false;
			}
		}
	}
	return true;
}

void RemoteServerStorage::sync_root(){
	if(isServer){
		io->send_data(root.data(), SHA256_DIGEST_LENGTH*sizeof(uint8_t));
	} else{
		io->recv_data(root.data(), SHA256_DIGEST_LENGTH*sizeof(uint8_t));
		hash_map.insert(make_pair(0, root));
	}
}

void RemoteServerStorage::insecureLoad(vector<Bucket>& input_bkts){
	assert(0);

	if(!isServer){
		throw new runtime_error("insecureLoad is for server only");
	}
	cout << "Insecure loading... " << endl;
	int per_block_size = (1 + block_size) * sizeof(int);
	for(int i = 0; i < capacity; i++){
		unsigned char* payload = new unsigned char[SBucket::getCipherSize()];
		unsigned char* tmp = payload;
		bool found = false;
		for(Block& b : input_bkts[i].getBlocks()){
			b.to_ptr(tmp);
			tmp += per_block_size;
		}
		
		// Encrypt and write
		int ctx_len = encrypt_wrapper(payload, per_block_size*Bucket::getMaxSize(), this->buckets[i]->data);
		assert(ctx_len == SBucket::getCipherSize());

		// this->buckets[i]->from_ptr(payload);

		delete[] payload;
	}

	if(integrity){
		cout << "Construct Merkle Tree... " << endl;
		// Assume the oram tree is an binary tree
		// , where 2*i for left child and 2*i + 1 for right child

		vector<bool> vt(capacity, false);
		for(int i = capacity ; i >= 1; i--){
			int id = i-1;
			int lid = 2*i-1;
			int rid = 2*i;
			if(lid > capacity - 1){
				// leaf node
				int id = i-1;
				sha256_wrapper(this->buckets[id]->data, SBucket::getCipherSize(), this->buckets[id]->hash);
			} else{
				// internal node
				sha256_trib_input_wrapper(
					this->buckets[id]->data, SBucket::getCipherSize(),
					this->buckets[lid]->hash, SHA256_DIGEST_LENGTH,
					this->buckets[rid]->hash, SHA256_DIGEST_LENGTH,
					this->buckets[id]->hash
				);
			}
		}

		for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
			root[i] = this->buckets[0]->hash[i];
		}

	}
	cout << "done... " << endl;
}

void RemoteServerStorage::insecureLoadPtr(int* bkts){
	if(!isServer){
		throw new runtime_error("insecureLoad is for server only");
	}
	cout << "Insecure loading... " << endl;
	int64_t per_block_size = (1 + block_size) * sizeof(int);
	int64_t per_bucket_size = Bucket::getMaxSize()*per_block_size;
	for(int i = 0; i < capacity; i++){
		unsigned char* payload = (unsigned char*)bkts + i*per_bucket_size;
		// Encrypt and write
		int ctx_len = encrypt_wrapper(payload, per_bucket_size, this->buckets[i]->data);
		assert(ctx_len == SBucket::getCipherSize());

		// this->buckets[i]->from_ptr(payload);
	}

	// #ifdef INTEGRITY_CHECK
	// cout << "Construct Merkle Tree... " << endl;
	// // Assume the oram tree is an binary tree
	// // , where 2*i for left child and 2*i + 1 for right child

	// vector<bool> vt(capacity, false);
	// for(int i = capacity ; i >= 1; i--){
	// 	int id = i-1;
	// 	int lid = 2*i-1;
	// 	int rid = 2*i;
	// 	if(lid > capacity - 1){
	// 		// leaf node
	// 		int id = i-1;
	// 		sha256_wrapper(this->buckets[id]->data, SBucket::getCipherSize(), this->buckets[id]->hash);
	// 	} else{
	// 		// internal node
	// 		sha256_trib_input_wrapper(
	// 			this->buckets[id]->data, SBucket::getCipherSize(),
	// 			this->buckets[lid]->hash, SHA256_DIGEST_LENGTH,
	// 			this->buckets[rid]->hash, SHA256_DIGEST_LENGTH,
	// 			this->buckets[id]->hash
	// 		);
	// 	}
	// }

	// for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
	// 	root[i] = this->buckets[0]->hash[i];
	// }
	
	// #endif

	cout << "done... " << endl;
}

Bucket RemoteServerStorage::ReadBucket(int position) {
	assert(0);

	if(isServer){
		throw new runtime_error("Read/Write Bucket is for client only");
	}

	if (!this->is_capacity_set) {
		throw new runtime_error("Please call setCapacity before reading or writing any block");
	}

	if (position >= this->capacity || position < 0) {
		//std::ostringstream positionStream;
		//positionStream << position;
		throw new runtime_error("You are trying to access Bucket " + to_string(position) + ", but this Server contains only " + to_string(this->capacity) + " buckets.");
	}

	// A read request
	int rt = Read;
	io->send_data(&rt, sizeof(int));

	// Send Bucket ID
	io->send_data(&position, sizeof(int));
	
	unsigned char* ctx_payload = new unsigned char[SBucket::getCipherSize()];
	io->recv_data(ctx_payload, SBucket::getCipherSize());

	unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
	int ptx_len = decrypt_wrapper(ctx_payload, SBucket::getCipherSize(), ptx_payload);
	int per_block_size = (1 + block_size) * sizeof(int);
	// assert(ptx_len == per_block_size*Bucket::getMaxSize());

	Bucket init_bkt = Bucket();
	unsigned char* tmp = ptx_payload;
	for(int i = 0; i < Bucket::getMaxSize(); i++){
		Block b(block_size);
		b.from_ptr(tmp);
		tmp += per_block_size;
		init_bkt.addBlock(b);
	}

	delete[] ptx_payload;
	return init_bkt;
}

void RemoteServerStorage::WriteBucket(int position, const Bucket& bucket_to_write) {

	assert(0);

	if(isServer){
		throw new runtime_error("Read/Write Bucket is for client only");
	}

	if (!this->is_capacity_set) {
		throw new runtime_error("Please call setCapacity before reading or writing any block");
	}

	if (position >= this->capacity || position < 0) {
		throw new runtime_error("You are trying to access Bucket " + to_string(position) + ", but this Server contains only " + to_string(this->capacity) + " buckets.");
	}

	// // sel
	// io->send_data(&sel, sizeof(bool));

	// A read request
	int rt = Write;
	io->send_data(&rt, sizeof(int));

	// Send Bucket ID
	io->send_data(&position, sizeof(int));

	unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
	int per_block_size = (1 + block_size) * sizeof(int);

	// Serialize the data
	unsigned char* tmp = ptx_payload;
	for(Block& b : bucket_to_write.getBlocks()){
		b.to_ptr(tmp);
		tmp += per_block_size;
		// b.printBlockInt();
	}

	unsigned char* ctx_payload = new unsigned char[SBucket::getCipherSize()];
	int ctx_len = encrypt_wrapper(ptx_payload, per_block_size*Bucket::getMaxSize(), ctx_payload);
	// assert(ctx_len == SBucket::getMaxSize());

	io->send_data(ctx_payload, SBucket::getCipherSize());
	
	delete[] ptx_payload;
	delete[] ctx_payload;
	return;
}

void RemoteServerStorage::ReadBucketBatch(const std::vector<int>& positions, std::vector<Bucket>& bkts){

	assert(0);
	
	// if(isServer){
	// 	throw new runtime_error("Read/Write Bucket is for client only");
	// }

	// if (!this->is_capacity_set) {
	// 	assert(0);
	// 	throw new runtime_error("Please call setCapacity before reading or writing any block");
	// }

	// // cout << "ReadBucketBatch: " << positions.size() << " " << SBucket::getCipherSize() << endl;
	
	// int rt = ReadBatch;
	// io->send_data(&rt, sizeof(int));

	// size_t num_buckets = positions.size();
	// io->send_data(&num_buckets, sizeof(size_t));
	// io->send_data(positions.data(), sizeof(int)*num_buckets);
	// // cout << "ReadBucketBatch num_buckets: " << num_buckets << endl;

	// size_t len = num_buckets * (SBucket::getCipherSize());
	// // cout << "ReadBucketBatch allocate payload for size: " << len << endl;
	// unsigned char* payload = new unsigned char[len];
	// // cout << "ReadBucketBatch allocate done" << endl;

	// io->recv_data(payload, len);

	// // cout << "ReadBucketBatch from server" << endl;

	// #ifdef INTEGRITY_CHECK
	// int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
	// unsigned char* hash_payload = new unsigned char[hash_len];
	// io->recv_data(hash_payload, hash_len);

	// // Assume that position vector is sorted by layers. Layers close to bottom first

	// for(int bucket_id = 0; bucket_id < num_buckets; bucket_id++){
	// 	int pos = positions[bucket_id];

	// 	// Insert sibling's hash
	// 	int sib = get_sibling(pos);
	// 	unsigned char* tmp = hash_payload + bucket_id*SHA256_DIGEST_LENGTH;
	// 	// hash_map.insert(make_pair(sib, vector<uint8_t>(tmp, tmp + SHA256_DIGEST_LENGTH)));
	// 	// cout << "Processing pos: " << pos << " and sib: " << sib << endl;

	// 	if(!verify_and_insert(sib, tmp)){
	// 		cout << "Hash verification fails at sib: " << sib << endl;
	// 		assert(0);
	// 	}

	// 	// Compute and insert current hash
	// 	unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
	// 	uint8_t* hash = new uint8_t[SHA256_DIGEST_LENGTH];
	// 	if( pos >= capacity / 2){
	// 		// leaf
	// 		sha256_wrapper(ctx_payload, SBucket::getCipherSize(), hash);
	// 	} else{
	// 		// non-leaf
	// 		int l = 2*pos + 1;
	// 		int r = l + 1;
	// 		auto lit = hash_map.find(l);
	// 		auto rit = hash_map.find(r);

	// 		if(lit == hash_map.end() || rit == hash_map.end()){
	// 			// This shouldn't happen
	// 			assert(0);
	// 		}
	// 		sha256_trib_input_wrapper(
	// 			ctx_payload, SBucket::getCipherSize(),
	// 			lit->second.data(), SHA256_DIGEST_LENGTH,
	// 			rit->second.data(), SHA256_DIGEST_LENGTH,
	// 			hash
	// 		);
	// 	}

	// 	if(!verify_and_insert(pos, hash)){
	// 		cout << "Hash verification fails at pos: " << pos << endl;
	// 		assert(0);
	// 	}
		
	// 	delete[] hash;
	// }

	// delete[] hash_payload;
	// #endif

	// size_t per_block_size = (1 + block_size) * sizeof(int);
	// for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
	// 	Bucket init_bkt = Bucket();
	// 	unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
	// 	unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
	// 	size_t ptx_len = decrypt_wrapper(ctx_payload, SBucket::getCipherSize(), ptx_payload);
	// 	// assert(ptx_len == per_block_size*Bucket::getMaxSize());
	// 	unsigned char* tmp = ptx_payload;
	// 	for(size_t block_id= 0; block_id < Bucket::getMaxSize(); block_id++){
	// 		Block b(block_size);
	// 		b.from_ptr(tmp);
	// 		tmp += per_block_size;
	// 		init_bkt.addBlock(b);
	// 	}
	// 	bkts.push_back(std::move(init_bkt));
	// 	delete[] ptx_payload;
	// }

	// // cout << "ReadBucketBatch done" << endl;

	// delete[] payload;
}

void RemoteServerStorage::ReadBucketBatchAsBlock(const std::vector<int>& positions, std::vector<Block*>& blocks){
	if(isServer){
		throw new runtime_error("Read/Write Bucket is for client only");
	}

	if (!this->is_capacity_set) {
		assert(0);
		throw new runtime_error("Please call setCapacity before reading or writing any block");
	}

	// cout << "ReadBucketBatch: " << positions.size() << " " << SBucket::getCipherSize() << endl;
	
	int rt = ReadBatch;
	io->send_data(&rt, sizeof(int));

	size_t num_buckets = positions.size();
	io->send_data(&num_buckets, sizeof(size_t));
	io->send_data(positions.data(), sizeof(int)*num_buckets);
	// cout << "ReadBucketBatch num_buckets: " << num_buckets << endl;

	size_t len = num_buckets * (SBucket::getCipherSize());
	// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
	unsigned char* payload = new unsigned char[len];
	// cout << "ReadBucketBatch allocate done" << endl;

	io->recv_data(payload, len);

	// cout << "ReadBucketBatch from server" << endl;

	if(integrity){
		int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
		unsigned char* hash_payload = new unsigned char[hash_len];
		io->recv_data(hash_payload, hash_len);

		// Assume that position vector is sorted by layers. Layers close to bottom first
		for(int bucket_id = 0; bucket_id < num_buckets; bucket_id++){
			int pos = positions[bucket_id];

			// Insert sibling's hash
			int sib = get_sibling(pos);
			unsigned char* tmp = hash_payload + bucket_id*SHA256_DIGEST_LENGTH;
			// hash_map.insert(make_pair(sib, vector<uint8_t>(tmp, tmp + SHA256_DIGEST_LENGTH)));
			// cout << "Processing pos: " << pos << " and sib: " << sib << endl;

			if(!verify_and_insert(sib, tmp)){
				cout << "Hash verification fails at sib: " << sib << endl;
				assert(0);
			}

			// Compute and insert current hash
			unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
			uint8_t* hash = new uint8_t[SHA256_DIGEST_LENGTH];
			if( pos >= capacity / 2){
				// leaf
				sha256_wrapper(ctx_payload, SBucket::getCipherSize(), hash);
			} else{
				// non-leaf
				int l = 2*pos + 1;
				int r = l + 1;
				auto lit = hash_map.find(l);
				auto rit = hash_map.find(r);

				if(lit == hash_map.end() || rit == hash_map.end()){
					// This shouldn't happen
					assert(0);
				}
				sha256_trib_input_wrapper(
					ctx_payload, SBucket::getCipherSize(),
					lit->second.data(), SHA256_DIGEST_LENGTH,
					rit->second.data(), SHA256_DIGEST_LENGTH,
					hash
				);
			}
			if(!verify_and_insert(pos, hash)){
				cout << "Hash verification fails at pos: " << pos << endl;
				assert(0);
			}
			delete[] hash;
		}
		delete[] hash_payload;
	}

	size_t per_block_size = (1 + block_size) * sizeof(int);
	blocks.resize(num_buckets * Bucket::getMaxSize());
	
	#pragma omp parallel for num_threads(NUM_THREADS)
	for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
		// printf("numThreads = %d\n", omp_get_num_threads()); 
		unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
		unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
		size_t ptx_len = decrypt_wrapper(ctx_payload, SBucket::getCipherSize(), ptx_payload);
		// assert(ptx_len == per_block_size*Bucket::getMaxSize());
		unsigned char* tmp = ptx_payload;
		for(size_t block_id= 0; block_id < Bucket::getMaxSize(); block_id++){
			Block* b = new Block(block_size);
			b->from_ptr(tmp);
			tmp += per_block_size;
			blocks[block_id + bucket_id * Bucket::getMaxSize()] = b;
		}
		// bkts.push_back(std::move(init_bkt));
		delete[] ptx_payload;
	}

	// cout << "ReadBucketBatch done" << endl;

	delete[] payload;
}

void RemoteServerStorage::ReadBlockBatchAsBlockRing(const std::vector<int>& positions, const std::vector<int>& offsets, std::vector<Block*>& blocks, std::vector<bool> &valids){
	if(isServer){
		throw new runtime_error("Read/Write Bucket is for client only");
	}

	if (!this->is_capacity_set) {
		assert(0);
		throw new runtime_error("Please call setCapacity before reading or writing any block");
	}

	// Here a trick is that for ring oram we consider each bucket with only one block
	// For the sake of simple impelementation

	// cout << "ReadBlockBatchAsBlockRing: 1" << endl;
	
	int rt = ReadBatchBlock;
	io->send_data(&rt, sizeof(int));

	size_t num_blocks = positions.size();
	io->send_data(&num_blocks, sizeof(size_t));
	io->send_data(positions.data(), sizeof(int)*num_blocks);
	io->send_data(offsets.data(), sizeof(int)*num_blocks);
	// cout << "ReadBucketBatch num_blocks: " << num_blocks << endl;

	size_t len = num_blocks * (SBucket::getCipherSize());
	// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
	unsigned char* payload = new unsigned char[len];
	// cout << "ReadBucketBatch allocate done" << endl;

	io->recv_data(payload, len);

	size_t per_block_size = (1 + block_size) * sizeof(int);
	blocks.resize(num_blocks);

	// cout << "ReadBlockBatchAsBlockRing: recv_data" << endl;
	
	#pragma omp parallel for num_threads(NUM_THREADS)
	for(size_t block_id = 0; block_id < num_blocks; block_id++){
		// printf("numThreads = %d\n", omp_get_num_threads()); 
		unsigned char* ctx_payload = payload + block_id * SBucket::getCipherSize();
		// // for (int i = 0; i < 10; i++) { // Adjust the length as needed
		// // 	// Convert each byte to an unsigned value and print as hex
		// // 	std::cout << std::hex << std::setw(2) << std::setfill('0') 
		// // 			<< static_cast<int>(static_cast<unsigned char>(ctx_payload[i])) << " ";
		// // }
		// std::cout << std::endl;
		unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
		size_t ptx_len = decrypt_wrapper(ctx_payload, SBucket::getCipherSize(), ptx_payload);
		// assert(ptx_len == per_block_size*Bucket::getMaxSize());
		// unsigned char* tmp = ptx_payload;

		Block* b = new Block(block_size);
		b->from_ptr(ptx_payload);
		blocks[block_id] = b;
		
		// bkts.push_back(std::move(init_bkt));
		delete[] ptx_payload;
	}

	if(integrity){
		recv_and_verify_hash(
			positions,
			offsets,
			payload,
			valids
		);
	}

	// cout << "ReadBlockBatchAsBlockRing: recv_data done" << endl;

	delete[] payload;
}

void RemoteServerStorage::ReadBlockBatchAsBlockRingXor(const std::vector<int>& positions, const std::vector<int>& offsets, std::vector<Block*>& blocks, size_t num_real_blocks, std::vector<bool>& valids){
	// long comm = io->counter;
	if(isServer){
		throw new runtime_error("Read/Write Bucket is for client only");
	}

	if (!this->is_capacity_set) {
		assert(0);
		throw new runtime_error("Please call setCapacity before reading or writing any block");
	}

	// cout << "ReadBlockBatchAsBlockRingXor - pos_len:  " << positions.size() << ", offsets_len: " << offsets.size() << ", num_real_blocks: " << num_real_blocks << endl; 

	// cout << "ReadBlockBatchAsBlockRingXor - valids_len:  " << valids.size() << ", num_levels: " << num_levels << endl;
	
	int rt = ReadBatchBlockXor;
	io->send_data(&rt, sizeof(int));

	size_t num_blocks = positions.size();
	// assert(num_blocks % num_levels == 0);
	// size_t num_real_blocks = num_blocks / num_levels;
	io->send_data(&num_blocks, sizeof(size_t));
	io->send_data(&num_real_blocks, sizeof(size_t));
	io->send_data(positions.data(), sizeof(int)*num_blocks);
	io->send_data(offsets.data(), sizeof(int)*num_blocks);

	// no need for ivs
	size_t len = num_real_blocks * (SBucket::getCipherSize() - 16);

	unsigned char* payload = new unsigned char[len];
	unsigned char* ivs = new unsigned char[num_blocks*16];

	io->recv_data(payload, len);
	io->recv_data(ivs, num_blocks*16);

	size_t per_block_size = (1 + block_size) * sizeof(int);
	blocks.resize(num_real_blocks);

	// assert(valids.size() == num_levels*num_real_blocks);
	
	#pragma omp parallel for num_threads(NUM_THREADS)
	for(size_t block_id = 0; block_id < num_real_blocks; block_id++){
		unsigned char* ctx_payload = payload + block_id * (SBucket::getCipherSize() - 16);


		int valid_block_offset = -1;
		for(int i = 0; i < num_blocks / num_real_blocks; i++){

			size_t block_offset = block_id*(num_blocks / num_real_blocks) + i;
			if(valids[block_offset]){
				// Skip the valid block
				assert(valid_block_offset == -1);
				valid_block_offset = block_offset;
			} else{
				// Undo xor of dummies
				unsigned char* dummy_ctx = new unsigned char[SBucket::getCipherSize()];
				unsigned char* dummy_ptx = new unsigned char[SBucket::getCipherSize()];
				// TODO: enable encrypt randomization here
				Block* b = new Block(block_size);
				b->to_ptr(dummy_ptx);
				size_t ctx_len = encrypt_wrapper_with_iv(
					ivs + block_offset*16, 
					dummy_ptx, 
					per_block_size*Bucket::getMaxSize(), 
					dummy_ctx
				);

				delete b;

				assert(ctx_len == SBucket::getCipherSize() - 16);

				// for (int i = 0; i < 10; i++) { // Adjust the length as needed
				// 	// Convert each byte to an unsigned value and print as hex
				// 	std::cout << std::hex << std::setw(2) << std::setfill('0') 
				// 			<< static_cast<int>(static_cast<unsigned char>(dummy_ctx[i])) << " ";
				// }
				// std::cout << std::endl;

				for(int j = 0; j < SBucket::getCipherSize() - 16; j++){
					// de-xor
					ctx_payload[j] = ctx_payload[j] ^ dummy_ctx[j];
				}

				delete[] dummy_ctx;
				delete[] dummy_ptx;
			}
		}

		assert(valid_block_offset != -1);

		unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
		// cout << "try decrypt" << endl;
		size_t ptx_len = decrypt_wrapper_with_iv(
			ivs + valid_block_offset* 16, 
			ctx_payload, 
			SBucket::getCipherSize() - 16, 
			ptx_payload);

		// cout << "try haha" << endl;
		Block* b = new Block(block_size);
		b->from_ptr(ptx_payload);
		blocks[block_id] = b;
		delete[] ptx_payload;
	}

	if(integrity){
		recv_and_verify_hash(
			positions,
			offsets,
			payload,
			valids
		);
	}

	// cout << "ReadBlockBatchAsBlockRingXor - done."  << endl; 
	// cout << io->counter - comm << " B; ";
	delete[] payload;
	delete[] ivs;
}

void RemoteServerStorage::ReadBucketBatchAsBlockRing(const std::vector<int>& positions, std::vector<Block*>& blocks, int bucket_size){
	if(isServer){
		throw new runtime_error("Read/Write Bucket is for client only");
	}

	if (!this->is_capacity_set) {
		assert(0);
		throw new runtime_error("Please call setCapacity before reading or writing any block");
	}

	// Here a trick is that for ring oram we consider each bucket with only one block
	// For the sake of simple impelementation
	
	int rt = ReadBatch;
	io->send_data(&rt, sizeof(int));

	size_t num_buckets = positions.size();
	io->send_data(&num_buckets, sizeof(size_t));
	io->send_data(positions.data(), sizeof(int)*num_buckets);
	// cout << "ReadBucketBatch num_buckets: " << num_buckets << endl;

	size_t num_blocks = num_buckets * bucket_size;
	size_t len =  num_blocks * (SBucket::getCipherSize());
	// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
	unsigned char* payload = new unsigned char[len];
	// cout << "ReadBucketBatch allocate done" << endl;

	io->recv_data(payload, len);

	size_t per_block_size = (1 + block_size) * sizeof(int);
	blocks.resize(num_blocks);
	
	#pragma omp parallel for num_threads(NUM_THREADS)
	for (int bucket_id = 0; bucket_id < positions.size(); bucket_id++) {
		for(int block_id = 0; block_id < bucket_size; block_id++){

			unsigned char* ctx_payload = payload + (bucket_id * bucket_size + block_id) * SBucket::getCipherSize();
			unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
			size_t ptx_len = decrypt_wrapper(ctx_payload, SBucket::getCipherSize(), ptx_payload);
			// assert(ptx_len == per_block_size*Bucket::getMaxSize());

			Block* b = new Block(block_size);
			b->from_ptr(ptx_payload);
			blocks[bucket_id * bucket_size + block_id] = b;
			// bkts.push_back(std::move(init_bkt));
			delete[] ptx_payload;
		}
	}

	delete[] payload;
}


void RemoteServerStorage::WriteBucketBatch(const std::vector<int>& positions, const std::vector<Bucket>& bucket_to_write){
	assert(0);
	// if(isServer){
	// 	throw new runtime_error("Read/Write Bucket is for client only");
	// }

	// if (!this->is_capacity_set) {
	// 	throw new runtime_error("Please call setCapacity before reading or writing any block");
	// }

	// // cout << "WriteBucketBatch: " << positions.size() << endl;

	// int rt = WriteBatch;
	// io->send_data(&rt, sizeof(int));

	// size_t num_buckets = bucket_to_write.size();
	// io->send_data(&num_buckets, sizeof(size_t));

	// size_t len = num_buckets * (SBucket::getCipherSize());
	// // cout << "WriteBatch allocate payload for size: " << len << endl;
	// unsigned char* payload = new unsigned char[len];
	// // cout << "WriteBatch allocate done" << endl;

	// size_t per_block_size = (1 + block_size) * sizeof(int);

	// for (size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++) {
	// 	unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
	// 	unsigned char* tmp = ptx_payload;
	// 	for(Block& b : bucket_to_write[bucket_id].getBlocks()){
	// 		b.to_ptr(tmp);
	// 		tmp += per_block_size;
	// 	}

	// 	unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
	// 	size_t ctx_len = encrypt_wrapper(ptx_payload, per_block_size*Bucket::getMaxSize(), ctx_payload);
	// 	// assert(ctx_len == SBucket::getMaxSize());
	// 	delete[] ptx_payload;
	// }

	// io->send_data(positions.data(), positions.size()*sizeof(int));
	// io->send_data(payload, len);

	// assert(0);

	// #ifdef INTEGRITY_CHECK
	// int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
	// unsigned char* hash_payload = new unsigned char[hash_len];
	// io->send_data(hash_payload, hash_len);

	// delete[] hash_payload;
	// #endif

	// // std::cout << "Write batch 1 with len " << len << std::endl;

	// delete[] payload;

}

void RemoteServerStorage::WriteBucketBatchMap(const std::map<int, Bucket>& bucket_to_write){

	assert(0);
	
	// // // sel
	// // io->send_data(&sel, sizeof(bool));

	// int rt = WriteBatch;
	// io->send_data(&rt, sizeof(int));

	// size_t num_buckets = bucket_to_write.size();
	// io->send_data(&num_buckets, sizeof(size_t));

	// size_t len = num_buckets * (SBucket::getCipherSize());
	// unsigned char* payload = new unsigned char[len];
	// size_t per_block_size = (1 + block_size) * sizeof(int);

	// std::vector<int> positions;
	// size_t bucket_id = 0;
	// for (const auto& pair : bucket_to_write) {
	// 	positions.push_back(pair.first);
	// 	unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
	// 	unsigned char* tmp = ptx_payload;
	// 	for(Block& b : pair.second.getBlocks()){
	// 		b.to_ptr(tmp);
	// 		tmp += per_block_size;
	// 	}
	// 	unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
	// 	size_t ctx_len = encrypt_wrapper(ptx_payload, per_block_size*Bucket::getMaxSize(), ctx_payload);
	// 	// assert(ctx_len == SBucket::getMaxSize());
	// 	bucket_id++;
	// 	delete[] ptx_payload;
	// }

	// io->send_data(positions.data(), positions.size()*sizeof(int));
	// io->send_data(payload, len);

	// #ifdef INTEGRITY_CHECK
	// int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
	// unsigned char* hash_payload = new unsigned char[hash_len];

	// int first = 0;

	// // Compute new hashes
	// for(int bucket_id = num_buckets - 1; bucket_id >= 0; bucket_id--){
	// 	int pos = positions[bucket_id];

	// 	uint8_t* hash = hash_payload + bucket_id * SHA256_DIGEST_LENGTH;
	// 	unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
	// 	if( pos >= capacity / 2){
	// 		// leaf
	// 		sha256_wrapper(ctx_payload, SBucket::getCipherSize(), hash);
	// 	} else{
	// 		// non-leaf
	// 		int l = 2*pos + 1;
	// 		int r = l + 1;
	// 		auto lit = hash_map.find(l);
	// 		auto rit = hash_map.find(r);

	// 		if(lit == hash_map.end() || rit == hash_map.end()){
	// 			// This shouldn't happen
	// 			assert(0);
	// 		}
	// 		sha256_trib_input_wrapper(
	// 			ctx_payload, SBucket::getCipherSize(),
	// 			lit->second.data(), SHA256_DIGEST_LENGTH,
	// 			rit->second.data(), SHA256_DIGEST_LENGTH,
	// 			hash
	// 		);
	// 	}
	// 	hash_map[pos] = vector<uint8_t>(hash, hash+SHA256_DIGEST_LENGTH);
	// }

	// // cout << "hash all: ";
	// // for(int j = 0; j < hash_len; j++){
	// // 	cout << (int)(hash_payload[j]) << " ";
	// // }
	// // cout << endl;

	// io->send_data(hash_payload, hash_len);
	// delete[] hash_payload;

	// // Reset the hash map
	// memcpy(root, hash_map[0].data(), SHA256_DIGEST_LENGTH);
	// hash_map.clear();
	// hash_map.insert(make_pair(0, vector<uint8_t>(root, root + SHA256_DIGEST_LENGTH)));


	// #endif

	// delete[] payload;
}

void RemoteServerStorage::WriteBucketBatchMapAsBlock(const std::map<int, vector<Block*>>& bucket_to_write){

	int rt = WriteBatch;
	io->send_data(&rt, sizeof(int));

	size_t num_buckets = bucket_to_write.size();
	io->send_data(&num_buckets, sizeof(size_t));

	size_t len = num_buckets * (SBucket::getCipherSize());
	unsigned char* payload = new unsigned char[len];
	size_t per_block_size = (1 + block_size) * sizeof(int);

	std::vector<int> positions;
	size_t bucket_id = 0;
	vector<vector<Block*>> bkts;
	for (const auto& pair : bucket_to_write) {
		positions.push_back(pair.first);
		bkts.push_back(pair.second);
	}

	#pragma omp parallel for num_threads(NUM_THREADS)
	for (int bucket_id = 0; bucket_id < positions.size(); bucket_id++) {
		unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
		unsigned char* tmp = ptx_payload;
		for(Block* b : bkts[bucket_id]){
			b->to_ptr(tmp);
			tmp += per_block_size;
			delete b;
		}
		unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
		size_t ctx_len = encrypt_wrapper(ptx_payload, per_block_size*Bucket::getMaxSize(), ctx_payload);
		// assert(ctx_len == SBucket::getMaxSize());
		delete[] ptx_payload;
	}

	io->send_data(positions.data(), positions.size()*sizeof(int));
	io->send_data(payload, len);

	if(integrity){
		int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
		unsigned char* hash_payload = new unsigned char[hash_len];

		// Compute new hashes
		for(int bucket_id = num_buckets - 1; bucket_id >= 0; bucket_id--){
			int pos = positions[bucket_id];

			uint8_t* hash = hash_payload + bucket_id * SHA256_DIGEST_LENGTH;
			unsigned char* ctx_payload = payload + bucket_id * SBucket::getCipherSize();
			if( pos >= capacity / 2){
				// leaf
				sha256_wrapper(ctx_payload, SBucket::getCipherSize(), hash);
			} else{
				// non-leaf
				int l = 2*pos + 1;
				int r = l + 1;
				auto lit = hash_map.find(l);
				auto rit = hash_map.find(r);

				if(lit == hash_map.end() || rit == hash_map.end()){
					// This shouldn't happen
					assert(0);
				}
				sha256_trib_input_wrapper(
					ctx_payload, SBucket::getCipherSize(),
					lit->second.data(), SHA256_DIGEST_LENGTH,
					rit->second.data(), SHA256_DIGEST_LENGTH,
					hash
				);
			}
			hash_map[pos] = vector<uint8_t>(hash, hash+SHA256_DIGEST_LENGTH);
		}

		io->send_data(hash_payload, hash_len);
		delete[] hash_payload;

		// Reset the hash map
		memcpy(root.data(), hash_map[0].data(), SHA256_DIGEST_LENGTH);
		hash_map.clear();
		hash_map.insert(make_pair(0, root));
	}

	delete[] payload;
}

void RemoteServerStorage::WriteBucketBatchMapAsBlockRing(const std::map<int, vector<Block*>>& bucket_to_write, int bucket_size){
	
	int rt = WriteBatch;
	io->send_data(&rt, sizeof(int));

	size_t num_buckets = bucket_to_write.size();
	io->send_data(&num_buckets, sizeof(size_t));

	size_t num_blocks = num_buckets*bucket_size;

	size_t len = num_blocks * (SBucket::getCipherSize());
	unsigned char* payload = new unsigned char[len];
	size_t per_block_size = (1 + block_size) * sizeof(int);

	std::vector<int> positions;
	size_t bucket_id = 0;
	vector<vector<Block*>> bkts;
	for (const auto& pair : bucket_to_write) {
		positions.push_back(pair.first);
		bkts.push_back(pair.second);
	}

	#pragma omp parallel for num_threads(NUM_THREADS)
	for (int bucket_id = 0; bucket_id < positions.size(); bucket_id++) {
		for(int block_id = 0; block_id < bucket_size; block_id++){
			unsigned char* ptx_payload = new unsigned char[SBucket::getCipherSize()];
			bkts[bucket_id][block_id]->to_ptr(ptx_payload);
			unsigned char* ctx_payload = payload + (bucket_id * bucket_size + block_id) * SBucket::getCipherSize();
			size_t ctx_len = encrypt_wrapper(ptx_payload, per_block_size*Bucket::getMaxSize(), ctx_payload);
			delete[] ptx_payload;
			delete bkts[bucket_id][block_id];
		}
	}

	io->send_data(positions.data(), positions.size()*sizeof(int));
	io->send_data(payload, len);

	if(integrity){

        uint8_t* per_block_hash = new uint8_t[SHA256_DIGEST_LENGTH * num_blocks];
		#pragma omp parallel for num_threads(NUM_THREADS)
        for(size_t i = 0; i < num_blocks; i++){
            sha256_wrapper(payload + i*SBucket::getCipherSize(), SBucket::getCipherSize(), per_block_hash + i*SHA256_DIGEST_LENGTH);
        }

		size_t hash_payload_size = num_buckets * per_bucket_hashes * SHA256_DIGEST_LENGTH;
		uint8_t* hash_payload = new uint8_t[hash_payload_size];
		memset(hash_payload, 0, hash_payload_size);

		#pragma omp parallel for num_threads(NUM_THREADS)
		for(size_t i = 0; i < num_buckets; i++){
			for(size_t j = per_bucket_hashes; j >= 1; j--){
                size_t id = j-1;
                size_t lid = 2*j-1;
                size_t rid = 2*j;
                if(lid > per_bucket_hashes - 1){
                    // leaf
                    size_t offset = j - (per_bucket_hashes + 1) / 2;
                    if(offset < bucket_size){
                        uint8_t* src = per_block_hash + i * bucket_size * SHA256_DIGEST_LENGTH + offset * SHA256_DIGEST_LENGTH;
                        uint8_t* dst = hash_payload + i * per_bucket_hashes * SHA256_DIGEST_LENGTH + id * SHA256_DIGEST_LENGTH;
                        memcpy(dst, src, SHA256_DIGEST_LENGTH);
                    }
                } else{
                    // internal node
                    uint8_t* dst = hash_payload + i * per_bucket_hashes * SHA256_DIGEST_LENGTH + id * SHA256_DIGEST_LENGTH;
                    uint8_t* lsrc = hash_payload + i * per_bucket_hashes * SHA256_DIGEST_LENGTH + lid * SHA256_DIGEST_LENGTH;
                    uint8_t* rsrc = hash_payload + i * per_bucket_hashes * SHA256_DIGEST_LENGTH + rid * SHA256_DIGEST_LENGTH;

                    sha256_twin_input_wrapper(
                        lsrc, SHA256_DIGEST_LENGTH,
                        rsrc, SHA256_DIGEST_LENGTH,
                        dst
                    );
                }
            }

			// update local root
			memcpy(
				per_bucket_hash + positions[i]*SHA256_DIGEST_LENGTH,
				hash_payload + i * per_bucket_hashes * SHA256_DIGEST_LENGTH,
				SHA256_DIGEST_LENGTH
			);

			// cout << "update root for pos: " << positions[i] << ": " ;
			// // for(int j = 0; j < SHA256_DIGEST_LENGTH; j++){
			// // 	cout << (int)((per_bucket_hash + positions[i]*SHA256_DIGEST_LENGTH)[j]) << " ";
			// // }
			// cout << endl;
		}

		io->send_data(hash_payload, hash_payload_size);

		delete[] hash_payload;
		delete[] per_block_hash;
	}

	delete[] payload;
}

void RemoteServerStorage::RunServer(){

	if(!isServer){
		throw new runtime_error("RunServer is for server only");
	}
	cout << "Remote storage servers running ..." << endl;

	while(1) {
		int rt;
		io->recv_data(&rt, sizeof(int));
		switch (rt){
			case Read:{
				assert(0);
				int bucket_id;
				io->recv_data(&bucket_id, sizeof(int));
				// this->buckets[bucket_id]->to_io(io);
				break;
			}
			case Write:{
				assert(0);
				int bucket_id;
				io->recv_data(&bucket_id, sizeof(int));
				// this->buckets[bucket_id]->from_io(io);
				break;
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

				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					size_t bucket_pos = position[bucket_id]; 
					size_t bucket_offset = bucket_id * SBucket::getCipherSize();
					this->buckets[bucket_pos]->data_to_ptr(payload + bucket_offset);
				} 

				// cout << "ReadBucketBatch write to payload done" << endl;

				io->send_data(payload, sizeof(unsigned char)*len);

				// cout << "ReadBucketBatch send to client done" << endl;

				if(integrity){
					int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
					unsigned char* hash_payload = new unsigned char[hash_len];

					for(int bucket_id = 0; bucket_id < num_buckets; bucket_id++){
						int bucket_pos = position[bucket_id]; 
						int bucket_offset = bucket_id * SHA256_DIGEST_LENGTH;
						this->buckets[get_sibling(bucket_pos)]->hash_to_ptr(hash_payload + bucket_offset);
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
				
				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					size_t bucket_pos = position[bucket_id]; 
					size_t bucket_offset = bucket_id * SBucket::getCipherSize();
					this->buckets[bucket_pos]->data_from_ptr(payload + bucket_offset);
				}

				if(integrity){
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

void RemoteServerStorage::RunServer_disk(){

	if(!isServer){
		throw new runtime_error("RunServer is for server only");
	}
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
				// Load file into memory
				int fd = open(buckets_fname, O_RDWR);
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
				size_t file_size = st.st_size;

				// Memory-map the file with read-write permissions
				char* data = static_cast<char*>(mmap(nullptr, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
				if (data == MAP_FAILED) {
					perror("Error mapping file");
					close(fd);
					assert(0);
				}

				char* sbuckets = data + sizeof(int) + sizeof(int) + sizeof(bool);

				size_t num_buckets;
				io->recv_data(&num_buckets, sizeof(size_t));
				std::vector<int> position(num_buckets);
				io->recv_data(position.data(), sizeof(int)*num_buckets);

				size_t len = num_buckets * (SBucket::getCipherSize());
				// cout << "ReadBucketBatch allocate payload for size: " << len << endl;
				unsigned char* payload = new unsigned char[len];
				// cout << "ReadBucketBatch allocate done" << endl;

				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					size_t bucket_pos = position[bucket_id]; 
					size_t bucket_offset = bucket_id * SBucket::getCipherSize();
					char* sbkt = sbuckets + bucket_pos * SBucket::getCipherSize();
					memcpy(payload + bucket_offset, sbkt, SBucket::getCipherSize());
					// this->buckets[bucket_pos]->data_to_ptr(payload + bucket_offset);
				} 

				// cout << "ReadBucketBatch write to payload done" << endl;

				io->send_data(payload, sizeof(unsigned char)*len);

				// cout << "ReadBucketBatch send to client done" << endl;

				if(integrity){
					assert(0);
					// int hash_len = num_buckets * SHA256_DIGEST_LENGTH;
					// unsigned char* hash_payload = new unsigned char[hash_len];

					// for(int bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					// 	int bucket_pos = position[bucket_id]; 
					// 	int bucket_offset = bucket_id * SHA256_DIGEST_LENGTH;
					// 	this->buckets[get_sibling(bucket_pos)]->hash_to_ptr(hash_payload + bucket_offset);
					// } 

					// io->send_data(hash_payload, sizeof(unsigned char)*hash_len);
					// delete[] hash_payload;
				}

				delete[] payload;
				if (munmap(data, file_size) == -1) {
					perror("Error unmapping file");
				}
				close(fd);
				break;
			}
			case WriteBatch:{
				// Load file into memory
				int fd = open(buckets_fname, O_RDWR);
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
				size_t file_size = st.st_size;

				// Memory-map the file with read-write permissions
				char* data = static_cast<char*>(mmap(nullptr, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
				if (data == MAP_FAILED) {
					perror("Error mapping file");
					close(fd);
					assert(0);
				}

				char* sbuckets = data + sizeof(int) + sizeof(int) + sizeof(bool);

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
				
				for(size_t bucket_id = 0; bucket_id < num_buckets; bucket_id++){
					size_t bucket_pos = position[bucket_id]; 
					size_t bucket_offset = bucket_id * SBucket::getCipherSize();
					char* sbkt = sbuckets + bucket_pos * SBucket::getCipherSize();
					memcpy(sbkt, payload + bucket_offset, SBucket::getCipherSize());
					// this->buckets[bucket_pos]->data_from_ptr(payload + bucket_offset);
				}

				if(integrity){
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

				delete[] payload;
				if (munmap(data, file_size) == -1) {
					perror("Error unmapping file");
				}
				close(fd);
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

void RemoteServerStorage::CloseServer(){
	int rt = End;
	io->send_data(&rt, sizeof(int));
}

void RemoteServerStorage::InitServer(){
	int rt = Init;
	io->send_data(&rt, sizeof(int));
	io->recv_data(&rt, sizeof(int));
}


void RemoteServerStorage::save(const char* fname){
	FILE* f = fopen(fname, "w");
    if (!f) {
        fprintf(stderr, "could not open %s\n", fname);
        perror("");
        abort();
    }
	// Write capacity
	fwrite(&capacity, 1, sizeof(int), f);
	// Write SBucket size
	int sb_size = SBucket::getCipherSize();
	fwrite(&sb_size, 1, sizeof(int), f);

	fwrite(&integrity, 1, sizeof(bool), f);


    for (size_t i = 0; i < capacity; i++){
        fwrite(this->buckets[i]->data, 1, SBucket::getCipherSize(), f);
		if(integrity){
			fwrite(this->buckets[i]->hash, 32, sizeof(uint8_t), f);
		}
    }
    fclose(f);
}


void RemoteServerStorage::load(const char* fname){
	int fd = open(fname, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "could not open %s\n", fname);
        perror("");
        abort();
    }
    
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

    close(fd);
}


void RemoteServerStorage::load_disk(const char* fname){
	int fd = open(fname, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "could not open %s\n", fname);
        perror("");
        abort();
    }
    
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

	if(integrity){
		for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
			root[i] = this->buckets[0]->hash[i];
		}
	}

    close(fd);

	buckets_fname = (char *)malloc(strlen(fname) + 1);
	strcpy(buckets_fname, fname);
	
}
