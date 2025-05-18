#ifndef PORAM_BUILDER_H
#define PORAM_BUILDER_H

#include <iostream>
#include <iomanip>
#include <cmath>
#include <chrono>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <fstream>
#include <sys/time.h>
#include <stdlib.h>

// diskann
// #include "oram_index.h"

// oram
#include "OramInterface.h"
#include "node.h"
#include "OramAPI.h"

using namespace std;
// using namespace diskann;

template<typename T, typename LabelT = node_id_t>
class OramBuilder {

    public:

    const char* buckets_path;
    const char* block_map_path;
    const char* position_map_path;
    const char* metadata_path;

    RingOramConfig* config;
    RandForOramInterface* random;
    FakeBlockFetcherRing<T, LabelT>* block_fetcher;

    map<node_id_t, vector<node_id_t>> graph;

    OramBuilder(
        const char* buckets_path,
        const char* block_map_path,
        const char* position_map_path,
        const char* metadata_path,
        node_id_t num_points,
        RingOramConfig* config
    ) {
        this->buckets_path = buckets_path;
        this->block_map_path = block_map_path;
        this->position_map_path = position_map_path;
        this->metadata_path = metadata_path;
    
        this->config = config;
        this->random = new RandomForOram();
        this->block_fetcher = new FakeBlockFetcherRing<T, LabelT>(num_points, *config, this->random);
    }


    void load_graph(const char* graph_path){
        ifstream infile(graph_path);  // Replace with your filename
        if (!infile.is_open()) {
            cerr << "could not open file " << graph_path << endl;
            perror("");
            abort();
        }

        string line;
        while (getline(infile, line)) {
            istringstream iss(line);

            string node_id;
            iss >> node_id;
            graph[(node_id_t) stoi(node_id)] = vector<node_id_t>(DiskANNNode<T, LabelT>::n_neighbors, -1);
            
            string nbr_cnt_s;
            iss >> nbr_cnt_s;
            int nbr_cnt = stoi(nbr_cnt_s);

            for(int i = 0; i < nbr_cnt; i++){
                string nbr_id;
                iss >> nbr_id;
                graph[stoi(node_id)][i] = ((node_id_t) stoi(nbr_id));
            }

            if(stoi(node_id) % 100000 == 0){
                cout << "-> Done loading graph till node " << node_id << endl;
            }
        }

        infile.close();
    }

    void load_index(const char* index_file_path){
        // wait for Sandhya
        load_graph(index_file_path);
    }   

    void insert_real_blocks(T* database){   
        std::cout << "-> Start clustering: " << std::endl;
        node_id_t num_points = block_fetcher->num_points;

        int dim = DiskANNNode<T, LabelT>::dim;

        // cout << "num points: " << num_points << endl;
        for(int node_id = 0; node_id < num_points; node_id++){
            DiskANNNode<T, LabelT>* oram_node = new DiskANNNode<T, LabelT>();
            oram_node->set_id(node_id);

            oram_node->set_neighbors(graph[node_id]);
            
            vector<T> coords;
            for(size_t offset = node_id*dim; offset < (node_id+1)*dim; offset++){
                coords.push_back(database[offset]);
            }
            oram_node->set_coords(coords);

            // oram_node->print_node();

            block_id_t block_id = block_fetcher->add_block_with_list(oram_node, {node_id});
            // abort();

            if(node_id % 100000 == 0){
                std::cout << "-> Done clustering: " << node_id << std::endl;
            }

            delete oram_node;
        }
        cout << "Real blocks insertion completed!" << endl;
    }

    void initiate_and_write_blocks(T* database, int block_size) {
        FILE* f = fopen(buckets_path, "w");
        if (!f) {
            fprintf(stderr, "could not open %s\n", buckets_path);
            perror("");
            abort();
        }

        insert_real_blocks(database);
        delete[] database;

        int per_block_size = (1 + config->block_size) * sizeof(int);

        bool integrity = false;

        std::vector<SBucket*> buckets;
        buckets.resize(config->num_buckets * config->bucket_size);

        vector<block_id_t> block_ids;
        block_ids.resize(config->num_buckets * config->bucket_size);

        cout << "-> Encrypting ORAM Tree..." << endl;
        #pragma omp parallel for num_threads(NUM_THREADS)
        for(int i = 0; i < config->num_buckets; i++){
            // fill in the real blocks
            for(int j = 0; j < config->real_bucket_size; j++){
                SBucket* sbkt = new SBucket(integrity);
                Bucket* bkt = block_fetcher->bkts[i*config->real_bucket_size + j];

                unsigned char* payload = new unsigned char[SBucket::getCipherSize()];

                vector<Block> blocks = bkt->getBlocks();
                assert(blocks.size() == 1);
                
                blocks[0].to_ptr(payload);
                block_ids[i*config->bucket_size + j] = blocks[0].index;

                // Encrypt and write
                int ctx_len = encrypt_wrapper(payload, per_block_size*Bucket::getMaxSize(), sbkt->data);
                
                buckets[i*config->bucket_size + j] = sbkt;
                assert(ctx_len == SBucket::getCipherSize());
                delete bkt;
                delete[] payload;
            }

            // fill in the dummy blocks
            for(int j = config->real_bucket_size; j < config->bucket_size; j++){
                SBucket* sbkt = new SBucket(integrity);
                unsigned char* payload = new unsigned char[SBucket::getCipherSize()];
                Block dummy = Block(block_size);
                dummy.to_ptr(payload);
                
                block_ids[i*config->bucket_size + j] = -1;
                int ctx_len = encrypt_wrapper(payload, per_block_size*Bucket::getMaxSize(), sbkt->data);
            
                buckets[i*config->bucket_size + j] = sbkt;
                assert(ctx_len == SBucket::getCipherSize());
                delete[] payload;
            }
        }

        assert(block_ids.size() == config->num_buckets * config->bucket_size);

        cout << "Saving block mapping..." << endl;
        block_fetcher->save_block_mapping(block_map_path);

        cout << "Saving position mapping..." << endl;
        block_fetcher->save_position_map(position_map_path);


        // Save metadata
        {
            cout << "Saving metadata..." << endl;
            int s = block_ids.size();
            FILE* f = fopen(metadata_path, "w");
            if (!f) {
                fprintf(stderr, "could not open %s\n", metadata_path);
                perror("");
                abort();
            }
            fwrite(&s, 1, sizeof(int), f);
            fwrite(block_ids.data(), 1, block_ids.size()*sizeof(int), f);
            fclose(f);
        }

        // Save buckets
        {
            cout << "Saving buckets..." << endl;
            FILE* f = fopen(buckets_path, "w");
            if (!f) {
                fprintf(stderr, "could not open %s\n", buckets_path);
                perror("");
                abort();
            }
            // Write capacity
            fwrite(&(config->num_buckets), 1, sizeof(int), f);
            // Write SBucket size
            int sb_size = SBucket::getCipherSize();
            fwrite(&sb_size, 1, sizeof(int), f);

            fwrite(&integrity, 1, sizeof(bool), f);       // not using integrity

            for (size_t i = 0; i < config->num_buckets * config->bucket_size; i++){
                size_t total_written = 0;
                size_t bytes_to_write = SBucket::getCipherSize();
                while (total_written < bytes_to_write) {
                    size_t written = fwrite(buckets[i]->data, 1, bytes_to_write - total_written, f);
                    if (written == 0) {
                        if (ferror(f)) {
                            perror("Write error");
                            break;
                        }
                    }
                    total_written += written;
                }
            }
            fclose(f);
        }

    }
};

#endif