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
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// diskann
// #include "oram_index.h"

// oram
#include "OramInterface.h"
#include "node.h"
#include "OramAPI.h"

#define NUM_THREADS 32

using namespace std;
// using namespace diskann;

template<typename T, typename LabelT = node_id_t>
class OramBuilder {

    public:

    float large_number = 1;

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
        const float large_number,
        RingOramConfig* config
    ) {
        this->buckets_path = buckets_path;
        this->block_map_path = block_map_path;
        this->position_map_path = position_map_path;
        this->metadata_path = metadata_path;
        this->large_number = large_number;

        this->config = config;
        this->random = new RandomForOram();
        this->block_fetcher = new FakeBlockFetcherRing<T, LabelT>(num_points, *config, this->random);
    }

    void load_graph(const char* graph_path) {
        int fd = open(graph_path, O_RDONLY);
        if (fd == -1) {
            perror("Failed to open file");
            abort();
        }

        // Get file size
        off_t file_size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);

        char* data = static_cast<char*>(mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0));
        if (data == MAP_FAILED) {
            perror("mmap failed");
            close(fd);
            abort();
        }

        // Find line offsets
        std::vector<size_t> line_starts;
        line_starts.push_back(0);
        for (size_t i = 0; i < file_size; ++i) {
            if (data[i] == '\n') {
                if (i + 1 < file_size)
                    line_starts.push_back(i + 1);
            }
        }

        graph.clear();

        // Parallel parse each line
        #pragma omp parallel for schedule(dynamic)
        for (size_t i = 0; i < line_starts.size(); ++i) {
            const char* line = &data[line_starts[i]];
            const char* end = (i + 1 < line_starts.size()) ? &data[line_starts[i + 1] - 1] : &data[file_size];

            std::string_view line_view(line, end - line);

            std::istringstream iss{std::string(line_view)};
            int node_id, nbr_cnt;
            iss >> node_id >> nbr_cnt;

            std::vector<node_id_t> neighbors(DiskANNNode<T, LabelT>::n_neighbors, -1);
            for (int j = 0; j < nbr_cnt && j < neighbors.size(); ++j) {
                int nbr_id;
                iss >> nbr_id;
                neighbors[j] = nbr_id;
            }

            #pragma omp critical
            {
                graph[node_id] = std::move(neighbors);
            }

            if (node_id % 100000 == 0) {
                #pragma omp critical
                std::cout << "-> Done loading graph till node " << node_id << std::endl;
            }
        }

        munmap(data, file_size);
        close(fd);
    }


    // void load_graph(const char* graph_path){
    //     ifstream infile(graph_path);  // Replace with your filename
    //     if (!infile.is_open()) {
    //         cerr << "could not open file " << graph_path << endl;
    //         perror("");
    //         abort();
    //     }

    //     string line;
    //     int i = 0; 
    //     while (getline(infile, line)) {
    //         // if(i < 60000000){
    //         //     i++;
    //         //     continue;
    //         // }

    //         istringstream iss(line);

    //         string node_id;
    //         iss >> node_id;
    //         graph[(node_id_t) stoi(node_id)] = vector<node_id_t>(DiskANNNode<T, LabelT>::n_neighbors, -1);
            
    //         string nbr_cnt_s;
    //         iss >> nbr_cnt_s;
    //         int nbr_cnt = stoi(nbr_cnt_s);

    //         for(int i = 0; i < nbr_cnt; i++){
    //             string nbr_id;
    //             iss >> nbr_id;
    //             graph[stoi(node_id)][i] = ((node_id_t) stoi(nbr_id));
    //         }

    //         if(stoi(node_id) % 100000 == 0){
    //             cout << "-> Done loading graph till node " << node_id << endl;
    //         }
    //         // if(i == 70000000){
    //         //     break;
    //         // }
    //         i++;
    //     }

    //     infile.close();
    // }

    void load_index(const char* index_file_path){
        // wait for Sandhya
        load_graph(index_file_path);
    }   

    void insert_real_blocks(T* database){   
        std::cout << "-> Start clustering: " << std::endl;
        node_id_t num_points = block_fetcher->num_points;

        int dim = DiskANNNode<T, LabelT>::dim;

        // cout << "num points: " << num_points << endl;
        for(size_t node_id = 0; node_id < num_points; node_id++){
            DiskANNNode<T, LabelT>* oram_node = new DiskANNNode<T, LabelT>();
            oram_node->set_id(node_id);

            oram_node->set_neighbors(graph[node_id]);
            graph[node_id].clear();
            
            vector<T> coords;
            for(size_t offset = node_id*dim; offset < (node_id+1)*dim; offset++){
                // if(node_id >= 2796201 && node_id < 2796204){
                //     cout << node_id << "." << offset << "\n";
                // }
                coords.push_back(database[offset]*large_number);
            }
            // cout << coords.size() << "\n";
            oram_node->set_coords(coords);

            // cout << "Hello5\n";

            if(oram_node->get_id() == 65610822){
                oram_node->print_node_info();
            }
            // cout << "Hello6\n";


            // oram_node->print_node();

            block_id_t block_id = block_fetcher->add_block_with_list(oram_node, {node_id});
            // abort();
            // cout << "Hello7\n";

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
        #pragma omp parallel for num_threads(96)
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