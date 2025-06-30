/*
    Interface for an ANN algorithm to be ported with the ORAM
*/
#ifndef PORAM_API_H
#define PORAM_API_H

#include "ArgMapping.h"
#include "net_io_channel.h"

// stl
#include <sys/resource.h>
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
#include <cstdint>

// oram
#include "RemoteServerStorage.h"
#include "RemoteServerRing.h"
#include "RandForOramInterface.h"
#include "RandomForOram.h"
#include "OramRing.h"
#include "OramReadPathEviction.h"
#include "OramInterface.h"
#include "RemoteRing.h"

#include "diskann/include/timer.h"

using namespace std;

using node_id_t = int32_t;
using block_id_t = int32_t;
using offset_id_t = int64_t;


inline double elapsed() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

inline void tprint(string s, double t0){
    cout << "[" << std::fixed << std::setprecision(3) << elapsed() - t0 << "s] " << s;
}

template<typename T, typename LabelT = node_id_t>
struct DiskANNNode {
    // layout:  node_id | neighbors | coords 
    // next_layer_neighbors is only for nodes in upper layers or layer_id != 0

    int len;        // == num_components_in_diskann_aligned_data
    vector<T> data;
    LabelT node_id;

    char* diskann_aligned_data;

    static int n_neighbors;
    static int dim; 

    DiskANNNode(){
        len = dim + 1 + n_neighbors; // coords | n_nbrs | nbr_ids
        data = vector<T>(len, -1);
        diskann_aligned_data = (char*) malloc(len * sizeof(T));
    }

    DiskANNNode(T* input, float large_number){
        len = dim + 1 + n_neighbors; // coords | n_nbrs | nbr_ids

        data.resize(len);
        memcpy(data.data(), input, len*sizeof(T));

        for(int i = 0; i < dim; i++){
            data[1 + n_neighbors + i] /= large_number;  // scale the coordinates
        }

        diskann_aligned_data = (char*) malloc(len * sizeof(T));

        // copy node_coords
        memcpy(diskann_aligned_data, data.data() + 1 + n_neighbors, dim*(sizeof(T)/sizeof(char)));  // skip node_id and n_nbrs

        // copy the neighbour ids
        // find num_nbrs 
        T* nbr = input + 1;     // skipped the node_id
        T num_actual_nbrs = 0;
        int i = 0;

        T minus_one = (T) -1;
        while(i < n_neighbors){
            if(*nbr < 0){
                // diskann_aligned_data[(dim + 1) + i] = (T) -1;
                memcpy(diskann_aligned_data + ((dim + 1) + i)*sizeof(T), &minus_one, 1*sizeof(T)/sizeof(char));
            } else {
                memcpy(diskann_aligned_data + ((dim + 1) + i)*sizeof(T), nbr, 1*sizeof(T)/sizeof(char));
                num_actual_nbrs++;
            }

            nbr++;
            i++;
        }

        // write number of neighbours
        memcpy(diskann_aligned_data + dim*sizeof(T), &num_actual_nbrs, 1*sizeof(T));

        this->node_id = (LabelT) data[0];

    }


    ~DiskANNNode(){
        if(diskann_aligned_data != NULL){
            free(diskann_aligned_data);
        }
    }

    void print_node_info(){
        cout << "Node ID: " << node_id << endl;
        cout << "Neighbors: ";
        for(int i = 0; i < n_neighbors; i++){
            if(data[1 + i] >= 0){
                cout << data[1 + i] << " ";
            }
        }
        cout << endl;
        cout << "Coordinates: ";
        for(int i = 0; i < dim; i++){
            cout << data[1 + n_neighbors + i] << " ";
        }
        cout << endl << endl;
    }

    int get_int_size(){
        return len;
    }

    T* get_int_data(){
        return data.data();
    }

    char* get_diskann_aligned_data(){
        return diskann_aligned_data;
    }

    LabelT get_id(){
        assert(data.size() > 0);
        return node_id;
    }

    void set_id(LabelT nid){
        assert(nid >= 0);
        node_id = nid;
        data[0] = (T) nid;
    }

    vector<LabelT> get_neighbors(){
        return vector<LabelT>(data.begin() + 1, data.begin() + 1 + DiskANNNode::n_neighbors); 
    }

    void set_neighbors(vector<LabelT>& nbs){
        assert(nbs.size() == DiskANNNode::n_neighbors);

        for(int i = 0; i < nbs.size(); i++){
            data[1 + i] = (T) nbs[i];
        }
    }

    void set_coords(vector<T>& coords){
        // cout << coords.size() << " " << dim << "\n";
        // bad but assuming sizeof(int) == size(float)
        assert(coords.size() == dim);
        memcpy(data.data() + 1 + DiskANNNode::n_neighbors, coords.data(), dim*sizeof(T));
    }

    T* get_coords(){
        return (T *)(data.data() + 1 + DiskANNNode::n_neighbors);
    }

    void print_node(){
        for(auto x : data){
            cout << x << " ";
        }
        cout << endl;
    }

    bool operator==(const DiskANNNode& other) const {
        if(other.len != len){
            return false;
        }
        for(int i = 0; i < len; i++){
            if(data[i] != other.data[i]){
                return false;
            }
        }
        
        return true;
    }
};


class OramAPI {
    public:
    OramInterface* oram;

    map<int, int> node_to_block_map;
    vector<int> node_to_block;
    bool debug;
    int oram_calls = 0;
    float large_number;

    OramAPI(
        RemoteRing* rss,
        RandForOramInterface* random,
        int total_blocks,
        int num_levels,
        int oram_cached_levels,
        int block_size,
        int real_bucket_size,
        int dummy_size,
        int evict_rate,
        string block_mapping_file,
        string metadata_path,
        string pos_map_path,
        bool debug,
        float large_number,
        RingOramConfig config
    ){
        oram = new OramRing(
            rss, 
            random, 
            config,
            num_levels,
            oram_cached_levels,
            true,
            true
        );

        this->debug = debug;
        this->large_number = large_number;

        if (debug) printf("Loading ORAM metadata\n");
        ((OramRing*)oram)->loadMetaDataFromFile(metadata_path.c_str());

        if (debug) printf("Loading position map\n");
        ((OramRing*)oram)->loadPositionMapFromFile(pos_map_path.c_str());
        if (debug) printf("Position map successfully loaded\n");

        int total_nodes = oram->getNumBlocks();    // == total_nodes_in_graph
        node_to_block.resize(total_nodes);

        if (debug) printf("Loading block mapping file\n");
        read_node_to_block_mapping(block_mapping_file.c_str());
        if (debug) printf("Block mapping file successfully loaded\n");

        ((OramRing*) oram)->init_cache_top();
    }

    ~OramAPI() {
        delete oram;
    }

    void read_node_to_block_mapping(const char* block_mapping_file){
        int total_nodes = oram->getNumBlocks();    // == total_nodes_in_graph
        if (debug) cout << "Total nodes: " << total_nodes << endl;

        int num_levels_in_compass = 1;

        int* data = new int[num_levels_in_compass*total_nodes];


        FILE* f = fopen(block_mapping_file, "r");
        if (!f) {
            fprintf(stderr, "could not open %s\n", block_mapping_file);
            perror("");
            abort();
        }
        fread(data, sizeof(int), num_levels_in_compass*total_nodes, f);
        fclose(f);

        if (debug) cout << "Starting to load node to block mapping" << endl;
        for(int i = 0; i < total_nodes; i++){
            this->node_to_block_map[i] = *(data + num_levels_in_compass*i);
            this->node_to_block[i] = *(data + num_levels_in_compass*i);
        }

        delete[] data;
    }

    vector<block_id_t> get_block_ids(vector<node_id_t> node_ids){
        vector<int> block_ids;
        for(auto node_id : node_ids){
            int block_id = node_to_block_map[node_id];
            block_ids.push_back(block_id);
            // cout << "Block ID: " << block_id << " ";
        }
        // cout << "\n";
        return block_ids;
    }

    template<typename T,  typename LabelT=node_id_t>
    vector<DiskANNNode<T, LabelT>*> oram_access(vector<node_id_t> node_ids, int padded_access_size){        
        int real_accesses = node_ids.size();

        vector<block_id_t> block_ids = get_block_ids(node_ids);

        // int num_rounds = ((RemoteServerStorage*) ((OramRing*) oram)->storage)->io->num_rounds;

        vector<T*> fetched_blocks =((OramRing*) oram)->batch_multi_access_swap_ro_templated<T>(
            vector<OramInterface::Operation>(real_accesses, OramInterface::Operation::READ),
            block_ids,
            vector<T*>(real_accesses, NULL),
            padded_access_size
        );

        // cout << ((RemoteServerStorage*) ((OramRing*) oram)->storage)->io->num_rounds - num_rounds << " ";

        vector<DiskANNNode<T, LabelT>*> nodes;
        for(int i = 0; i < real_accesses; i++){
            DiskANNNode<T, LabelT>* node = new DiskANNNode<T, LabelT>(fetched_blocks[i], large_number);
            nodes.push_back(node);

            delete fetched_blocks[i];
        }

        return nodes;
    }

};

#endif