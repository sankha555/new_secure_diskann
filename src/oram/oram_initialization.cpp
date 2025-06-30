#include "ArgMapping.h"
#include "defaults.h"

// stl
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

// oram
#include "macro.h"
#include "OramAPI.h"
#include "config_parser.h"
#include "OramBuilder.h"
#include "io_utils.h"

using namespace std;

string dataset;
string config_path;

string degree;
string efc;
string pq_bytes;

int main(int argc, char** argv) {
    // this code should be run on the server
    ArgMapping amap;
    amap.arg("d", dataset, "Dataset: [sift, trip, msmarco, laion]");
    amap.arg("c", config_path, "Path to config file");
    amap.arg("r", degree, "degree of graph");
    amap.arg("e", efc, "ef construction");
    amap.arg("p", pq_bytes, "PQ bytes per vector");

    amap.parse(argc, argv);
    
    cout << "Starting oram initialization..." << endl;

    Metadata md;

    config_path = config_path.size() == 0 ? (CONFIG_DIR) + "config_" + dataset + ".json" : config_path;
    cout << config_path << "\n";
    if (parseJson(config_path, md, dataset) != 0) {
        cerr << "Error: Failed to parse JSON configuration." << endl;
        return EXIT_FAILURE;
    }

    cout << "Configuration loaded successfully." << endl;

    DiskANNNode<float, node_id_t>::dim = md.dim;
    DiskANNNode<float, node_id_t>::n_neighbors = md.M;

    struct RingOramConfig config(
        md.block_size, 
        md.real_bucket_size, 
        md.dummy_size, 
        md.evict_rate, 
        md.base_size,
        md.num_levels,
        md.oram_cached_levels
    );

    Bucket::setMaxSize(1);
    SBucket::setCipherSize(compute_ctx_len((1 + md.block_size) * sizeof(int)));

    OramBuilder<float, node_id_t> *oram_builder = new OramBuilder<float, node_id_t>(
        md.buckets_path.c_str(),
        md.block_map_path.c_str(),
        md.pos_map_path.c_str(),
        md.metadata_path.c_str(),
        md.base_size,
        md.large_number,
        &config
    );

    // load database
    size_t nb, dim;
    float* database = fvecs_read(md.base_path.c_str(), &dim, &nb);
    // assert((node_id_t) nb == (node_id_t) md.base_size);

    string index_path = GRAPHS_DIR + dataset + "/graph_R" + degree + "_L" + efc + "_PQ" + pq_bytes + ".txt";
    cout << "Initializing ORAM from " << index_path << "\n";
    oram_builder->load_index(index_path.c_str());
    oram_builder->initiate_and_write_blocks(database, md.block_size);

    cout << "Oram initialization done!" << endl;

    return 0;
}
