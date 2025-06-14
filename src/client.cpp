#include "defaults.h"
#include "ArgMapping.h"
#include "net_io_channel.h"
#include "evp.h"
#include "rapidjson/document.h"
#include <boost/program_options.hpp>
#include "io_utils.h"

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
#include <stdlib.h>

// oram
#include "macro.h"
#include "OramAPI.h"
#include "config_parser.h"

// diskann
#include "diskann_interface.h"
#include "tableprinter.h"

#include "OramBuilder.h"

using namespace std;
namespace po = boost::program_options;

int party = CLIENT_PARTY;
int port = CLIENT_PORT;
string address = CLIENT_IP;
string dataset = "";
string config_path;

void setup_connection(int port, string address, NetIO*& io, NetIO*& bf_io) {
    io = new NetIO(address.c_str(), port, false, true);
    if (!io) {
        cerr << "Error: Failed to initialize NetIO for main connection." << endl;
        exit(EXIT_FAILURE);
    }

    bf_io = new NetIO(address.c_str(), port + 1, false, true);
    if (!bf_io) {
        cerr << "Error: Failed to initialize NetIO for backup connection." << endl;
        delete io;
        exit(EXIT_FAILURE);
    }

    cout << "\nNetwork connection established with server at " << address << endl;
}

int main(int argc, char **argv) {
    cout << "Starting client..." << endl;

    ArgMapping amap;
    amap.arg("p", port, "Port Number");
    amap.arg("d", dataset, "Dataset: [sift, trip, msmarco, laion]");
    amap.arg("ip", address, "IP Address of client");
    amap.arg("c", config_path, "Path to config file");
    amap.parse(argc, argv);

    Metadata md;
    config_path = config_path.size() == 0 ?  (CONFIG_DIR) + "config_" + dataset + ".json" : config_path;
    if (parseJson(config_path, md, dataset) != 0) {
        cerr << "Error: Failed to parse JSON configuration." << endl;
        return EXIT_FAILURE;
    }

    if (md.debug) cout << "Port: " << port << ", Dataset: " << dataset << ", Address: " << address << endl;

    if (md.debug) cout << "Configuration loaded successfully." << endl;

    struct RingOramConfig config(
        md.block_size, 
        md.real_bucket_size, 
        md.dummy_size, 
        md.evict_rate, 
        md.base_size,
        md.num_levels,
        md.oram_cached_levels
    );

    DiskANNNode<float, node_id_t>::n_neighbors = md.M;
    DiskANNNode<float, node_id_t>::dim = md.dim;
    Bucket::setMaxSize(1);
    SBucket::setCipherSize(compute_ctx_len((1 + md.block_size) * sizeof(int)));

    NetIO* io = nullptr;
    NetIO* bf_io = nullptr;
    setup_connection(port, address, io, bf_io);

    RemoteRing* rss = new RemoteRing(io, config, false, true, md.integrity);
    if (!rss) {
        cerr << "Error: Failed to initialize RemoteServerStorage." << endl;
        delete io;
        delete bf_io;
        return EXIT_FAILURE;
    }
    // rss->setCapacity(config.num_buckets, md.integrity);

    RandForOramInterface* random = new RandomForOram();
    if (!random) {
        cerr << "Error: Failed to initialize RandomForOram." << endl;
        delete rss;
        delete io;
        delete bf_io;
        return EXIT_FAILURE;
    }

    OramAPI* oram_api = nullptr;
    if (md.use_oram){
        oram_api = new OramAPI(
            rss,
            random,
            config.num_blocks,
            md.num_levels,
            md.oram_cached_levels,
            config.block_size,
            config.real_bucket_size,
            config.dummy_size,
            config.evict_rate,
            md.block_map_path,
            md.metadata_path,
            md.pos_map_path,
            md.debug,
            md.large_number,
            config
        );
    }
    

    if (md.use_oram && !oram_api) {
        cerr << "Error: Failed to initialize OramAPI." << endl;
        delete random;
        delete rss;
        delete io;
        delete bf_io;
        return EXIT_FAILURE;
    }

    if (md.debug) cout << "OramAPI initialized successfully." << endl;

    DiskANNInterface diskann(config_path.c_str(), io, md.use_oram, md.debug);
    diskann.read_diskann_args(dataset);

    long comm = io->counter, rounds = io->num_rounds;
    bool ready;
    bf_io->recv_data(&ready, sizeof(bool));

    diskann.initiate_and_run_diskann(oram_api);
    
    comm = io->counter - comm;
    rounds = io->num_rounds - rounds;

    // io->send_data(&comm, sizeof(int));
    rss->close_server();

    if (md.use_oram) {
        print_communication_metrics(md.num_queries, io, comm, rounds, rss, rss->rounds_for_oram_access,rss->rounds_for_reshuffles, rss->rounds_for_evictions);
    }

    delete oram_api;
    delete random;
    delete rss;
    delete io;
    delete bf_io;

    cout << "\nClient terminated successfully." << endl;
    return EXIT_SUCCESS;
}