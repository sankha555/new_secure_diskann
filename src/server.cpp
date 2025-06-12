#include "defaults.h"
#include "ArgMapping.h"
#include "net_io_channel.h"
#include "evp.h"

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
#include "io_utils.h"

// oram
#include "macro.h"
#include "OramAPI.h"
#include "config_parser.h"

int party = SERVER_PARTY;
int port = SERVER_PORT;
string address = SERVER_IP;
string dataset = "";
string config_path;

using namespace std;

void setup_connection(int port, string address, NetIO*& io, NetIO*& bf_io) {
    io = new NetIO(nullptr, port, false, true);
    if (!io) {
        cerr << "Error: Failed to initialize NetIO for main connection." << endl;
        exit(EXIT_FAILURE);
    }

    bf_io = new NetIO(nullptr, port + 1, false, true);
    if (!bf_io) {
        cerr << "Error: Failed to initialize NetIO for backup connection." << endl;
        delete io;
        exit(EXIT_FAILURE);
    }

    cout << "\nNetwork connection established with client at " << address << endl;
}

int main(int argc, char** argv) {
    cout << "Starting server..." << endl;

    ArgMapping amap;
    amap.arg("p", port, "Port Number");
    amap.arg("d", dataset, "Dataset: [sift, trip, msmarco, laion]");
    amap.arg("ip", address, "IP Address of server");
    amap.arg("c", config_path, "Path to config file");
    amap.parse(argc, argv);

    Metadata md;
    config_path = config_path.size() == 0 ?  (CONFIG_DIR) + "config_" + dataset + ".json" : config_path;
    if (parseJson(config_path, md, dataset) != 0) {
        cerr << "Error: Failed to parse JSON configuration." << endl;
        return EXIT_FAILURE;
    }

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

    RandForOramInterface* random = new RandomForOram();
    if (!random) {
        cerr << "Error: Failed to initialize RandomForOram." << endl;
        delete io;
        delete bf_io;
        return EXIT_FAILURE;
    }

    bool in_memory = true;

    if(!md.use_oram){
        bool ready = true;
        bf_io->send_data(&ready, sizeof(bool));
        cout << "Starting remote server... \n";

        // int close;
        // bf_io->recv_data(&close, sizeof(int));
        cout << "\nServer terminated successfully." << endl;

        return 0;
    }

    RemoteRing server = RemoteRing(io, config, true, in_memory, md.integrity);
    try {
        if(md.use_oram){
            server.load_server_state(md.buckets_path.c_str());
        }
    } catch (const std::exception& e) {
        cerr << "Error: Failed to load server buckets. Exception: " << e.what() << endl;
        delete random;
        delete io;
        delete bf_io;
        return EXIT_FAILURE;
    }

    if (md.debug) cout << "Server buckets loaded successfully." << endl;

    bool ready = true;
    try {
        bf_io->send_data(&ready, sizeof(bool));
    } catch (const std::exception& e) {
        cerr << "Error: Failed to send ready signal. Exception: " << e.what() << endl;
        delete random;
        delete io;
        delete bf_io;
        return EXIT_FAILURE;
    }

    
    if(md.use_oram){
        long long* dummy_data = new long long[1000000]; 
        long comm = io->counter;
        for(int i = 0; i < 500; i++){
            io->recv_data(dummy_data, 1000000 * sizeof(long long));
            cout << "\rDummy " << i+1 << " sent: " << (io->counter - comm)*1.0/(1024*1024) << " MB"  << std::flush;
        }
        cout << "\n";
        io->counter = comm;   
    }

    double t0 = elapsed();
    tprint("Starting remote server... \n", t0);

    long comm = io->counter, round = io->num_rounds;

    try {
        server.start_comm = comm;
        server.start_rounds = round;
        server.run_server();
    } catch (const std::exception& e) {
        cerr << "Error: Exception occurred while running the server. Exception: " << e.what() << endl;
    }

    comm = io->counter - comm;
    round = io->num_rounds - round;

    io->send_data(&comm, sizeof(long));
    io->send_data(&round, sizeof(long));

    delete random;
    delete io;
    delete bf_io;

    cout << "\nServer terminated successfully." << endl;
    return EXIT_SUCCESS;
}
