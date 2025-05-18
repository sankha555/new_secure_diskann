//
//
//

#ifndef PORAM_REMOTESERVER_H
#define PORAM_REMOTESERVER_H
// #include "OramInterface.h"
// #include "RandForOramInterface.h"
// #include "UntrustedStorageInterface.h"
#include "Bucket.h"
#include "net_io_channel.h"
#include <cmath>
#include <sstream>
#include <map>


class RemoteServer  {
public:

    // IO
    NetIO* io;

    // Integrity
    bool integrity;
    std::vector<uint8_t> root;

    bool in_memory;
    // If the Remote server put everything in memory
    std::vector<SBucket*> buckets;
    // If NOT
    char* buckets_fname;
    int fd;
    unsigned char* mmap_data; // mmap data & file size
    size_t mmap_size;
    unsigned char* mmap_bkts; 

    RemoteServer(NetIO* io, int capacity, bool in_memory, bool integrity);

    // Insecure Family
    // uint8_t* root;
    // void insecureLoad(vector<Bucket>& input_bkts);
    // void insecureLoadPtr(int* bkts);
    // void sync_root();


    void RunServer();
    void sync_root();

    void load(const char* fname);
    
private: 
    int capacity;
    void RunServerInMemory();
    void RunServerInDisk();
    void RunServerInDiskRing();

    void fileMap();
    void fileUnMap();

};


#endif //PORAM_REMOTESERVER_H
