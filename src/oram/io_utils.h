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
#include <map>
#include <fstream>
#include <sys/time.h>
#include <sys/stat.h>
#include "net_io_channel.h"

#include "tableprinter.h"
#include "RemoteRing.h"

float* fvecs_read(const char* fname, size_t* d_out, size_t* n_out) {
    FILE* f = fopen(fname, "r");
    if (!f) {
        fprintf(stderr, "could not open %s\n", fname);
        perror("");
        abort();
    }
    int d;
    fread(&d, 1, sizeof(int), f);
    assert((d > 0 && d < 1000000) || !"unreasonable dimension");
    fseek(f, 0, SEEK_SET);
    struct stat st;
    fstat(fileno(f), &st);
    size_t sz = st.st_size;
    assert(sz % ((d + 1) * 4) == 0 || !"weird file size");
    size_t n = sz / ((d + 1) * 4);

    *d_out = d;
    *n_out = n;
    float* x = new float[n * (d + 1)];
    size_t nr = fread(x, sizeof(float), n * (d + 1), f);
    assert(nr == n * (d + 1) || !"could not read whole file");

    // shift array to remove row headers
    for (size_t i = 0; i < n; i++)
        memmove(x + i * d, x + 1 + i * (d + 1), d * sizeof(*x));

    fclose(f);
    return x;
}

// not very clean, but works as long as sizeof(int) == sizeof(float)
int* ivecs_read(const char* fname, size_t* d_out, size_t* n_out) {
    return (int*)fvecs_read(fname, d_out, n_out);
}

void fvecs_write(const char* fname, float* data, size_t d, size_t n) {
    FILE* f = fopen(fname, "w");
    if (!f) {
        fprintf(stderr, "could not open %s\n", fname);
        perror("");
        abort();
    }
    for (size_t i = 0; i < n; i++){
        fwrite(&d, 1, sizeof(int), f);
        fwrite(data + i*d, d, sizeof(float), f);
    }
    fclose(f);
}

void ivecs_write(const char* fname, int* data, size_t d, size_t n) {
    fvecs_write(fname, (float*)data, d, n);
}

void print_communication_metrics(NetIO* io, long c2s_comm, long c2s_round, RemoteRing* rss, int oram_rounds, int reshuffle_rounds, int eviction_rounds) {
    long s2c_comm, s2c_round;
    io->recv_data(&s2c_comm, sizeof(long));
    io->recv_data(&s2c_round, sizeof(long));

    std::cout << std::endl;
    std::cout << "Total communication: " << (c2s_comm + s2c_comm)*1.0/(1024*1024) << " MB" << std::endl;
    std::cout << "---> Client-to-Server: " << c2s_comm*1.0/(1024*1024) << " MB" << std::endl;
    std::cout << "---> Server-to-Client: " << s2c_comm*1.0/(1024*1024) << " MB" << std::endl;
    std::cout << "---> Oram Access: " << (rss->comm_for_oram_access + rss->server_comm_for_oram_access)*1.0/(1024*1024) << " MB" << std::endl;
    std::cout << "---> Reshuffling: " << (rss->comm_for_reshuffles + rss->server_comm_for_reshuffles)*1.0/(1024*1024) << " MB" << std::endl;
    std::cout << "---> Evictions: " << (rss->comm_for_evictions + rss->server_comm_for_evictions)*1.0/(1024*1024) << " MB" << std::endl;

    // oram_rounds = oram_rounds/2;
    // reshuffle_rounds = (reshuffle_rounds/3)*2;
    // eviction_rounds = (eviction_rounds/3)*2;
    c2s_round = oram_rounds + reshuffle_rounds + eviction_rounds;

    std::cout << "\nTotal rounds: " << c2s_round << " rounds" << std::endl;
    std::cout << "---> Oram Access: " << oram_rounds << " rounds" << std::endl;
    std::cout << "---> Reshuffling: " << (reshuffle_rounds) << " rounds" << std::endl;
    std::cout << "---> Eviction: " << (eviction_rounds) << " rounds" << std::endl;

}


void print_search_results(vector<double> data, bool only_headers){
    using namespace tableprinter;
    printer p{
        {
            { name { "Queue Size | " }      , width { 16 } , tableprinter::fixed { } , tableprinter::precision { 0 } } ,
            { name { "Beamwidth | " }    , width { 16 } , tableprinter::fixed { } , tableprinter::precision { 0 }} ,
            { name { "Num Queries | " } , width { 16 } , tableprinter::fixed { } , tableprinter::precision { 0 }} ,
            { name { "Recall@10 | " }    , width { 16 } , tableprinter::fixed { } , tableprinter::precision { 2 } } ,
            { name { "MRR@10 | " }   , width { 16 } , tableprinter::fixed { } , tableprinter::precision { 2 } } ,
            { name { "Iterations | "} , width {16} , tableprinter::fixed { } , tableprinter::precision { 2 } } ,
            { name { "Hops | " } , width {16} , tableprinter::fixed { } , tableprinter::precision { 2 } } ,
            { name { "Comm. (MB) | " } , width {16} , tableprinter::fixed { } , tableprinter::precision { 2 } },
            { name { "Rounds | " } , width {16} , tableprinter::fixed { } , tableprinter::precision { 2 } },
            { name { "E2E Time (s) | " } , width {16} , tableprinter::fixed { } , tableprinter::precision { 2 } },
            { name { "User Time (s) | " } , width {16} , tableprinter::fixed { } , tableprinter::precision { 2 } },
            { name { "Comm. Time (s) | " } , width {16} , tableprinter::fixed { } , tableprinter::precision { 2 } },
        },

        {std::cout}
    };

    if (only_headers) {
        cout << "===================================================================================================================================================================================" << endl;
        p.sanity_check().print_headers();
        cout << "===================================================================================================================================================================================" << endl;
    }

    auto to_string_custom =  [](double value, int precision) {
        std::ostringstream out;
        out << std::fixed << std::setprecision(precision) << value;
        return out.str();
    };
    
    if (!only_headers) {
        const size_t len = data.size();
        vector<string> str_data(len);
        std::setprecision(2);
        for(int i = 0; i < len; i++){
            str_data[i] = to_string_custom(data[i], 2) + " | ";
        }

        p.print(str_data[0], str_data[1], str_data[2], str_data[3], str_data[4], str_data[5], str_data[6], str_data[7], str_data[8], str_data[9], str_data[10], str_data[11]);
    }    

    cout << endl;

}