#include <cstdlib>
#include <iostream>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <chrono>


using namespace std;

int main(){
    string bucket_path = "oram_data/marco/R128_L100_PQ64/buckets.bin";

    int bw = 48;
    int iter = 6;
    int path_len = 13;
    size_t read_size = 3616;

    srand ( time(NULL) );

    int fd = open(bucket_path.c_str(), O_RDONLY);

	auto start_read = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < iter; i++){
        for(int t = 0; t < bw; t++){
            for(int j = 0; j < path_len; j++){
                off_t offset = rand() % 50331552;
                cout << "Seek to " << offset << "\n";
                lseek(fd, offset, SEEK_SET);

                unsigned char* data = new unsigned char[read_size];
                size_t read_bytes = read(fd, data, read_size);
                if(read_bytes != read_size){
                    cout << "Did not read entire bucket\n";
                    exit(0);
                }
            }
        }
    }
	auto end_read = std::chrono::high_resolution_clock::now();

    cout << "Read duration: " << (end_read - start_read).count()*1.0/(1e9) << "\n";

    return 0;
}