#include <cstdlib>
#include <iostream>
#include <string>
#include <fcntl.h>
#include <unistd.h>

using namespace std;

int main(){
  string buckets_path = "oram_data/marco/R128_L100_P64/buckets.bin";

  size_t ctx_block_size = 3616;
  size_t num_buckets = 524287;
  size_t bucket_size = 96;
	size_t metadata_size = sizeof(int) + sizeof(int) + sizeof(bool);

	int bucket_file = open(buckets_path.c_str(), O_RDWR);

  for(size_t bucket_pos = 0; bucket_pos < num_buckets; bucket_pos++){
    
    off_t offset = metadata_size + bucket_pos * ctx_block_size * bucket_size;
    if(lseek(bucket_file, offset, SEEK_SET) == -1){
      std::cerr << "Error seeking in bucket file : bucket " << bucket_pos << std::endl;
      exit(EXIT_FAILURE);
    }

    unsigned char* data = new unsigned char[bucket_size * ctx_block_size];
    ssize_t read_size = read(bucket_file, data, bucket_size * ctx_block_size);
    if(read_size != bucket_size * ctx_block_size){
      cerr << "Error reading from bucket file: offset " << bucket_pos << endl;
      exit(EXIT_FAILURE);
    }

    string small_bucket_path = "oram_data/marco/R128_L100_P64/buckets/bucket_" + std::to_string(bucket_pos) + ".bin";
	  int small_bucket_file = open(small_bucket_path.c_str(), O_WRONLY);
    ssize_t write_size = write(small_bucket_file, data, bucket_size * ctx_block_size);
    if(write_size != bucket_size * ctx_block_size){
      cerr << "Error writing to small bucket file: " << bucket_pos << endl;
      exit(EXIT_FAILURE);
    }
    close(small_bucket_file);

    cout << "\rBucket " << bucket_pos << " written" << std::flush;
  }
  close(bucket_file);
}