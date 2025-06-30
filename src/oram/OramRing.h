//
//
//

#ifndef PORAM_OramRing_H
#define PORAM_OramRing_H
#include "OramInterface.h"
#include "RandForOramInterface.h"
// #include "UntrustedStorageInterface.h"
// #include "RemoteServerStorage.h"
#include "RemoteRing.h"
#include <cmath>
#include <map>
#include <set>
#include <bitset>
#include <cassert>

class OramMetaData {
public:
    uint8_t count;
    bitset<128> valids;
    vector<int> block_ids; // positive for

    // OramMetaData();

    int GetBlockOffset(int block_id, bool& real); 
    int GetBlockOffsetLeak(int block_id, bool& real); 
    void print_stat(); 
    // int ShuffleAndReset();
};

class OramRing : public OramInterface {
public:
    RemoteRing* storage;
    RandForOramInterface* rand_gen;
    int G;

    int block_size;
    int real_bucket_size;
    int dummy_size;
    int bucket_size;
    int evict_rate;

    int num_levels;
    int num_leaves;
    int num_blocks;
    int num_buckets;

    int cnt_delayed_leaves;

    bool cache_top;
    int num_cached_levels;
    int num_cached_bucket;
    map<int, Block*> cached_oram;
    int cnt_early_reshuffle;
    int cnt_q;

    bool batching;
    bool lazy_eveiction;
    int num_reshuffles = 0;

    vector<int> position_map; //array
    vector<OramMetaData> metadata;

    // vector<Block> stash;
    map<int, Block> mstash;

    map<std::pair<int, int>, Block*, PairComparator> mmstash;

    OramRing(RemoteRing* storage,
            RandForOramInterface* rand_gen, RingOramConfig config, int num_levels, int cached_levels, bool batch = true, bool lazy = true);

    void evict_and_write_back();

    void init_cache_top();

    std::vector<int*> access(std::vector<Operation> ops, std::vector<int> blockIndices, std::vector<int*> newdata, int pad_l);

    std::vector<int*> batch_multi_access_swap_ro(std::vector<Operation> ops, std::vector<int> blockIndices, std::vector<int*> newdata, int pad_l);

    template<typename T>
    std::vector<T*> batch_multi_access_swap_ro_templated(std::vector<Operation> ops, std::vector<int> blockIndices, std::vector<T*> newdata , int pad_l){

        // cout << "Entering bmasr" << endl;
        int len = ops.size();
        std::vector<T*> ret;
        {
            vector<int> leaves;
            vector<int> positions;
            vector<int> block_ids; // only for reshuflle

            bool reshuffle = false;
            set<int> reshuffle_buckets;

            for(int block_id : blockIndices){
                int oldLeaf = position_map[block_id];
                bool found = false;

                for (int l = num_levels - 1; l >= num_cached_levels; l--) {
                    int pos = P(oldLeaf, l);
                    // check metadata and increase count
                    this->metadata[pos].count++;

                    if(this->metadata[pos].count >= dummy_size){
                        cnt_early_reshuffle += 1;
                        reshuffle = true;
                        reshuffle_buckets.insert(pos);
                    }

                    block_ids.push_back(block_id);
                    positions.push_back(pos);
                }

                leaves.push_back(oldLeaf);
                // cout << oldLeaf << " ";
            }
            // cout << "\n";

            for(int i = leaves.size(); i < pad_l; i++){
                int newLeaf = rand_gen->getRandomLeafWithBound(num_leaves);

                for (int l = num_levels - 1; l >= num_cached_levels; l--) {
                    int pos = P(newLeaf, l);

                    // check metadata and increase count
                    this->metadata[pos].count++;

                    if(this->metadata[pos].count >= dummy_size){
                        cnt_early_reshuffle += 1;
                        reshuffle = true;
                        reshuffle_buckets.insert(pos);
                    }
                    block_ids.push_back(-1);
                    positions.push_back(pos);
                }
            }

            // Reshuffle 
            // Re-generate the offsets for shuffled buckets
            // long comm = ((RemoteServerStorage*)storage)->io->counter;
            if(reshuffle){
                // num_reshuffles++;
                // cout << "Early reshuffle " << reshuffle_buckets.size() << " buckets." << endl;
                early_reshuffle(vector<int>(reshuffle_buckets.begin(), reshuffle_buckets.end()));
            }
            // cout << "Comm for reshuffle = " << ((RemoteServerStorage*)storage)->io->counter - comm << endl;

            vector<int> offsets;
            vector<bool> valids;
            for(int i = 0; i < positions.size(); i++){
                int pos = positions[i];
                bool real = false;
                int offset = metadata[pos].GetBlockOffset(block_ids[i], real);
                offsets.push_back(offset);
                if(block_ids[i] != -1){
                    valids.push_back(real);
                } else{
                    valids.push_back(false);
                }
                if(reshuffle && reshuffle_buckets.find(pos) != reshuffle_buckets.end()){
                    // update the count if this bucket is reshuffled
                    metadata[pos].count++;
                    if(metadata[pos].count >= dummy_size){
                        // this should not happen statistically
                        assert(0);
                    }
                }
            }

            // revisit valids incase of cache miss
            // base on the assumption that all ctx of dummies are the same
            // Fix this later...
            int interval  = num_levels - num_cached_levels;
            assert(valids.size() == interval * pad_l);
            for(int i = 0; i < pad_l; i++){
                bool found = false;
                for (int j = 0;j < interval; j++) {
                    found = found || valids[i*interval + j];
                }
                if(!found){
                    valids[i*interval] = true;
                }
            }

            // update the metadata
            // for(int i = 0; i < positions.size(); i++){
            //     int pos = positions[i];
            //     int offset = offsets[i];
            //     metadata[pos] 
            // }

            // cout << "positions and offsets generated" << endl;

            cnt_delayed_leaves += pad_l;

            // cout << "cnt_delayed_leaves: " << cnt_delayed_leaves << endl;

            // cout << "Num positions = " << positions.size() << ", Num offsets = " << offsets.size() << ", Num valids = " << valids.size() << endl;

            // Batch read
            std::vector<Block*> blocks;
            // auto t_0 = std::chrono::high_resolution_clock::now();
            ((RemoteRing*)storage)->ReadBlockBatchAsBlockRingXor(positions, offsets, blocks, pad_l, valids);
            // cout << "saving data" << endl;

            for(Block* b : blocks){
                int idx = b->index;
                // cout << "saving data: " << idx << endl;
                if (idx != -1) {
                    // cout << "Got: " << b->index << endl;
                    auto it = mmstash.find(make_pair(position_map[idx], idx));
                    mmstash[make_pair(position_map[idx], idx)] = b;
                } else{
                    // free dummy blocks
                    // avoid memory leaks
                    delete b;
                }
            }
            

            // cout << "saving data done" << endl;
        }
        
        // Read request data from stash
        for(int i = 0; i < len; i++){
            int blockIndex = blockIndices[i];
            int oldLeaf = position_map[blockIndex];
            int newLeaf = rand_gen->getRandomLeafWithBound(num_leaves);
            position_map[blockIndex] = newLeaf;
            Operation op = ops[i];
            T *data = new T[block_size];

            // cout << "Read index: " << blockIndex << " oldleaf: " << oldLeaf << " newLeaf: " << newLeaf << endl;

            auto it = mmstash.find(make_pair(oldLeaf, blockIndex));
            if(it != mmstash.end()){

                // Only support READ for now
                assert(op == Operation::READ);
                for(int i = 0; i < block_size; i++){
                    data[i] = (T) it->second->data[i];
                }
                ret.push_back(data);

                Block* b_tmp = it->second;
                mmstash.erase(it);

                // Assign this block to a new position
                mmstash[make_pair(newLeaf, blockIndex)] = b_tmp;
            } else{
                // This shouldn't happen
                cout << "missing block id: " << blockIndex << endl;
                assert(0);
            }
        } 

        return ret;
    }

    int globalG();
    int ReverseBits(int G, int bits_length);

    void early_reshuffle(vector<int> buckets);

    std::pair<int, int> Q(int leaf, int level);
    int P(int leaf, int level);
    int* getPositionMap();
    void loadPositionMap(std::vector<int>& pmap);
    void loadPositionMapFromFile(const char* fname);
    void loadMetaDataFromFile(const char* fname);
    vector<Block> getStash();
    int getStashSize();
    int getNumLeaves();
    int getNumLevels();
    int getNumBlocks();
    int getNumBuckets();

};


#endif 
