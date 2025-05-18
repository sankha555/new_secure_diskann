#include "node.h"

template<>
DiskANNNode<float, int>* BlockFetcher<float, int>::get_block(node_id_t node_id){
    assert(0);
    return NULL;
}

template<>
vector<DiskANNNode<float, int>> BlockFetcher<float, int>::get_blocks(vector<node_id_t> node_ids, int pad_l){
    assert(0);
    return {};
}

