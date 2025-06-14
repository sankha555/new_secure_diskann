#include "config_parser.h"

// stl
#include <iostream>
#include <cassert>
#include <cstdio>
#include <fstream>


// json
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/error/en.h"



int parseJson(string config_path, Metadata &md, string dataset){
    // Open the JSON file
    ifstream file(config_path);
    if (!file.is_open()) {
        cerr << "Failed to open file." << endl;
        return 1;
    }

    // Read the entire file into a buffer
    string jsonContent;
    string line;
    while (getline(file, line)) {
        jsonContent += line + "\n";
    }
    file.close();

    // Parse the JSON content
    rapidjson::Document document;
    document.Parse(jsonContent.c_str());

    // Accessing values
    if (document.HasParseError()) {
        cerr << "Parse error: " << rapidjson::GetParseError_En(document.GetParseError()) << endl;
        return 1;
    }

    // Extracting data
    if (document.HasMember(dataset) && document[dataset].IsObject()) {
        const rapidjson::Value& val = document[dataset];

        if(val.HasMember("integrity") && val["integrity"].IsBool()){
            md.integrity = val["integrity"].GetBool();
        } else{
            cerr << "Parse error: integrity not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("real_bucket_size") && val["real_bucket_size"].IsInt()){
            md.real_bucket_size = val["real_bucket_size"].GetInt();
        } else{
            cerr << "Parse error: real_bucket_size not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("dummy_size") && val["dummy_size"].IsInt()){
            md.dummy_size = val["dummy_size"].GetInt();
        } else{
            cerr << "Parse error: dummy_size not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("evict_rate") && val["evict_rate"].IsInt()){
            md.evict_rate = val["evict_rate"].GetInt();
        } else{
            cerr << "Parse error: evict_rate not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("num_levels") && val["num_levels"].IsInt()){
            md.num_levels = val["num_levels"].GetInt();
        } else{
            cerr << "Parse error: num_levels not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("oram_cached_levels") && val["oram_cached_levels"].IsInt()){
            md.oram_cached_levels = val["oram_cached_levels"].GetInt();
        } else{
            cerr << "Parse error: oram_cached_levels not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("large_number") && val["large_number"].IsInt()){
            md.large_number = val["large_number"].GetInt();
        } else{
            cerr << "Parse error: large_number not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("use_oram") && val["use_oram"].IsBool()){
            md.use_oram = val["use_oram"].GetBool();
        } else{
            cerr << "Parse error: use_oram not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("debug") && val["debug"].IsBool()){
            md.debug = val["debug"].GetBool();
        } else{
            cerr << "Parse error: debug not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("block_size") && val["block_size"].IsInt()){
            md.block_size = val["block_size"].GetInt();
        } else{
            cerr << "Parse error: block_size not found or invalid format" << endl;
            return 1;
        } 

        if(val.HasMember("dim") && val["dim"].IsInt()){
            md.dim = val["dim"].GetInt();
        } else{
            cerr << "Parse error: dim not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("M") && val["M"].IsInt()){
            md.M = val["M"].GetInt();
        } else{
            cerr << "Parse error: M not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("base_size") && val["base_size"].IsInt()){
            md.base_size = val["base_size"].GetInt();
        } else{
            cerr << "Parse error: base_size not found or invalid format" << endl;
            return 1;
        }

        // if(val.HasMember("ef_search") && val["ef_search"].IsInt()){
        //     md.ef_search = val["ef_search"].GetInt();
        // } else{
        //     cerr << "Parse error: ef_search not found or invalid format" << endl;
        //     return 1;
        // }

        if(val.HasMember("-L") && val["-L"].IsInt()){
            md.ef_spec = val["-L"].GetInt();
        } else{
            cerr << "Parse error: L not found or invalid format" << endl;
            return 1;
        }

        // if(val.HasMember("ef_spec") && val["ef_spec"].IsInt()){
        //     md.ef_spec = val["ef_spec"].GetInt();
        // } else{
        //     cerr << "Parse error: ef_spec not found or invalid format" << endl;
        //     return 1;
        // }

        // if(val.HasMember("ef_neighbor") && val["ef_neighbor"].IsInt()){
        //     md.ef_neighbor = val["ef_neighbor"].GetInt();
        // } else{
        //     cerr << "Parse error: ef_neighbor not found or invalid format" << endl;
        //     return 1;
        // }

        // if(val.HasMember("ef_lowest_cached_layer") && val["ef_lowest_cached_layer"].IsInt()){
        //     md.ef_lowest_cached_layer = val["ef_lowest_cached_layer"].GetInt();
        // } else{
        //     cerr << "Parse error: ef_lowest_cached_layer not found or invalid format" << endl;
        //     return 1;
        // }

        // if(val.HasMember("ef_upper_steps") && val["ef_upper_steps"].IsInt()){
        //     md.ef_upper_steps = val["ef_upper_steps"].GetInt();
        // } else{
        //     cerr << "Parse error: ef_upper_steps not found or invalid format" << endl;
        //     return 1;
        // }

        // if(val.HasMember("index_path") && val["index_path"].IsString()){
        //     md.index_path = val["index_path"].GetString();
        // } else{
        //     cerr << "Parse error: index_path not found or invalid format" << endl;
        //     return 1;
        // }

        // if(val.HasMember("pq_path") && val["pq_path"].IsString()){
        //     md.pq_path = val["pq_path"].GetString();
        // } else{
        //     cerr << "Parse error: pq_path not found or invalid format" << endl;
        //     return 1;
        // } 

        if(val.HasMember("base_path") && val["base_path"].IsString()){
            md.base_path = val["base_path"].GetString();
        } else{
            cerr << "Parse error: base_path not found or invalid format" << endl;
            return 1;
        }

        // if(val.HasMember("query_path") && val["query_path"].IsString()){
        //     md.query_path = val["query_path"].GetString();
        // } else{
        //     cerr << "Parse error: query_path not found or invalid format" << endl;
        //     return 1;
        // }

        // if(val.HasMember("gt_path") && val["gt_path"].IsString()){
        //     md.gt_path = val["gt_path"].GetString();
        // } else{
        //     cerr << "Parse error: gt_path not found or invalid format" << endl;
        //     return 1;
        // }

        if(val.HasMember("buckets_path") && val["buckets_path"].IsString()){
            md.buckets_path = val["buckets_path"].GetString();
        } else{
            cerr << "Parse error: buckets_path not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("pos_map_path") && val["pos_map_path"].IsString()){
            md.pos_map_path = val["pos_map_path"].GetString();
        } else{
            cerr << "Parse error: pos_map_path not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("block_map_path") && val["block_map_path"].IsString()){
            md.block_map_path = val["block_map_path"].GetString();
        } else{
            cerr << "Parse error: block_map_path not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("metadata_path") && val["metadata_path"].IsString()){
            md.metadata_path = val["metadata_path"].GetString();
        } else{
            cerr << "Parse error: metadata_path not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("graph_cache_path") && val["graph_cache_path"].IsString()){
            md.graph_cache_path = val["graph_cache_path"].GetString();
        } else{
            cerr << "Parse error: graph_cache_path not found or invalid format" << endl;
            return 1;
        }

        if(val.HasMember("hash_path") && val["hash_path"].IsString()){
            md.hash_path = val["hash_path"].GetString();
        } else{
            cerr << "Parse error: hash_path not found or invalid format" << endl;
            return 1;
        }

        
        if(val.HasMember("--query_nums") && val["--query_nums"].IsInt64()){
            md.num_queries = val["--query_nums"].GetInt64();
        } else{
            cerr << "Parse error: --query_nums not found or invalid format" << endl;
            return 1;
        }
    }

    return 0;

}