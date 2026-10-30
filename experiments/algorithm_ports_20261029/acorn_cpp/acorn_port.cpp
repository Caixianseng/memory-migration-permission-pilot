// Thin adapter for fixed author ACORN commit c259f11..., not a graph reimplementation.
#include <faiss/IndexACORN.h>
#include <faiss/IndexHNSW.h>
#include <faiss/IndexFlat.h>
#include <faiss/utils/random.h>
#include <nlohmann/json.hpp>
#include <omp.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using json = nlohmann::json;
using Id = faiss::idx_t;
using Clock = std::chrono::steady_clock;
static const int SEED = 20261029;
static const int EF_CONSTRUCTION = 80;
static const int EF_SEARCH = 256;
static const int REPS = 3;

static double ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b-a).count();
}
template<class T> static size_t capbytes(const std::vector<T>& v) {
    return v.capacity() * sizeof(T);
}
template<class G> static size_t graphbytes(const G& g) {
    return capbytes(g.assign_probas) + capbytes(g.cum_nneighbor_per_level) +
        capbytes(g.levels) + capbytes(g.offsets) + capbytes(g.neighbors);
}

struct Result {
    std::vector<Id> ids;
    std::vector<float> distances;
    int rounds = 0;
    int final_candidates = 0;
    explicit Result(int k) : ids(k, -1), distances(k, std::numeric_limits<float>::infinity()) {}
};

static float distance(const float* a, const float* b, int d) {
    float total = 0.0f;
    for(int i=0;i<d;i++) { float z=a[i]-b[i]; total += z*z; }
    return total;
}

static json timed(const std::function<Result()>& run, const std::vector<char>& mask, int n, int k) {
    run(); // exactly one declared warmup
    std::vector<double> times;
    std::vector<std::vector<Id>> replicate_ids;
    Result last(k);
    for(int rep=0; rep<REPS; rep++) {
        auto a=Clock::now();
        last=run();
        auto b=Clock::now();
        times.push_back(ms(a,b));
        replicate_ids.push_back(last.ids);
    }
    json ids=json::array(), distances=json::array();
    int illegal=0, padding=0, duplicates=0;
    std::set<Id> seen;
    for(int i=0;i<k;i++) {
        Id id=last.ids[i];
        if(id < -1 || id >= n) throw std::runtime_error("native result ID out of range");
        ids.push_back(id);
        if(id==-1) { distances.push_back(nullptr); padding++; }
        else {
            if(!mask[static_cast<size_t>(id)]) illegal++;
            if(!seen.insert(id).second) duplicates++;
            distances.push_back(last.distances[i]);
        }
    }
    auto sorted=times;std::sort(sorted.begin(),sorted.end());
    bool stable=true;
    for(const auto& x:replicate_ids) if(x!=replicate_ids.front()) stable=false;
    return json{{"ids",ids},{"distances",distances},{"latency_ms",sorted[1]},
        {"latency_repetitions_ms",times},{"replicate_ids_stable",stable},
        {"illegal_result_count",illegal},{"padding_count",padding},
        {"duplicate_id_count",duplicates},{"search_rounds",last.rounds},
        {"final_candidates",last.final_candidates}};
}

static std::vector<float> matrix(const json& value, int* rows, int* columns) {
    if(!value.is_array() || value.empty()) throw std::runtime_error("nonempty numeric matrix required");
    *rows=static_cast<int>(value.size());
    if(!value[0].is_array() || value[0].empty()) throw std::runtime_error("nonempty matrix row required");
    *columns=static_cast<int>(value[0].size());
    if(*rows>20000 || *columns>4096) throw std::runtime_error("adapter shape cap exceeded");
    std::vector<float> out;
    out.reserve(static_cast<size_t>(*rows)*(*columns));
    for(const auto& row:value) {
        if(!row.is_array() || row.size()!=static_cast<size_t>(*columns)) throw std::runtime_error("ragged matrix");
        for(const auto& x:row) {
            if(!x.is_number()) throw std::runtime_error("numeric vectors required");
            float v=x.get<float>();
            if(!std::isfinite(v)) throw std::runtime_error("finite float32 required");
            out.push_back(v);
        }
    }
    return out;
}

static json execute(const json& input) {
    int n,d,nq,qd;
    auto xb=matrix(input.at("vectors"),&n,&d);
    auto queries=matrix(input.at("queries"),&nq,&qd);
    if(n<2 || qd!=d) throw std::runtime_error("N>=2 and matching query dimension required");
    if(!input.at("k").is_number_integer()) throw std::runtime_error("integer k required");
    const int k=input.at("k").get<int>();
    if(k<=0 || k>n) throw std::runtime_error("1<=k<=N required");
    const auto& masks_json=input.at("masks");
    if(!masks_json.is_array() || masks_json.size()!=static_cast<size_t>(nq)) throw std::runtime_error("one mask per query required");
    std::vector<std::vector<char>> masks;
    for(const auto& row:masks_json) {
        if(!row.is_array() || row.size()!=static_cast<size_t>(n)) throw std::runtime_error("mask length must equal N");
        std::vector<char> mask;
        for(const auto& value:row) {
            if(value.is_boolean()) mask.push_back(value.get<bool>()?1:0);
            else if(value.is_number_integer() && (value.get<int>()==0 || value.get<int>()==1)) mask.push_back(value.get<int>());
            else throw std::runtime_error("mask entries must be boolean or integer0/1");
        }
        masks.push_back(mask);
    }
    omp_set_num_threads(1);
    const int M=std::max(2,std::min(16,n-1));
    std::vector<int> metadata(n,0); // required author constructor input, not authorization
    auto start=Clock::now();
    std::unique_ptr<faiss::IndexACORNFlat> acorn(new faiss::IndexACORNFlat(d,M,1,metadata,2*M,faiss::METRIC_L2));
    acorn->acorn.efConstruction=EF_CONSTRUCTION;
    acorn->acorn.efSearch=EF_SEARCH;
    acorn->acorn.rng=faiss::RandomGenerator(SEED);
    acorn->add(n,xb.data());
    auto built_acorn=Clock::now();
    std::unique_ptr<faiss::IndexHNSWFlat> hnsw(new faiss::IndexHNSWFlat(d,M,faiss::METRIC_L2));
    hnsw->hnsw.efConstruction=EF_CONSTRUCTION;
    hnsw->hnsw.efSearch=EF_SEARCH;
    hnsw->hnsw.rng=faiss::RandomGenerator(SEED);
    hnsw->add(n,xb.data());
    auto built_hnsw=Clock::now();
    json out{{"schema","fixed_author_acorn_adapter_v1"},{"source_commit","c259f11cdbec880671658eaa0d8747e2cc9de79d"}};
    out["acorn"]=json::array();out["hnsw_post"]=json::array();out["hnsw_adaptive"]=json::array();out["exact"]=json::array();
    const size_t acorn_bytes=graphbytes(acorn->acorn)+acorn->storage->ntotal*d*sizeof(float)+capbytes(metadata);
    const size_t hnsw_bytes=graphbytes(hnsw->hnsw)+hnsw->storage->ntotal*d*sizeof(float);
    out["metadata"]={{"n",n},{"dimension",d},{"queries",nq},{"k",k},{"M",M},{"gamma",1},{"M_beta",2*M},
        {"efConstruction",EF_CONSTRUCTION},{"efSearch",EF_SEARCH},{"threads",1},{"seed",SEED},
        {"hnsw_start_candidates",std::min(n,16*k)},{"warmup",1},{"timing_repetitions",REPS},
        {"acorn_build_ms",ms(start,built_acorn)},{"hnsw_build_ms",ms(built_acorn,built_hnsw)},
        {"acorn_tracked_index_bytes",acorn_bytes},{"hnsw_tracked_index_bytes",hnsw_bytes},
        {"input_vector_bytes",xb.size()*sizeof(float)},
        {"index_bytes_scope","payload plus selected vector backing capacities and ACORN required metadata; not RSS or serialized size"}};
    for(int qi=0;qi<nq;qi++) {
        const float* q=queries.data()+static_cast<size_t>(qi)*d;
        const auto& mask=masks[qi];
        int allowed=std::count(mask.begin(),mask.end(),char(1));
        auto acorn_run=[&](){
            Result r(k);
            if(allowed) {
                // Preserve native IDs, including illegal IDs, for host rejection/audit.
                acorn->search(1,q,k,r.distances.data(),r.ids.data(),const_cast<char*>(mask.data()));
                r.rounds=1;
            }
            return r;
        };
        auto post_run=[&](bool adaptive){
            Result r(k);
            if(!allowed) return r;
            int candidates=std::min(n,16*k);
            while(true) {
                std::vector<Id> ids(candidates,-1);
                std::vector<float> ds(candidates,std::numeric_limits<float>::infinity());
                hnsw->search(1,q,candidates,ds.data(),ids.data());
                r.rounds++;r.final_candidates=candidates;
                std::fill(r.ids.begin(),r.ids.end(),Id(-1));
                std::fill(r.distances.begin(),r.distances.end(),std::numeric_limits<float>::infinity());
                int kept=0;
                for(int j=0;j<candidates && kept<k;j++) {
                    Id id=ids[j];
                    if(id < -1 || id>=n) throw std::runtime_error("HNSW result ID out of range");
                    if(id>=0 && mask[static_cast<size_t>(id)]) {r.ids[kept]=id;r.distances[kept]=ds[j];kept++;}
                }
                if(!adaptive || kept>=k || candidates==n) return r;
                candidates=std::min(n,candidates*2);
            }
        };
        auto exact_run=[&](){
            Result r(k);
            std::vector<std::pair<float,Id>> ranked;
            for(int i=0;i<n;i++) if(mask[i]) ranked.emplace_back(distance(q,xb.data()+static_cast<size_t>(i)*d,d),i);
            int count=std::min(k,static_cast<int>(ranked.size()));
            std::partial_sort(ranked.begin(),ranked.begin()+count,ranked.end());
            for(int j=0;j<count;j++) {r.ids[j]=ranked[j].second;r.distances[j]=ranked[j].first;}
            r.rounds=allowed?1:0;r.final_candidates=allowed;
            return r;
        };
        out["acorn"].push_back(timed(acorn_run,mask,n,k));
        out["hnsw_post"].push_back(timed([&](){return post_run(false);},mask,n,k));
        out["hnsw_adaptive"].push_back(timed([&](){return post_run(true);},mask,n,k));
        out["exact"].push_back(timed(exact_run,mask,n,k));
    }
    return out;
}

int main(int argc,char** argv) {
    std::string input_path,output_path;
    for(int i=1;i<argc;i++) {
        std::string a=argv[i];
        if(a=="--input" && i+1<argc) input_path=argv[++i];
        else if(a=="--output" && i+1<argc) output_path=argv[++i];
        else {std::cerr<<"usage: acorn_port.exe --input INPUT.json --output OUTPUT.json\n";return 2;}
    }
    if(input_path.empty() || output_path.empty()) return 2;
    try {
        std::ifstream in(input_path);
        if(!in) throw std::runtime_error("cannot open input JSON");
        json input;in>>input;
        auto result=execute(input);
        std::ofstream out(output_path);
        if(!out) throw std::runtime_error("cannot open output JSON");
        out<<result.dump(2)<<"\n";
        return 0;
    } catch(const std::exception& e) {
        std::ofstream out(output_path);
        if(out) out<<json{{"error",e.what()},{"stage","author_adapter"}}.dump(2)<<"\n";
        std::cerr<<e.what()<<"\n";return 3;
    }
}
