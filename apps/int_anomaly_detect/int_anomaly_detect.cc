#include "util/latency.h"
#include <gflags/gflags.h>
#include <signal.h>
#include <cstring>
#include "../apps_common.h"
#include "rpc.h"
#include "util/autorun_helpers.h"
#include "util/numautils.h"
//#include "util/pmem.h"

//#include <cut_split.h>
//#include <tuple_merge.h>

// #define USE_PMEM false

// #if USE_PMEM == true
// #include <libpmem.h>
// #endif

struct int_path_latency_report_t {
  // Set by tofino
  uint64_t egr_ts; // switch sends req
  uint64_t ingress_mac_tstamp; // switch receives resp

  // nanoPU word 1
  uint32_t src_ip;
  uint32_t dst_ip;

  // nanoPU word 2
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t proto;

  // nanoPU word 3
  uint8_t unused[3];
  uint8_t flow_flags;

  // nanoPU word 4
  uint64_t num_hops;

  // Actual hop latencies and the nic timestamp field are excluded from the eRPC message struct
  // Hop latencies will be sent on the wire immediately following the struct
  // The terminating nic timestamp is replaced by the tofino timestamps at the beginning of the message
} __attribute__((packed));

struct path_latency_anomaly_event_t {
  // Set by tofino
  uint64_t egr_ts; // switch sends req
  uint64_t ingress_mac_tstamp; // switch receives resp

  // nanoPU word 1
  uint64_t msg_id;

  // nanoPU word 2
  uint32_t src_ip;
  uint32_t dst_ip;

  // nanoPU word 3
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t proto;

  // nanoPU word 4
  uint64_t path_latency;

  uint64_t anomaly_timestamp;
} __attribute__((packed));

struct done_message_t {
  // Set by tofino
  uint64_t egr_ts; // switch sends req
  uint64_t ingress_mac_tstamp; // switch receives resp

  // nanoPU word 1
  uint64_t msg_id;

  // nanoPU word 2
  uint64_t start_time;
} __attribute__((packed));

struct no_update_t {
  // Set by tofino
  uint64_t egr_ts; // switch sends req
  uint64_t ingress_mac_tstamp; // switch receives resp

  // nanoPU word 1
  uint64_t msg_id;
} __attribute__((packed));

enum RespMsgId {
  kError, kNoUpdate, kAnomalyEvent, kDone
};

static constexpr uint32_t kNumHops = 4;
static constexpr uint32_t kResponseBufSize = sizeof(struct path_latency_anomaly_event_t);
static constexpr uint32_t kRequestBufSize = sizeof(struct int_path_latency_report_t) + kNumHops*sizeof(uint64_t);
static constexpr uint32_t kReportSrcIp = 0x0a020202;
static constexpr uint32_t kReportDstIp = 0x0a030303;
static constexpr uint16_t kFlowId = 0;
static constexpr uint8_t kDataFlagMask = 0x1;
static constexpr uint8_t kStartFlagMask = 0x2;
static constexpr uint8_t kFinFlagMask = 0x4;
static constexpr uint32_t kDefaultHopLatency = 100;
static constexpr uint32_t kNumReports = 50;
static constexpr uint32_t kMaxNumFlows = 256;
static constexpr uint32_t kMaxNumSamples = 10;
static constexpr uint32_t kPathLatencyThresh = 1000;

static constexpr size_t kAppEvLoopMs = 1000;  // Duration of event loop
//static constexpr bool kAppVerbose = false;    // Print debug info on datapath
//static constexpr double kAppLatFac = 10.0;    // Precision factor for latency
static constexpr size_t kAppReqType = 1;      // eRPC request type

//static constexpr size_t kAppRespSize = sizeof(struct classification_hdr_t);
//static constexpr size_t kAppMinReqSize = 64;
static constexpr size_t kAppMaxReqSize = 1024;

// If true, we persist client requests to a persistent log
//static constexpr bool kAppUsePmem = true;
//static constexpr const char *kAppPmemFile = "/dev/dax12.0";
//static constexpr size_t kAppPmemFileSize = GB(4);

volatile sig_atomic_t ctrl_c_pressed = 0;
void ctrl_c_handler(int) { ctrl_c_pressed = 1; }

struct flow_state_t {
  bool valid;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t num_samples;
  uint8_t buf_ptr;
  uint64_t latencies[kMaxNumSamples];
  uint64_t total_latency;
};

class ServerContext : public BasicAppContext {
 public:
  //size_t file_offset = 0;
  //uint8_t *pbuf;
  //SerialNuevoMatch<1>* classifier;
  uint64_t start_time;
  bool first_recvd;
  flow_state_t flowState[kMaxNumFlows];
  uint32_t total_report_count;
};

class ClientContext : public BasicAppContext {
 public:
  //size_t start_tsc;
  //size_t req_size;  // Between kAppMinReqSize and kAppMaxReqSize
  //erpc::Latency latency;
  erpc::MsgBuffer req_msgbuf, resp_msgbuf;
  uint32_t report_num;
  //trace_packet* trace_packets;
  //uint32_t num_of_packets;
  //volatile uint32_t next_trace_idx = 0;
  ~ClientContext() {}
};

void req_handler(erpc::ReqHandle *req_handle, void *_context) {
  //auto start_time_handler = erpc::rdtsc();

  auto *c = static_cast<ServerContext *>(_context);

// #if USE_PMEM == true
//   const erpc::MsgBuffer *req_msgbuf = req_handle->get_req_msgbuf();
//   const size_t copy_size = req_msgbuf->get_data_size();
//   if (c->file_offset + copy_size >= kAppPmemFileSize) c->file_offset = 0;
//   pmem_memcpy_persist(&c->pbuf[c->file_offset], req_msgbuf->buf, copy_size);

//   c->file_offset += copy_size;
// #endif
  const auto *req_msgbuf = req_handle->get_req_msgbuf();
  assert(req_msgbuf->get_data_size() == kRequestBufSize);
  auto *req = reinterpret_cast<const struct int_path_latency_report_t*>(req_msgbuf->buf);
  const uint64_t* hop_latencies = reinterpret_cast<const uint64_t*>(reinterpret_cast<const char*>(req) + sizeof(struct int_path_latency_report_t));

  uint16_t flow_hash = req->dst_port;
  bool is_start = (req->flow_flags & kStartFlagMask) > 0;
  bool is_fin = ((req->flow_flags) & kFinFlagMask) > 0;
  uint64_t path_latency = 0;
  for (uint32_t i = 0; i < req->num_hops; i++) {
    path_latency += hop_latencies[i];
  }
  uint64_t nic_timestamp = req->egr_ts; // This is as close to a NIC timestamp as we can get on these machines
  if (c->flowState[flow_hash].valid && ((c->flowState[flow_hash].src_ip != req->src_ip) ||
      (c->flowState[flow_hash].dst_ip != req->dst_ip) || (c->flowState[flow_hash].src_port != req->src_port) ||
      (c->flowState[flow_hash].dst_port != req->dst_port))) {
    printf("ERROR: flow hash collision!\n");
    assert(false);
    return;
  }
  if (is_start) {
    c->flowState[flow_hash].num_samples = 0;
    c->flowState[flow_hash].buf_ptr = 0;
    c->flowState[flow_hash].total_latency = 0;
  }

  c->flowState[flow_hash].valid = true;
  c->flowState[flow_hash].src_ip = req->src_ip;
  c->flowState[flow_hash].dst_ip = req->dst_ip;
  c->flowState[flow_hash].src_port = req->src_port;
  c->flowState[flow_hash].dst_port = req->dst_port;
  if (c->flowState[flow_hash].num_samples == kMaxNumSamples) {
    uint64_t old_latency = c->flowState[flow_hash].latencies[c->flowState[flow_hash].buf_ptr];
    c->flowState[flow_hash].latencies[c->flowState[flow_hash].buf_ptr] = path_latency;
    c->flowState[flow_hash].total_latency = c->flowState[flow_hash].total_latency + path_latency - old_latency;
  } else {
    c->flowState[flow_hash].latencies[c->flowState[flow_hash].buf_ptr] = path_latency;
    c->flowState[flow_hash].total_latency += path_latency;
    c->flowState[flow_hash].num_samples += 1;  
  }

  c->flowState[flow_hash].buf_ptr += 1;
  c->flowState[flow_hash].buf_ptr = c->flowState[flow_hash].buf_ptr % kMaxNumSamples;

  uint64_t avg_path_latency = c->flowState[flow_hash].total_latency / c->flowState[flow_hash].num_samples;
  uint64_t abs_latency_diff = (path_latency > avg_path_latency) ? (path_latency - avg_path_latency) : (avg_path_latency - path_latency);
  // printf("%ld\n", abs_latency_diff);

  if (is_fin) {
    c->flowState[flow_hash].valid = false;
  }

  if (!c->first_recvd) {
    c->start_time = nic_timestamp;
    c->first_recvd = true;
  }
  c->total_report_count++;

  auto &resp_msgbuf  = req_handle->pre_resp_msgbuf;
  erpc::Rpc<erpc::CTransport>::resize_msg_buffer(&resp_msgbuf, kResponseBufSize);

  if (c->total_report_count == kNumReports) {
    auto *resp = reinterpret_cast<struct done_message_t *>(resp_msgbuf.buf);
    resp->egr_ts = req->egr_ts;
    resp->ingress_mac_tstamp = req->ingress_mac_tstamp;
    resp->msg_id = RespMsgId::kDone;
    resp->start_time = c->start_time;
    c->total_report_count = 0;
  } else if (abs_latency_diff > kPathLatencyThresh) {
    auto *resp = reinterpret_cast<struct path_latency_anomaly_event_t *>(resp_msgbuf.buf);
    resp->egr_ts = req->egr_ts;
    resp->ingress_mac_tstamp = req->ingress_mac_tstamp;
    resp->msg_id = RespMsgId::kAnomalyEvent;
    resp->src_ip = c->flowState[flow_hash].src_ip;
    resp->dst_ip = c->flowState[flow_hash].dst_ip;
    resp->src_port = c->flowState[flow_hash].src_port;
    resp->dst_port = c->flowState[flow_hash].dst_port;
    resp->path_latency = path_latency;
    resp->anomaly_timestamp = nic_timestamp;
  } else {
    auto *resp = reinterpret_cast<struct no_update_t *>(resp_msgbuf.buf);
    resp->egr_ts = req->egr_ts;
    resp->ingress_mac_tstamp = req->ingress_mac_tstamp;
    resp->msg_id = RespMsgId::kNoUpdate;
  }

  //double req_lat_us = erpc::to_usec(erpc::rdtsc() - start_time_handler, c->rpc->get_freq_ghz());
  //printf("%lf\n", req_lat_us);
  c->rpc->enqueue_response(req_handle, &resp_msgbuf);
}

void server_func(erpc::Nexus *nexus) {
  std::vector<size_t> port_vec = flags_get_numa_ports(FLAGS_numa_node);
  uint8_t phy_port = port_vec.at(0);

  ServerContext c;
  erpc::Rpc<erpc::CTransport> rpc(nexus, static_cast<void *>(&c), 0 /* tid */,
                                  basic_sm_handler, phy_port);
  c.rpc = &rpc;

  c.first_recvd = false;
  c.start_time = 0;
  c.total_report_count = 0;
  for (uint32_t i = 0; i < kMaxNumFlows; i++) {
    c.flowState[i].valid = false;
  }

// #if USE_PMEM == true
//   printf("Mapping pmem file...");
//   c.pbuf = erpc::map_devdax_file(kAppPmemFile, kAppPmemFileSize);
//   pmem_memset_persist(c.pbuf, 0, kAppPmemFileSize);
//   printf("done.\n");
// #endif

	// Set configuration for NuevoMatch
	// NuevoMatchConfig config;
	// config.num_of_cores = 1;
	// config.max_subsets = 1;
	// config.start_from_iset = 0;
	// config.disable_isets = false;
	// config.disable_remainder = false;
	// config.disable_bin_search = false;
	// config.disable_validation_phase = false;
	// config.disable_all_classification = false;
	// //config.force_rebuilding_remainder = true;
	// config.force_rebuilding_remainder = false;

	// uint32_t binth = 8;
	// uint32_t threshold = 25;
 //  config.remainder_classifier = new CutSplit(binth, threshold);
	// config.remainder_type = "cutsplit";

  // c.classifier = new SerialNuevoMatch<1>(config);

	// Read classifier file to memory
	// ObjectReader classifier_handler("nuevomatch_64.classifier");
	// c.classifier->load(classifier_handler);



  while (true) {
    rpc.run_event_loop(10);
    if (ctrl_c_pressed == 1) break;
  }
}

void connect_session(ClientContext &c) {
  std::string server_uri = erpc::get_uri_for_process(0);
  printf("Process %zu: Creating session to %s.\n", FLAGS_process_id,
         server_uri.c_str());

  int session_num = c.rpc->create_session(server_uri, 0 /* tid */);
  erpc::rt_assert(session_num >= 0, "Failed to create session");
  c.session_num_vec.push_back(session_num);

  while (c.num_sm_resps != 1) {
    c.rpc->run_event_loop(10);
    if (unlikely(ctrl_c_pressed == 1)) return;
  }
}

void app_cont_func(void *, void *);
inline void send_req(ClientContext &c) {
  // c.start_tsc = erpc::rdtsc();
  assert(c.req_msgbuf.get_data_size() == kRequestBufSize);
  struct int_path_latency_report_t* req = reinterpret_cast<struct int_path_latency_report_t *>(c.req_msgbuf.buf);
  req->egr_ts = 0;
  req->ingress_mac_tstamp = 0;
  req->src_ip = kReportSrcIp;
  req->dst_ip = kReportDstIp;
  req->src_port = 0;
  req->dst_port = kFlowId;
  req->proto = 0;
  req->flow_flags = kDataFlagMask;
  if (c.report_num == 0) {
    req->flow_flags |= kStartFlagMask;
  }
  req->num_hops = kNumHops;
  uint64_t* hop_latencies_dst = reinterpret_cast<uint64_t*>(reinterpret_cast<char*>(req) + sizeof(struct int_path_latency_report_t));
  for (uint64_t i = 0; i < kNumHops; i++) {
    hop_latencies_dst[i] = kDefaultHopLatency;
    if (i == 1 && c.report_num == 40) {
      hop_latencies_dst[i] = 20000;
    }
  }
  c.report_num++;


  //req->trace_idx = c.next_trace_idx;
  //req->match_priority = 0;
  //memcpy((uint32_t *)req->headers, c.trace_packets[req->trace_idx].get(), CLASSIFICATION_HEADER_WORDS*8);
  //c.next_trace_idx = (c.next_trace_idx+1) % c.num_of_packets;
  if (c.report_num <= kNumReports) {
    c.rpc->enqueue_request(c.session_num_vec[0], kAppReqType, &c.req_msgbuf,
                           &c.resp_msgbuf, app_cont_func, nullptr);
  }
}

void app_cont_func(void *_context, void *) {
  auto *c = static_cast<ClientContext *>(_context);
  assert(c->resp_msgbuf.get_data_size() == kResponseBufSize);
  erpc::rt_assert(c->resp_msgbuf.get_data_size() == kResponseBufSize,
                  "Invalid response size");
  auto* resp = reinterpret_cast<struct no_update_t*>(c->resp_msgbuf.buf);
  //assert(resp->trace_idx < c->num_of_packets);
//#if 0
//  if (resp->match_priority != c->trace_packets[resp->trace_idx].match_priority)
//    printf("WARNING: trace_idx %u match_priority %d (should be %d)\n", resp->trace_idx, resp->match_priority, c->trace_packets[resp->trace_idx].match_priority);
//#endif
//#if 0
  //else printf("MATCHED!!!!!!!1 trace_idx %u match_priority %d (should be %d)\n", resp->trace_idx, resp->match_priority, c->trace_packets[resp->trace_idx].match_priority);
//#endif
  uint64_t egr_ts = be64toh(resp->egr_ts) >> 16;
  uint64_t ingr_ts = be64toh(resp->ingress_mac_tstamp) >> 16;
  uint64_t lat_ns = ingr_ts - egr_ts;
  printf("egr_ts: 0x%lx    ingress_mac_tstamp: 0x%lx   latency: %ldns\n", egr_ts, ingr_ts, lat_ns);
  printf("msg id is %ld\n", resp->msg_id);

  if (resp->msg_id == RespMsgId::kDone) {
    auto* done_resp = reinterpret_cast<struct done_message_t*>(resp);
    uint64_t start_time = be64toh(done_resp->start_time) >> 16;
    uint64_t overall_latency = ingr_ts - start_time;
    printf("ingress time is %ld, start time is %ld, latency is %ld\n", ingr_ts, start_time, overall_latency);
  } else if (resp->msg_id == RespMsgId::kAnomalyEvent) {
    auto* anomaly_resp = reinterpret_cast<struct path_latency_anomaly_event_t*>(resp);
    uint64_t anomaly_ts = be64toh(anomaly_resp->anomaly_timestamp) >> 16;
    uint64_t reflex_latency = ingr_ts - anomaly_ts;
    printf("anomaly ingress at %ld, original ts %ld, reflex latency %ld\n", ingr_ts, anomaly_ts, reflex_latency);
  }

//#if 0
//  double req_lat_us =
//      erpc::to_usec(erpc::rdtsc() - c->start_tsc, c->rpc->get_freq_ghz());
//#else
//  double req_lat_us = lat_ns/1e3;
//#endif
//  c->latency.update(static_cast<size_t>(req_lat_us * kAppLatFac));

  send_req(*c);
}

void client_func(erpc::Nexus *nexus) {
  // Initial erpc setup
  std::vector<size_t> port_vec = flags_get_numa_ports(FLAGS_numa_node);
  uint8_t phy_port = port_vec.at(0);
  ClientContext c;
  erpc::Rpc<erpc::CTransport> rpc(nexus, static_cast<void *>(&c), 0,
                                  basic_sm_handler, phy_port);
  rpc.retry_connect_on_invalid_rpc_id = true;
  c.rpc = &rpc;
  c.req_msgbuf = rpc.alloc_msg_buffer_or_die(kAppMaxReqSize);
  c.resp_msgbuf = rpc.alloc_msg_buffer_or_die(kAppMaxReqSize);

  // INT-specific eRPC configuration
  //c.req_size = kRequestBufSize;
  c.rpc->resize_msg_buffer(&c.req_msgbuf, kRequestBufSize);
  c.rpc->resize_msg_buffer(&c.resp_msgbuf, kResponseBufSize);
  c.report_num = 0;

  // Read the textual trace file
  // const char* trace_filename = "trace";
  // vector<uint32_t> arbitrary_fields;
  // c.trace_packets = read_trace_file(trace_filename, arbitrary_fields, &c.num_of_packets);
  // if (!c.trace_packets) {
  //   throw error("error while reading trace file");
  // }
  // printf("Total %u packets in trace\n", c.num_of_packets);

  connect_session(c);

  printf("Process %zu: Session connected. Starting work.\n", FLAGS_process_id);
  // printf("write_size median_us 5th_us 99th_us 999th_us\n");

  send_req(c);
  for (size_t i = 0; i < FLAGS_test_ms; i += 1000) {
    rpc.run_event_loop(10);  // 1 second
    if (ctrl_c_pressed == 1) break;
    // printf("%zu %.1f %.1f %.1f %.1f\n", c.req_size,
    //        c.latency.perc(.5) / kAppLatFac, c.latency.perc(.05) / kAppLatFac,
    //        c.latency.perc(.99) / kAppLatFac, c.latency.perc(.999) / kAppLatFac);

// #if 0
    // c.req_size *= 2;
    // if (c.req_size > kAppMaxReqSize) c.req_size = kAppMinReqSize;
    // c.rpc->resize_msg_buffer(&c.req_msgbuf, c.req_size);
    // c.rpc->resize_msg_buffer(&c.resp_msgbuf, c.req_size);
// #endif

    //c.latency.reset();
  }
}

int main(int argc, char **argv) {
  signal(SIGINT, ctrl_c_handler);

  gflags::ParseCommandLineFlags(&argc, &argv, true);
  erpc::rt_assert(FLAGS_numa_node <= 1, "Invalid NUMA node");
  erpc::Nexus nexus(erpc::get_uri_for_process(FLAGS_process_id),
                    FLAGS_numa_node, 0);
  nexus.register_req_func(kAppReqType, req_handler);

  auto t =
      std::thread(FLAGS_process_id == 0 ? server_func : client_func, &nexus);
  erpc::bind_to_core(t, FLAGS_numa_node, 0);
  t.join();
}
