#include <stdio.h>
#include "sha_blob_reference.h"
#include <random>
#include <algorithm>
#include <iterator>
#include <vector>
#include <string>
#include "concurrent_queue.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstring>
#include "blob_network_processor.h"
#include "../ca_blobs_fs/streaming_blobs.h"

#include "error.h"
extern int change_mode(const char *filename, const char *mode_string, int respect_umask);
extern void change_utime(const char* filename, time_t timestamp);
extern int unlink_file(const char* filename);

struct BlobTask
{
  std::string message, dirpath, filename, encoded_hash, file_mode;
  time_t timestamp;
  bool compress, noWrite;
  enum class Type { Download, Upload } type;
};

static bool download_blob_ref_file(BlobNetworkProcessor *processor, const BlobTask &task);
static bool upload_blob_ref_file(BlobNetworkProcessor *processor, const BlobTask &task);

static bool process_blob_task(BlobNetworkProcessor *download_processor, BlobNetworkProcessor *upload_processor, const BlobTask &task)
{
  if (task.type == BlobTask::Type::Download)
    return download_blob_ref_file(download_processor, task);
  return upload_blob_ref_file(upload_processor, task);
}

static std::atomic<int> hasErrors;
extern void cvs_flusherr();

int blob_download_progress = 0;//--blob_progress: once a second print download speed & servers data comes from

enum {MAX_PROGRESS_CLIENTS = 64};
static std::atomic<uint64_t> progress_bytes{0};//total wire bytes downloaded
static std::atomic<uint64_t> progress_client_bytes[MAX_PROGRESS_CLIENTS];
static std::atomic<bool> progress_stop{false};
static std::thread progress_thread;
static std::mutex progress_mutex;//guards urls & console line state
static std::string progress_client_url[MAX_PROGRESS_CLIENTS];//url:port each download client is connected to
static size_t progress_line_len = 0;//chars of progress line currently on screen

void blob_progress_note_server(int id, const char *url, int port)
{
  if (!blob_download_progress || unsigned(id) >= MAX_PROGRESS_CLIENTS)
    return;
  char buf[300]; std::snprintf(buf, sizeof(buf), "%s:%d", url, port);
  std::lock_guard<std::mutex> lock(progress_mutex);
  progress_client_url[id] = buf;
}

void blob_progress_add_bytes(int id, uint64_t sz)
{
  if (!blob_download_progress)
    return;
  progress_bytes.fetch_add(sz, std::memory_order_relaxed);
  if (unsigned(id) < MAX_PROGRESS_CLIENTS)
    progress_client_bytes[id].fetch_add(sz, std::memory_order_relaxed);
}

static void progress_clear_line_unlocked()
{
  if (progress_line_len)
  {
    fprintf(stderr, "\r%*s\r", (int)progress_line_len, "");
    fflush(stderr);
    progress_line_len = 0;
  }
}

//erase the progress line so regular output starts at column 0. call before printing to the console
void blob_progress_clear_line()
{
  if (!blob_download_progress)
    return;
  std::lock_guard<std::mutex> lock(progress_mutex);
  progress_clear_line_unlocked();
}

static void progress_loop()
{
  const double MB = 1024.*1024.;
  uint64_t prev = 0, prevClient[MAX_PROGRESS_CLIENTS] = {0};
  bool printedAnything = false;
  auto tick = std::chrono::steady_clock::now();
  for (;;)
  {
    tick += std::chrono::seconds(1);
    while (!progress_stop.load() && std::chrono::steady_clock::now() < tick)
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (progress_stop.load())
      break;
    const uint64_t cur = progress_bytes.load();
    const uint64_t spd = cur - prev;
    prev = cur;
    if (!cur)
      continue;//nothing downloaded yet, keep quiet
    //the source to show is where the bytes of the last second actually came from
    int best = -1, active = 0; uint64_t bestSpd = 0;
    for (int i = 0; i < MAX_PROGRESS_CLIENTS; ++i)
    {
      const uint64_t cb = progress_client_bytes[i].load(std::memory_order_relaxed), d = cb - prevClient[i];
      prevClient[i] = cb;
      if (!d)
        continue;
      ++active;
      if (d > bestSpd) { bestSpd = d; best = i; }
    }
    char line[512], more[32] = "";
    if (active > 1)
      std::snprintf(more, sizeof(more), " +%d more", active-1);
    std::lock_guard<std::mutex> lock(progress_mutex);
    std::snprintf(line, sizeof(line), "%.2f MB/s from %s%s (%.1f MB total)",
      spd/MB, best < 0 ? "-" : progress_client_url[best].c_str(), more, cur/MB);
    const size_t len = strlen(line);
    fprintf(stderr, "\r%-*s", (int)(len > progress_line_len ? len : progress_line_len), line);
    fflush(stderr);
    progress_line_len = len;
    printedAnything = true;
  }
  std::lock_guard<std::mutex> lock(progress_mutex);
  if (progress_line_len)
  {
    fputs("\n", stderr);
    fflush(stderr);
    progress_line_len = 0;
  }
  else if (printedAnything)
    fflush(stderr);
}

static void start_progress_thread()
{
  if (!blob_download_progress || progress_thread.joinable())
    return;
  progress_stop = false;
  progress_thread = std::thread(progress_loop);
}

static void stop_progress_thread()
{
  if (!progress_thread.joinable())
    return;
  progress_stop = true;
  progress_thread.join();
}

template <typename T>
struct atomic_wrapper
{
  std::atomic<T> _a;

  atomic_wrapper():_a(){}
  atomic_wrapper(const std::atomic<T> &a):_a(a.load()){}
  atomic_wrapper(const atomic_wrapper &other):_a(other._a.load()){}
  atomic_wrapper &operator=(const atomic_wrapper &other) {_a.store(other._a.load());}
  operator T() {return T(_a);}
  atomic_wrapper(const T& other) { _a = other; }
  atomic_wrapper& operator=(const T& other) { _a = other; return *this; }
};

struct BackgroundProcessor:public UrlProvider
{
  bool demandAuth() const override;
  bool getOTP(uint8_t *otp, size_t otp_size, uint64_t &otp_page) const override;
  const char* getRoot() const override;
  int attemptsCount(int id) const override;
  bool getNext(int attempt, int id, std::string &url, int &port) const override;//shuffled with id
  void fail(int attempt, int id) const override;

  BackgroundProcessor():queue(&threads){}
  ~BackgroundProcessor()
  {
    stop_progress_thread();
  }
  void finishDownloads()
  {
    if (hasErrors.load())
    {
      queue.cancel();
      stop_progress_thread();
      cvs_flusherr();
      error_exit();
    }
    queue.finishWork();
    stop_progress_thread();
  }

  bool is_inited() const {return !download_clients.empty();}
  void init();
  void wait();

  static void processor_thread_loop(BackgroundProcessor *processors, BlobNetworkProcessor *download_processor, BlobNetworkProcessor *upload_processor)
  {
    BlobTask task;
    while (hasErrors.load() == 0 && processors->queue.wait_and_pop(task))
      hasErrors.fetch_or(process_blob_task(download_processor, upload_processor, task) ? 0 : 1);
  }
  void emplace(BlobTask &&task)
  {
    if (!is_inited())
      return;
    if (threads.empty())
    {
      if (!process_blob_task(download_clients[0].get(), upload_clients[0].get(), task))
      {
    	cvs_flusherr();
		error_exit();
      }
    } else
    {
      //we can't guarantee, that user will finish download (not cancel it, kill the process or whatever)
      //if he won't, then entries would still be updated with new version, but the file will be old (while be shown as Modified)
      //the correct way would be to keep old entries, and update them only when download is finished
      //that's doable, but will require to:
      //  a) implement locking (so same entries are not updated from different threads, including main)
      //  b) format of entries has to be known here
      //  While not a big deal, is still not that easy task
      // so we use simplest solution - we simply kill old binary file. It can also be renamed, but better to not bother
      if (task.type == BlobTask::Type::Download)
        unlink_file(task.filename.c_str());
      else
      {
        //we preferrably lock file (by opening file handler) to prevent changing during commit
        //but total amount of file handlers is limited, so we trust people to be reasonable
      }
      queue.emplace(std::move(task));
    }
  }
  concurrent_queue<BlobTask> queue;
  std::vector<std::unique_ptr<BlobNetworkProcessor>> download_clients;//soa
  std::vector<std::unique_ptr<BlobNetworkProcessor>> upload_clients;//soa
  std::vector<std::thread> threads;//soa

  std::string base_repo;
  protected:

  struct DownloadURL
  {
    std::string url; int port;
    mutable atomic_wrapper<bool> failed = false;
  };
  struct RoundRobin
  {
    std::vector<DownloadURL> urls;//last one is always master
    uint32_t shuffleStart = 0, publicCount = 0, privateCount = 0;
    uint32_t shuffle(uint32_t attempt, uint32_t id) const;
    void createShuffles(uint32_t count, uint16_t publicCnt, uint16_t privateCnt);
  } roundRobin;

  uint32_t shuffle(uint32_t attempt, uint32_t id) const;
  void prepareShuffles(uint32_t count);

#if defined(_WIN32) && 0
  httplib::detail::WSInit wsinit_;
#endif
};

static std::unique_ptr<BackgroundProcessor> processor;

extern BlobNetworkProcessor *get_kv_processor(const UrlProvider& provider_, int id);

bool BackgroundProcessor::demandAuth() const
{
  extern bool always_demand_blob_encryption();
  return always_demand_blob_encryption();
}

bool BackgroundProcessor::getOTP(uint8_t *otp, size_t otp_size, uint64_t &otp_page) const
{
  extern uint32_t get_current_otp_info(uint8_t *otp, uint32_t otp_len, uint64_t& otp_page);
  memset(otp, 0, otp_size);
  return get_current_otp_info(otp, uint32_t(otp_size), otp_page) == uint32_t(otp_size);
}

const char* BackgroundProcessor::getRoot() const {  return base_repo.c_str(); }

int BackgroundProcessor::attemptsCount(int id) const
{
  return id < 0 ? 1 : (int)roundRobin.urls.size();
}

void BackgroundProcessor::fail(int attempt, int id) const
{
  if (uint32_t(attempt) >= roundRobin.urls.size())
    return;
  const int ui = roundRobin.shuffle(attempt, id);
  if (roundRobin.urls[ui].failed)//already failed
    return;
  blob_progress_clear_line();
  error(0,0, "Blobs server %s:%d failed\n%s. Contact IT!\n",
    roundRobin.urls[ui].url.c_str(), roundRobin.urls[ui].port,
    attempt < int(roundRobin.urls.size())-2 ? "Switching to next." :
      (attempt < int(roundRobin.urls.size())-1 ? "Switching to master." : "Master is not available!"));
  roundRobin.urls[ui].failed = true;
}

void BackgroundProcessor::RoundRobin::createShuffles(uint32_t count, uint16_t publicCnt, uint16_t privateCnt)
{
  //just use round robin with shuffled start
  const size_t urlsCnt = urls.size();
  std::random_device rd;
  std::mt19937 g(rd());
  shuffleStart = uint32_t(g());
  publicCount = publicCnt;
  privateCount = privateCnt;
}

uint32_t BackgroundProcessor::RoundRobin::shuffle(uint32_t attempt, uint32_t id) const
{
  if (urls.empty())
    return 0;
  const uint32_t urlsCnt = uint32_t(urls.size());
  if (publicCount <= 1 && privateCount <= 1)//last one is Master, and nothing to shuffle
    return attempt%urlsCnt;
  const uint32_t shuffledId = id + shuffleStart;
  if (attempt < publicCount)//first round robin on all public addresses
    return (attempt + shuffledId)%publicCount;
  if (attempt < privateCount)//then round robin on all private addresses
    return publicCount + uint32_t(attempt-publicCount + shuffledId)%privateCount;
  return urlsCnt-1;//master
}

bool BackgroundProcessor::getNext(int attempt, int id, std::string &url, int &port) const
{
  if (uint32_t(attempt) >= roundRobin.urls.size())
    return false;
  if (id < 0)
  {
    if (attempt != 0)
      return false;
    url = roundRobin.urls.back().url.c_str();
    port = roundRobin.urls.back().port;
    return true;
  }
  const int ui = roundRobin.shuffle(attempt, id);
  url = roundRobin.urls[ui].url.c_str();
  port = roundRobin.urls[ui].port;
  return true;
}

//link time resolved dependency
void get_download_source(const char *&config_url, int &config_port, const char *&repo, int &private_urls, int &public_urls, int &threads_count);
int get_public_blob_url(uint32_t i, const char *&url, int &port);
int get_private_blob_url(uint32_t i, const char *&url, int &port);
const char *get_master_blob_url(int &port);

void BackgroundProcessor::init()
{
  if (is_inited())
    return;

  int threads_count = std::min(8, std::max(1, (int)std::thread::hardware_concurrency()-1));//limit concurrency to fixed
  const char *config_url = nullptr;
  const char *repo = nullptr;
  int config_port = 2403;
  int private_urls = 0, public_urls = 0;
  get_download_source(config_url, config_port, repo, private_urls, public_urls, threads_count);
  base_repo = repo;
  if (base_repo[0] != '/')
    base_repo = "/" + base_repo;
  if (base_repo[base_repo.length()] != '/')
    base_repo += "/";

  uint32_t publicUrlsCnt = 0, privateUrlsCnt = 0;
  if (config_url)
  {
    private_urls = 1, public_urls = 0;//force using config
    //only one URL, no round robin
    roundRobin.urls.push_back(DownloadURL{config_url, config_port});
  } else
  {
    for (int i = 0; i < public_urls; ++i)
    {
      const char *url = nullptr; int port = 0;
      if (get_public_blob_url(i, url, port) >= 0)
      {
        roundRobin.urls.push_back(DownloadURL{url, port});//the last one
        publicUrlsCnt++;
      }
    }
    for (int i = 0; i < private_urls; ++i)
    {
      const char *url = nullptr; int port = 0;
      if (get_private_blob_url(i, url, port) >= 0)
      {
        roundRobin.urls.push_back(DownloadURL{url, port});//the last one
        privateUrlsCnt++;
      }
    }
  }

  int master_port = 2403;
  const char *master_url = get_master_blob_url(master_port);
  roundRobin.urls.push_back(DownloadURL{master_url, master_port});//the last one

  const uint32_t clientsCount = (uint32_t)std::max(1, threads_count);
  roundRobin.createShuffles(clientsCount, publicUrlsCnt, privateUrlsCnt);

  download_clients.resize(clientsCount);
  upload_clients.resize(clientsCount);
  int id = 0;
  for (auto &cli : download_clients)
    cli.reset(get_kv_processor(*this, id++));

  for (auto &cli : upload_clients)
    cli.reset(get_kv_processor(*this, -1));

  for (int ti = 0; ti < threads_count; ++ti)
    threads.emplace_back(std::thread(processor_thread_loop, this, download_clients[ti].get(), upload_clients[ti].get()));

  start_progress_thread();
}

void BackgroundProcessor::wait()
{
  for (auto &t:threads)
    t.join();
}


extern char *xgetwd();
extern void blob_free(void*);
void add_upload_queue(const char *filename, bool compress, const char *message)
{
  if (!processor)
  {
  	processor.reset(new BackgroundProcessor);
    processor->init();
  }
  if (!processor->upload_clients[0])
    return;
  char *cdir = xgetwd();
  processor->emplace(BlobTask{message, cdir, filename, "", "", 0, compress, false, BlobTask::Type::Upload});
  blob_free(cdir);
}
int cvs_output(const char *, size_t);
int cvs_outerr(const char *, size_t);
//console output of worker threads has to erase the progress line first, so it starts at column 0;
//the lock is held across the print so the ticker can't redraw the line in between
static int out_msg(const char *buf)
{
  std::lock_guard<std::mutex> lock(progress_mutex);
  progress_clear_line_unlocked();
  return cvs_output(buf, 0);
}
static int err_msg(const char *buf)
{
  std::lock_guard<std::mutex> lock(progress_mutex);
  progress_clear_line_unlocked();
  return cvs_outerr(buf, 0);
}

#include <unordered_set>
static std::unordered_set<std::string> download_dirs;
bool dir_being_downloaded_to(const char *s)
{
  return download_dirs.find(s) != download_dirs.end();
}

bool cur_dir_being_downloaded_to()
{
  char *cdir = xgetwd();
  const bool ret = dir_being_downloaded_to(cdir);
  blob_free(cdir);
  return ret;
}

void add_download_queue(const char *message, const char *filename, const char *encoded_hash, const char *file_mode, time_t timestamp, bool no_write)
{
  if (!processor)
  {
  	processor.reset(new BackgroundProcessor);
    processor->init();
  }
  char *cdir = xgetwd();
  download_dirs.emplace(cdir);
  processor->emplace(BlobTask{message, cdir, filename, encoded_hash, file_mode, timestamp, false, no_write, BlobTask::Type::Download});
  blob_free(cdir);
}

void wait_threads()
{
  if (processor)
    processor->finishDownloads();
  processor.reset();

}
void rename_file (const char *from, const char *to);
size_t get_file_size(const char* file);
static bool validate_downloaded_blobs = true;
char *cvs_temp_name();

static bool download_blob_ref_file(BlobNetworkProcessor *processor, const BlobTask &task)
{
  const bool validateHash = !task.noWrite && validate_downloaded_blobs;
  std::string temp_filename = task.dirpath +"/_new_";
  temp_filename += task.filename;
  size_t readUncompressedSz = ~size_t(0);
  for (int i = 0; i < 16; ++i)//make 16 attempts
  {

    FILE* tmp = fopen(temp_filename.c_str(), "wb");
    if (!tmp)
    {
      char buf[512]; std::snprintf(buf, sizeof(buf), "can't write temp %s\n", temp_filename.c_str());
      err_msg(buf);
      return false;
    }
    std::string err;
    char buf[512];
    caddressed_fs::DownloadBlobInfo info;
    char hashCtx[HASH_CONTEXT_SIZE];
    if (validate_downloaded_blobs)
      init_blob_hash_context(hashCtx, sizeof(hashCtx));
    bool downloadRet = processor->download(task.encoded_hash.data(),
        [&](const char *data, size_t data_length) {
          return caddressed_fs::decode_stream_blob_data(info, data, data_length,
            [&](const void *data, size_t sz) {
              const size_t written = task.noWrite ? sz : fwrite(data, 1, sz, tmp);
              if (validateHash)
                update_blob_hash(hashCtx, (const char *)data, std::min(written, sz));
              return written == sz;
            });//we can easily add hash validation here. but seems unnessasry
        },
        err);
    if (tmp && fclose(tmp) != 0)
    {
      err += "\nCan't write file - disk is full?";
      downloadRet = false;
    }
    if (!downloadRet)
      std::snprintf(buf, sizeof(buf), "ERROR: can't download <%.64s>, err = %s\n", task.encoded_hash.data(), err.c_str());
    bool validated = true;
    if (downloadRet && validateHash)
    {
      char recievedHash[65];recievedHash[0]=recievedHash[64]=0;
      unsigned char digest[32];
      finalize_blob_hash(hashCtx, digest, sizeof(digest));
      bin_hash_to_hex_string_64(digest, recievedHash);
      if (memcmp(task.encoded_hash.data(), recievedHash, 64) != 0)
      {
        //rename to something!
        char *tempName = cvs_temp_name();
        rename_file(temp_filename.c_str(), tempName);
        std::snprintf(buf, sizeof(buf),
          "ERROR: downloaded hash <%.64s> is different from requested <%.64s> for <%s>.\n"
          "File renamed to <%s>. Check it's content!!!\n",
          recievedHash, task.encoded_hash.data(), task.message.c_str(),
          tempName);
        validated = false;
      } else
      {
        const size_t fsz = get_file_size(temp_filename.c_str());//validate file system
        if (fsz != info.realUncompressedSize)
        {
          std::snprintf(buf, sizeof(buf),
            "ERROR: file <%s> has size of %lld after downloading, while we downloaded %lld\n",
            temp_filename.c_str(), (long long)fsz, (long long)info.realUncompressedSize);
          validated = false;
        }
      }
    }
    if (!downloadRet || !validated)
    {
      unlink_file(temp_filename.c_str());
      if (!processor->reconnect())
      {
        err_msg(buf);
        return false;
      } else
      {
        blob_progress_clear_line();
        error(0,0, "%s Reconnecting!\n", buf);
      }
    }
    else
    {
      readUncompressedSz = info.realUncompressedSize;
      break;
    }
  }
  std::string fullPath = (task.dirpath+"/")+task.filename;
  {
    int status = change_mode (temp_filename.c_str(), task.file_mode.c_str(), 1);
    if (status != 0)
      error (0, status, "cannot change mode of %s", task.filename.c_str());
  }
  rename_file (temp_filename.c_str(), fullPath.c_str());
  change_utime(fullPath.c_str(), task.timestamp);
  if (validateHash)
  {
    const size_t fsz = get_file_size(fullPath.c_str());//validate file system again
    if (fsz != readUncompressedSz)
    {
      char buf[256];std::snprintf(buf, sizeof(buf),
        "ERROR: file <%s> has size of %lld after renaming, while we downloaded %lld\n", fullPath.c_str(), (long long)fsz, (long long)readUncompressedSz);
      err_msg(buf);
      return false;
    }
  }
  char buf[256];std::snprintf(buf, sizeof(buf),"u %s\n", task.message.c_str());
  out_msg(buf);
  return true;
}
bool is_blob_file_sent(const char* filepath, const char* fileopen, char* hash_encoded);
bool finish_send_blob_file(const char* filepath, const char* fileopen, const char* hash_encoded);

static bool upload_blob_ref_file(BlobNetworkProcessor *processor, const BlobTask &task)
{
  std::string fullPath = (task.dirpath+"/")+task.filename;
  char hash[65]; hash[0]=hash[64] = 0;
  if (is_blob_file_sent(task.filename.c_str(), fullPath.c_str(), hash))
    return true;
  std::string err;
  if (!processor->upload(fullPath.c_str(), task.compress, hash, err))
  {
    char buf[512];std::snprintf(buf, sizeof(buf), "can't upload file <%s>, err = %s\n", fullPath.c_str(), err.c_str());
    err_msg(buf);
    return false;
  }
  if (finish_send_blob_file(task.filename.c_str(), fullPath.c_str(), hash))
  {
    char buf[256];std::snprintf(buf, sizeof(buf),"b %s\n", task.message.c_str());
    out_msg(buf);
  } else
  {
    char buf[512];std::snprintf(buf, sizeof(buf),"can't finish sending blob %s\n", task.message.c_str());
    err_msg(buf);
    return false;
  }
  return true;
}

