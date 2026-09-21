#include <sstream>
#include "blob_network_processor.h"
#include "sha_blob_reference.h"
#include <../keyValueServer/include/blobs_encryption.h>
#include <../keyValueServer/include/blob_client_lib.h>
#include <../keyValueServer/include/blob_sockets.h>
#include <memory>

void error(int, int, const char*, ...);

const char *blob_slow_switch_err = "source is slow, switching";//recognized by the retry loop
//set while we deliberately close a socket to abort a pull: suppresses the resulting read-error logs
static thread_local bool expect_socket_abort = false;

inline KVRet send_blob_file_data_net(BlobSocket &client, const char *file, const char *hash, bool blob_binary_compressed, std::string &err)
{
  auto output = std::stringstream("");
  using namespace caddressed_fs;
  using namespace streaming_compression;
  FILE* rf = fopen(file, "rb");
  fseek(rf, 0, SEEK_END);
  const size_t fsz = ftell(rf);
  fseek(rf, 0, SEEK_SET);
  StreamToServerData *strm = start_blob_stream_to_server(client, HASH_TYPE_REV_STRING, hash);
  if (!strm)
  {
    output << "Can't start sending binary blob data for " << file; err = output.str();
    return !is_valid(client) ? KVRet::Fatal : KVRet::Error;
  }

  BlobHeader hdr = get_header(blob_binary_compressed ? zstd_magic : noarc_magic, fsz, 0);
  char hctx[HASH_CONTEXT_SIZE];
  init_blob_hash_context(hctx, sizeof(hctx));
  KVRet r = blob_stream_to_server(*strm, &hdr, sizeof(hdr));

  char bufIn[128<<10]; char bufOut[64<<10];
  StreamStatus st = compress_lambda(
    [&](const char *&src, size_t &src_pos, size_t &src_size)
      {if (src_pos < src_size) return StreamStatus::Continue;//previously extracted wasn't consumed
       src = bufIn; src_pos = 0;
       src_size = fread(bufIn, 1, sizeof(bufIn), rf);
       update_blob_hash(hctx, bufIn, src_size);
       return ferror(rf) ? StreamStatus::Error : src_size == 0 ? StreamStatus::Finished : StreamStatus::Continue;
      },
    [&](char *&dst, size_t &dst_pos, size_t &dst_capacity)
      {
        if (dst_pos && r == KVRet::OK)
          r = blob_stream_to_server(*strm, bufOut, dst_pos);
        dst_pos = 0; dst_capacity = sizeof(bufOut); dst = bufOut;
        return StreamStatus::Continue;
      }
   , 6, blob_binary_compressed ? StreamType::ZSTD : StreamType::Unpacked);
  fclose(rf);

  if (st != StreamStatus::Finished)
  {
    output << "Can't compress binary blob for " << file << "\n";
    if (r == KVRet::OK)
      r = KVRet::Error;
  }
  uint8_t digest[32];char real_hash[65];real_hash[0]=real_hash[64]=0;
  if (!finalize_blob_hash(hctx, digest) || !bin_hash_to_hex_string_64(digest, real_hash))
  {
    output << "Can't calc hash for " << file;
    if (r == KVRet::OK)
      r = KVRet::Error;
  }
  if (memcmp(real_hash, hash, 64))
  {
    output << "File " << file << " changed it's hash from " << hash << " to "<<real_hash<<". Failing!\n";
    if (r == KVRet::OK)
      r = KVRet::Error;
  }
  if (r == KVRet::Fatal || (r = finish_blob_stream_to_server(client, strm, r == KVRet::OK)) == KVRet::Fatal)
    stop_blob_push_client(client);
  if (r != KVRet::OK)
    output << "Can't send binary blob data for " << file;
  err = output.str();
  return r;
}

struct KVNetworkProcessor:public BlobNetworkProcessor
{
  KVNetworkProcessor(const UrlProvider& provider_, int id_):provider(provider_), id(id_){}
  ~KVNetworkProcessor() { stop_blob_push_client(client); }

  bool start() {return is_valid(client) ? true : init(); }
  bool connectTo(const char *url, int port)
  {
    uint8_t otp[otp_page_size]; uint64_t otp_page = 0;
    const bool has_otp = provider.getOTP(otp, sizeof(otp), otp_page);
    CafsClientAuthentication auth = provider.demandAuth() ? CafsClientAuthentication::RequiresAuth : CafsClientAuthentication::AllowNoAuthPrivate;
    stop_blob_push_client(client);
    if (is_valid(client = start_blob_push_client(url, port, provider.getRoot(), 2/*timeout*/, has_otp ? otp : nullptr, otp_page, auth)))
    {
      //escalate patience with every consecutive failure: a huge blob served over a genuinely slow
      //path can pause longer than the default timeout, and it must still be able to complete
      blob_send_recieve_sock_timeout(client, 30 * (1 << (failStreak > 3 ? 3 : failStreak)));
      extern void blob_progress_note_server(int id, const char *url, int port);
      blob_progress_note_server(id, url, port);//ignores upload clients (id < 0)
      return true;
    }
    return false;
  }
  bool attemptReconnect(int attemptNo)
  {
    if (attemptNo >= provider.attemptsCount(id))
      return false;
    std::string url; int port;
    if (!provider.getNext(attemptNo, id, url, port))
      return false;
    if (connectTo(url.c_str(), port))
      return true;
    provider.fail(attemptNo, id);
    return false;
  }
  //error recovery reconnects round robin - the next source is guaranteed to be a different one
  //(the current source's measured speed is stale at best, it just failed us). only a supervisor
  //requested switch prefers the fastest source measured so far
  bool reconnect() { return reconnectEx(false); }
  bool reconnectEx(bool preferFastest)
  {
    if (preferFastest)
    {
      extern bool blob_progress_pick_fastest(int id, std::string &url, int &port);
      std::string url; int port;
      if (blob_progress_pick_fastest(id, url, port) && connectTo(url.c_str(), port))
        return true;
    }
    ++attempt;
    return init();
  }
  bool init() {
    //wrap around the source list, so a client is never permanently out of sources
    //(also retries sources that failed earlier - the network could have recovered)
    const int e = provider.attemptsCount(id);
    if (e <= 0)
      return false;
    for (int i = 0; i < e; ++i)
      if (attemptReconnect((attempt + i) % e))
      {
        attempt = (attempt + i) % e;
        return true;
      }
    attempt %= e;
    return false;
  }
  virtual bool canDownload() {return true;}
  virtual bool canUpload() {return true;}
  virtual bool download(const char *hex_hash, std::function<bool(const char *data, size_t data_length)> cb, std::string &err, bool allow_midpull_switch)
  {
    extern void blob_progress_add_bytes(int id, uint64_t sz);
    extern bool blob_progress_should_switch(int id);
    extern void blob_progress_penalize_source(int id);
    if (blob_progress_should_switch(id))
      reconnectEx(true);//we are on a slow source: prefer the fastest known one
    else
      start();
    bool ok = true, switching = false;
    int64_t pulled = blob_pull_from_server(client, HASH_TYPE_REV_STRING, hex_hash, 0, 0, [&](const char *data, uint64_t , uint64_t size)
    {
       if (data && ok)//that's hint of size
       {
         blob_progress_add_bytes(id, size);
         //abort mid-blob too, or one huge blob would pin us to the slow source till the end.
         //the pull protocol can only be aborted by closing the socket
         if (allow_midpull_switch && !switching && blob_progress_should_switch(id))
         {
           switching = true; ok = false;
           expect_socket_abort = true;//the read errors that follow are intended, don't report them
           stop_blob_push_client(client);
         }
         else
           ok = cb(data, size);
       }
    });
    if (switching)
    {
      expect_socket_abort = false;
      err = blob_slow_switch_err;//caller reconnects (to the next source) and retries
      return false;
    }
    if (pulled == 0)
    {
      err = "No blob ";
      err += hex_hash;
      return false;
    }
    if (pulled < 0)
    {
      err = "Error reading data ";
      err += hex_hash;
      ++failStreak;
      blob_progress_penalize_source(id);//don't let a stale speed record keep sending us back here
      //no reconnect here - the caller does it (round robin, to a different source)
      return false;
    }
    if (!ok)
    {
      err = "Error writing data ";
      err += hex_hash;
      return false;
    }
    failStreak = 0;
    return true;
  }
  virtual bool upload(const char *file, bool compress, char *hex_hash, std::string &err) {
    start();
    if (!caddressed_fs::get_file_content_hash(file, hex_hash, 64))
      return false;

    int64_t sz = blob_size_on_server(client, HASH_TYPE_REV_STRING, hex_hash); //<-1 if error, -1 if missing
    if (sz < -1)
    {
      init();
      return false;
    }
    if (sz >= 0)//already on server
      return true;
    KVRet r = send_blob_file_data_net(client, file, hex_hash, compress, err);
    if (r == KVRet::Fatal)
      init();
    return r == KVRet::OK;
  }
  BlobSocket client;
  const UrlProvider& provider;
  int id = 0, attempt = 0;
  int failStreak = 0;//consecutive failed pulls: escalates the socket timeout
};

BlobNetworkProcessor *get_kv_processor(const UrlProvider& provider_, int id)
{
  return new KVNetworkProcessor(provider_, id);
}

#include <../keyValueServer/blob_push_log.h>
#include <stdarg.h>
void blob_logmessage(int log, const char *fmt,...)
{
  if (log < LOG_WARNING || expect_socket_abort)
    return;
  extern void blob_progress_clear_line();
  blob_progress_clear_line();//don't append to the progress line
  char buf[512];
  va_list va;
  va_start(va, fmt);
  vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);
  error(0, log, "%s", buf);
}

