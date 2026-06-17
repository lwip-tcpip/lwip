/**
 * @file udp_iperf_test.c
 * @brief Standalone iPerf2-compatible UDP test tool for Linux (Raspberry Pi / x86).
 *
 * This program implements the iPerf2 UDP protocol exactly as defined in our
 * lwiperf.c implementation. Use it on a Raspberry Pi (or any Linux machine)
 * to test against:
 *   - The embedded board running lwiperf UDP server/client
 *   - Standard iperf2 tool on x86
 *
 * Protocol (iPerf2 UDP):
 *   Each datagram has a 12-byte header:
 *     [0..3]  int32_t  id       — positive during test, negative for final pkt
 *     [4..7]  uint32_t tv_sec   — timestamp seconds
 *     [8..11] uint32_t tv_usec  — timestamp microseconds
 *   Final packet: id = -(sequence_number). Server sends back a 40-byte report.
 *
 * Build:
 *   gcc -O2 -o udp_iperf_test udp_iperf_test.c -lm
 *
 * Usage:
 *   Server: ./udp_iperf_test -s [-p port]
 *   Client: ./udp_iperf_test -c <server_ip> [-p port] [-b bandwidth] [-t seconds]
 *
 * Examples (Pi ←1G→ x86):
 *   Pi as server, x86 as client:
 *     Pi:  ./udp_iperf_test -s
 *     x86: iperf -u -c <pi_ip> -b 100M -t 10
 *
 *   Pi as client, board as server:
 *     Board: runs lwiperf_start_udp_server()
 *     Pi:    ./udp_iperf_test -c 192.168.1.100 -b 1M -t 10
 *
 * @author Arun Chhaganlal Suthar <arunsuthar98@gmail.com>
 */

#define _DEFAULT_SOURCE  /* usleep, getopt */
#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <math.h>

/*---------------------------------------------------------------------------
 * iPerf2 UDP protocol structures (must match lwiperf.c)
 *---------------------------------------------------------------------------*/

/** iPerf2 UDP datagram header (12 bytes, network byte order) */
typedef struct __attribute__((packed)) {
  int32_t  id;       /* positive = sequence number, negative = final packet */
  uint32_t tv_sec;   /* timestamp seconds */
  uint32_t tv_usec;  /* timestamp microseconds */
} iperf2_udp_hdr_t;

/** iPerf2 UDP server report (40 bytes, network byte order) */
typedef struct __attribute__((packed)) {
  int32_t  flags;          /* 0x80000000 = server report present */
  int32_t  total_len_hi;   /* total bytes transferred (high 32 bits) */
  int32_t  total_len_lo;   /* total bytes transferred (low 32 bits) */
  int32_t  stop_sec;       /* duration seconds */
  int32_t  stop_usec;      /* duration microseconds */
  int32_t  error_cnt;      /* number of lost datagrams */
  int32_t  out_of_order;   /* number of out-of-order datagrams */
  int32_t  datagrams;      /* total datagrams received */
  int32_t  jitter_sec;     /* jitter seconds */
  int32_t  jitter_usec;    /* jitter microseconds */
} iperf2_server_report_t;

/*---------------------------------------------------------------------------
 * Defaults
 *---------------------------------------------------------------------------*/

#define DEFAULT_PORT        5001
#define DEFAULT_DURATION_S  10
#define DEFAULT_BW_KBPS     1000    /* 1 Mbps */
#define DEFAULT_PKT_SIZE    1470    /* typical UDP payload for iPerf2 */
#define FINAL_PKT_RETRIES   10
#define REPORT_INTERVAL_S   1

/*---------------------------------------------------------------------------
 * Globals
 *---------------------------------------------------------------------------*/

static volatile int g_running = 1;

static void sigint_handler(int sig)
{
  (void)sig;
  g_running = 0;
}

static void get_timestamp(uint32_t *sec, uint32_t *usec)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  *sec = (uint32_t)tv.tv_sec;
  *usec = (uint32_t)tv.tv_usec;
}

static double timeval_diff_ms(struct timeval *start, struct timeval *end)
{
  double s = (double)(end->tv_sec - start->tv_sec) * 1000.0;
  double u = (double)(end->tv_usec - start->tv_usec) / 1000.0;
  return s + u;
}

/*---------------------------------------------------------------------------
 * UDP iPerf SERVER
 *---------------------------------------------------------------------------*/

static void run_server(uint16_t port)
{
  int sock;
  struct sockaddr_in addr, client_addr;
  socklen_t client_len = sizeof(client_addr);
  uint8_t buf[65536];
  ssize_t n;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    exit(1);
  }

  int reuse = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(sock);
    exit(1);
  }

  printf("------------------------------------------------------------\n");
  printf("UDP iPerf2 Server listening on port %u\n", port);
  printf("------------------------------------------------------------\n");

  signal(SIGINT, sigint_handler);

  while (g_running) {
    /* Wait for first packet from a new client session */
    struct timeval start_time, end_time, last_report;
    uint64_t total_bytes = 0;
    int32_t total_datagrams = 0;
    int32_t out_of_order = 0;
    int32_t expected_id = 1;
    int session_active = 0;

    printf("[Server] Waiting for client...\n");

    while (g_running) {
      n = recvfrom(sock, buf, sizeof(buf), 0,
                   (struct sockaddr *)&client_addr, &client_len);
      if (n < 0) {
        if (errno == EINTR) continue;
        perror("recvfrom");
        break;
      }

      if ((size_t)n < sizeof(iperf2_udp_hdr_t)) continue;

      iperf2_udp_hdr_t *hdr = (iperf2_udp_hdr_t *)buf;
      int32_t pkt_id = (int32_t)ntohl((uint32_t)hdr->id);

      if (!session_active) {
        /* First packet of session */
        gettimeofday(&start_time, NULL);
        last_report = start_time;
        session_active = 1;
        expected_id = 1;
        total_bytes = 0;
        total_datagrams = 0;
        out_of_order = 0;

        printf("[Server] Session from %s:%u\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
      }

      /* Check if this is the final packet (negative id) */
      if (pkt_id < 0) {
        gettimeofday(&end_time, NULL);
        total_datagrams++;
        total_bytes += (uint64_t)n;

        double duration_ms = timeval_diff_ms(&start_time, &end_time);
        double bw_kbps = 0;
        if (duration_ms > 0) {
          bw_kbps = (double)(total_bytes * 8) / duration_ms;
        }

        printf("[Server] Test complete:\n");
        printf("  Duration:    %.2f sec\n", duration_ms / 1000.0);
        printf("  Transferred: %.2f MB\n", (double)total_bytes / (1024.0 * 1024.0));
        printf("  Bandwidth:   %.2f Mbps\n", bw_kbps / 1000.0);
        printf("  Datagrams:   %d\n", total_datagrams);
        printf("  Out-of-order: %d\n", out_of_order);
        printf("  Lost:        %d (%.2f%%)\n",
               (int)((-pkt_id) - total_datagrams),
               total_datagrams > 0 ?
               100.0 * (double)((-pkt_id) - total_datagrams) / (double)(-pkt_id) : 0.0);

        /* Send server report back to client */
        iperf2_server_report_t report;
        memset(&report, 0, sizeof(report));
        report.flags = htonl(0x80000000u);
        report.total_len_hi = htonl((uint32_t)(total_bytes >> 32));
        report.total_len_lo = htonl((uint32_t)(total_bytes & 0xFFFFFFFF));
        uint32_t dur_sec = (uint32_t)(duration_ms / 1000.0);
        uint32_t dur_usec = (uint32_t)((duration_ms - dur_sec * 1000.0) * 1000.0);
        report.stop_sec = htonl(dur_sec);
        report.stop_usec = htonl(dur_usec);
        report.error_cnt = htonl((uint32_t)((-pkt_id) - total_datagrams));
        report.out_of_order = htonl((uint32_t)out_of_order);
        report.datagrams = htonl((uint32_t)total_datagrams);

        /* Build response: echo the final packet header + append report */
        uint8_t resp[sizeof(iperf2_udp_hdr_t) + sizeof(iperf2_server_report_t)];
        memcpy(resp, buf, sizeof(iperf2_udp_hdr_t));
        memcpy(resp + sizeof(iperf2_udp_hdr_t), &report, sizeof(report));

        sendto(sock, resp, sizeof(resp), 0,
               (struct sockaddr *)&client_addr, client_len);

        session_active = 0;
        printf("[Server] Report sent. Waiting for next client...\n");
        printf("------------------------------------------------------------\n");
        break;
      }

      /* Normal data packet */
      total_datagrams++;
      total_bytes += (uint64_t)n;

      if (pkt_id != expected_id) {
        if (pkt_id < expected_id) {
          out_of_order++;
        }
        /* else: lost packets (gap) */
      }
      expected_id = pkt_id + 1;

      /* Periodic report */
      struct timeval now;
      gettimeofday(&now, NULL);
      double since_report = timeval_diff_ms(&last_report, &now);
      if (since_report >= REPORT_INTERVAL_S * 1000.0) {
        double elapsed = timeval_diff_ms(&start_time, &now);
        double bw = (elapsed > 0) ? (double)(total_bytes * 8) / elapsed : 0;
        printf("[Server] %.1fs: %.2f MB, %.2f Mbps, %d pkts\n",
               elapsed / 1000.0,
               (double)total_bytes / (1024.0 * 1024.0),
               bw / 1000.0, total_datagrams);
        last_report = now;
      }
    }
  }

  close(sock);
  printf("[Server] Stopped.\n");
}

/*---------------------------------------------------------------------------
 * UDP iPerf CLIENT
 *---------------------------------------------------------------------------*/

static void run_client(const char *server_ip, uint16_t port,
                       uint32_t duration_s, uint32_t bw_kbps)
{
  int sock;
  struct sockaddr_in server_addr;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    exit(1);
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
    fprintf(stderr, "Invalid server IP: %s\n", server_ip);
    close(sock);
    exit(1);
  }

  /* Set receive timeout for final report */
  struct timeval tv;
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  signal(SIGINT, sigint_handler);

  printf("------------------------------------------------------------\n");
  printf("UDP iPerf2 Client sending to %s:%u\n", server_ip, port);
  printf("  Duration:  %u sec\n", duration_s);
  printf("  Bandwidth: ");
  if (bw_kbps >= 1000) {
    printf("%u Mbps\n", bw_kbps / 1000);
  } else {
    printf("%u Kbps\n", bw_kbps);
  }
  printf("  Pkt size:  %d bytes\n", DEFAULT_PKT_SIZE);
  printf("------------------------------------------------------------\n");

  /* Calculate inter-packet delay */
  uint32_t pkt_size = DEFAULT_PKT_SIZE;
  double bits_per_pkt = (double)pkt_size * 8.0;
  double pkts_per_sec = ((double)bw_kbps * 1000.0) / bits_per_pkt;
  double delay_us = (pkts_per_sec > 0) ? (1000000.0 / pkts_per_sec) : 1000.0;

  printf("[Client] Sending ~%.0f pkts/sec (%.1f us delay)\n", pkts_per_sec, delay_us);

  uint8_t pkt_buf[DEFAULT_PKT_SIZE];
  memset(pkt_buf, 0, sizeof(pkt_buf));

  /* Fill payload with pattern (like iperf2 does) */
  for (int i = sizeof(iperf2_udp_hdr_t); i < (int)pkt_size; i++) {
    pkt_buf[i] = (uint8_t)(i & 0xFF);
  }

  struct timeval start_time, now, last_report;
  gettimeofday(&start_time, NULL);
  last_report = start_time;

  int32_t seq = 1;
  uint64_t total_bytes = 0;
  uint32_t sec, usec;

  while (g_running) {
    gettimeofday(&now, NULL);
    double elapsed_ms = timeval_diff_ms(&start_time, &now);

    if (elapsed_ms >= (double)duration_s * 1000.0) {
      break;
    }

    /* Fill header */
    iperf2_udp_hdr_t *hdr = (iperf2_udp_hdr_t *)pkt_buf;
    get_timestamp(&sec, &usec);
    hdr->id = htonl((uint32_t)seq);
    hdr->tv_sec = htonl(sec);
    hdr->tv_usec = htonl(usec);

    ssize_t sent = sendto(sock, pkt_buf, pkt_size, 0,
                          (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (sent > 0) {
      total_bytes += (uint64_t)sent;
      seq++;
    }

    /* Periodic report */
    double since_report = timeval_diff_ms(&last_report, &now);
    if (since_report >= REPORT_INTERVAL_S * 1000.0) {
      double bw = (elapsed_ms > 0) ? (double)(total_bytes * 8) / elapsed_ms : 0;
      printf("[Client] %.1fs: %.2f MB sent, %.2f Mbps, %d pkts\n",
             elapsed_ms / 1000.0,
             (double)total_bytes / (1024.0 * 1024.0),
             bw / 1000.0, seq - 1);
      last_report = now;
    }

    /* Pacing delay */
    if (delay_us > 1.0) {
      usleep((unsigned int)delay_us);
    }
  }

  /* Send final packet (negative id) */
  printf("[Client] Sending final packet (id=-%d)...\n", seq);
  iperf2_udp_hdr_t *hdr = (iperf2_udp_hdr_t *)pkt_buf;
  get_timestamp(&sec, &usec);
  hdr->id = htonl((uint32_t)(-(seq)));
  hdr->tv_sec = htonl(sec);
  hdr->tv_usec = htonl(usec);

  /* Send final packet multiple times (in case of loss) */
  for (int retry = 0; retry < FINAL_PKT_RETRIES; retry++) {
    sendto(sock, pkt_buf, pkt_size, 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));

    /* Try to receive server report */
    uint8_t resp_buf[128];
    ssize_t rn = recvfrom(sock, resp_buf, sizeof(resp_buf), 0, NULL, NULL);
    if (rn >= (ssize_t)(sizeof(iperf2_udp_hdr_t) + sizeof(iperf2_server_report_t))) {
      iperf2_server_report_t *report =
          (iperf2_server_report_t *)(resp_buf + sizeof(iperf2_udp_hdr_t));

      uint32_t flags = ntohl((uint32_t)report->flags);
      if (flags & 0x80000000u) {
        uint64_t srv_bytes = ((uint64_t)ntohl((uint32_t)report->total_len_hi) << 32) |
                             (uint64_t)ntohl((uint32_t)report->total_len_lo);
        uint32_t dur_s = ntohl((uint32_t)report->stop_sec);
        uint32_t dur_us = ntohl((uint32_t)report->stop_usec);
        int32_t lost = (int32_t)ntohl((uint32_t)report->error_cnt);
        int32_t ooo = (int32_t)ntohl((uint32_t)report->out_of_order);
        int32_t dgrams = (int32_t)ntohl((uint32_t)report->datagrams);

        double srv_dur_ms = (double)dur_s * 1000.0 + (double)dur_us / 1000.0;
        double srv_bw = (srv_dur_ms > 0) ?
                        (double)(srv_bytes * 8) / srv_dur_ms : 0;

        printf("\n[Client] Server report received:\n");
        printf("  Duration:    %.2f sec\n", srv_dur_ms / 1000.0);
        printf("  Transferred: %.2f MB\n", (double)srv_bytes / (1024.0 * 1024.0));
        printf("  Bandwidth:   %.2f Mbps\n", srv_bw / 1000.0);
        printf("  Datagrams:   %d\n", dgrams);
        printf("  Lost:        %d (%.2f%%)\n", lost,
               dgrams > 0 ? 100.0 * (double)lost / (double)(dgrams + lost) : 0.0);
        printf("  Out-of-order: %d\n", ooo);
        break;
      }
    }

    usleep(100000); /* 100ms between retries */
  }

  /* Local summary */
  gettimeofday(&now, NULL);
  double total_ms = timeval_diff_ms(&start_time, &now);
  double final_bw = (total_ms > 0) ? (double)(total_bytes * 8) / total_ms : 0;

  printf("\n[Client] Local summary:\n");
  printf("  Duration:    %.2f sec\n", total_ms / 1000.0);
  printf("  Sent:        %.2f MB (%d datagrams)\n",
         (double)total_bytes / (1024.0 * 1024.0), seq - 1);
  printf("  Bandwidth:   %.2f Mbps\n", final_bw / 1000.0);
  printf("------------------------------------------------------------\n");

  close(sock);
}

/*---------------------------------------------------------------------------
 * Usage & main
 *---------------------------------------------------------------------------*/

static void print_usage(const char *prog)
{
  printf("iPerf2-compatible UDP Test Tool\n");
  printf("Implements the same protocol as lwiperf.c UDP mode.\n\n");
  printf("Usage:\n");
  printf("  %s -s [-p port]                          Server mode\n", prog);
  printf("  %s -c <ip> [-p port] [-b bw] [-t sec]   Client mode\n\n", prog);
  printf("Options:\n");
  printf("  -s           Run as UDP server\n");
  printf("  -c <ip>      Run as UDP client to <ip>\n");
  printf("  -p <port>    Port (default: %d)\n", DEFAULT_PORT);
  printf("  -t <sec>     Duration in seconds (default: %d)\n", DEFAULT_DURATION_S);
  printf("  -b <bw>      Target bandwidth (e.g. 1M, 100M, 500K) default: %dK\n",
         DEFAULT_BW_KBPS);
  printf("  -h           Show this help\n\n");
  printf("Examples:\n");
  printf("  Server:  %s -s\n", prog);
  printf("  Client:  %s -c 192.168.1.100 -b 100M -t 10\n", prog);
  printf("  Client:  %s -c 192.168.1.100 -b 500K -t 5\n\n", prog);
  printf("Test setup (Pi ←1G→ x86):\n");
  printf("  Pi server + x86 iperf client:\n");
  printf("    Pi:  %s -s\n", prog);
  printf("    x86: iperf -u -c <pi_ip> -b 100M -t 10\n\n");
  printf("  Pi client + board server (lwiperf):\n");
  printf("    Board: lwiperf_start_udp_server() running\n");
  printf("    Pi:    %s -c <board_ip> -b 1M -t 10\n", prog);
}

static uint32_t parse_bandwidth(const char *str)
{
  double val = atof(str);
  size_t len = strlen(str);

  if (len == 0) return DEFAULT_BW_KBPS;

  char suffix = str[len - 1];
  switch (suffix) {
    case 'G': case 'g': return (uint32_t)(val * 1000000.0);
    case 'M': case 'm': return (uint32_t)(val * 1000.0);
    case 'K': case 'k': return (uint32_t)(val);
    default:            return (uint32_t)(val / 1000.0); /* assume bps */
  }
}

int main(int argc, char *argv[])
{
  int mode = 0; /* 0=none, 1=server, 2=client */
  const char *server_ip = NULL;
  uint16_t port = DEFAULT_PORT;
  uint32_t duration_s = DEFAULT_DURATION_S;
  uint32_t bw_kbps = DEFAULT_BW_KBPS;

  int opt;
  while ((opt = getopt(argc, argv, "sc:p:t:b:h")) != -1) {
    switch (opt) {
      case 's':
        mode = 1;
        break;
      case 'c':
        mode = 2;
        server_ip = optarg;
        break;
      case 'p':
        port = (uint16_t)atoi(optarg);
        break;
      case 't':
        duration_s = (uint32_t)atoi(optarg);
        break;
      case 'b':
        bw_kbps = parse_bandwidth(optarg);
        break;
      case 'h':
      default:
        print_usage(argv[0]);
        return 0;
    }
  }

  if (mode == 0) {
    print_usage(argv[0]);
    return 1;
  }

  printf("============================================================\n");
  printf(" UDP iPerf2 Test Tool (lwiperf-compatible)\n");
  printf("============================================================\n");

  if (mode == 1) {
    run_server(port);
  } else {
    run_client(server_ip, port, duration_s, bw_kbps);
  }

  return 0;
}
