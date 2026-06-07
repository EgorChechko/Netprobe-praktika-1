#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <math.h>
#include <getopt.h>
#include <sqlite3.h>
#include <syslog.h>

/* ---------- Константы ---------- */
#define MAX_THREADS      128
#define MAX_RESULTS      65536
#define MAX_JOBS         65536
#define DEFAULT_TIMEOUT  2000      /* мс */
#define ICMP_PAYLOAD     56
#define BANNER_BUF_SIZE  512
#define MAX_PORTS        1024

/* ---------- Типы ---------- */
typedef enum { JOB_TCP, JOB_UDP, JOB_ICMP, JOB_STOP = -1 } job_type_t;

typedef struct {
    uint32_t ip;
    int port;
    job_type_t type;
} job_t;

typedef struct {
    uint32_t ip;
    int port;
    job_type_t type;
    int state;              /* 0 – открыт/доступен, -1 – закрыт, -2 – таймаут, -3 – ошибка */
    double rtt_ms;
    char banner[BANNER_BUF_SIZE];
    char service[64];
} probe_result_t;

/* ---------- Очередь заданий ---------- */
typedef struct {
    job_t *jobs;
    int capacity;
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
} job_queue_t;

/* ---------- Глобальные настройки ---------- */
static int opt_timeout_ms = DEFAULT_TIMEOUT;
static int opt_threads = 4;
static int opt_banner = 0;
static int opt_json = 0;
static int opt_color = 0;
static int opt_service_detect = 0;
static char *opt_html_file = NULL;
static int do_tcp = 0;
static int do_udp = 0;
static int do_icmp = 0;
static int tcp_ports[MAX_PORTS];
static int udp_ports[MAX_PORTS];
static int tcp_port_count = 0;
static int udp_port_count = 0;

/* Демон / периодические сканы / БД / уведомления */
static int opt_interval = 0;
static int opt_daemon = 0;
static char *opt_pidfile = NULL;
static char *opt_logfile = NULL;
static char *opt_db = NULL;
static int opt_notify = 0;
static int opt_syslog = 0;

static volatile sig_atomic_t keep_running = 1;
static probe_result_t *prev_results = NULL;
static int prev_result_count = 0;
static pthread_mutex_t prev_lock = PTHREAD_MUTEX_INITIALIZER;

static sqlite3 *db = NULL;

/* Результаты текущего сканирования */
static probe_result_t results[MAX_RESULTS];
static int result_count = 0;
static pthread_mutex_t result_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------- Сигнатуры сервисов ---------- */
typedef struct {
    const char *signature;
    const char *service_name;
} service_sig_t;

static service_sig_t service_table[] = {
    {"SSH-2.0-OpenSSH", "OpenSSH"},
    {"SSH-2.0", "SSH (generic)"},
    {"HTTP/1.", "HTTP"},
    {"HTTP/2.", "HTTP/2"},
    {"PostgreSQL", "PostgreSQL"},
    {"MySQL", "MySQL"},
    {"MariaDB", "MariaDB"},
    {"Redis", "Redis"},
    {"MongoDB", "MongoDB"},
    {"AMQP", "RabbitMQ / AMQP"},
    {"Nginx", "Nginx"},
    {"Apache", "Apache"},
    {"Microsoft-IIS", "IIS"},
    {"FTP", "FTP"},
    {"220 ", "FTP (ready)"},
    {"220-", "FTP (ready)"},
    {"SMTP", "SMTP"},
    {"POP3", "POP3"},
    {"IMAP", "IMAP"},
    {"RTSP", "RTSP"},
    {"Telnet", "Telnet"},
    {"SSH", "SSH"},
    {NULL, NULL}
};

/* ---------- Прототипы функций ---------- */
void do_tcp_probe(uint32_t ip, int port, int timeout_ms, probe_result_t *res);
void do_icmp_probe(uint32_t ip, int timeout_ms, probe_result_t *res);
void do_udp_probe(uint32_t ip, int port, int timeout_ms, probe_result_t *res);
int cidr_to_ips(const char *cidr, uint32_t *ip_list, int max);
void parse_ports(const char *arg, int *ports, int *count);
void job_queue_init(job_queue_t *q, int cap);
int job_queue_push(job_queue_t *q, job_t job);
int job_queue_pop(job_queue_t *q, job_t *job);
void job_queue_destroy(job_queue_t *q);
void* worker(void *arg);
int cmp_result(const void *a, const void *b);
void print_results(void);
void print_json(void);
void print_json_to_file(FILE *f);
void generate_html_report(const char *filename);
void detect_service(probe_result_t *res);
void daemonize(void);
void write_pidfile(void);
void signal_handler(int sig);
void init_db(void);
void save_to_db(probe_result_t *results, int count, time_t ts);
int load_last_scan(probe_result_t **res, int *count);
void send_notification(const char *msg);
void compare_and_notify(probe_result_t *new_res, int new_count);
void save_previous_results(probe_result_t *res, int count);
void perform_scan(void);
void show_help(const char *prog);

/* ---------- Реализация очереди ---------- */
void job_queue_init(job_queue_t *q, int cap) {
    q->jobs = malloc(cap * sizeof(job_t));
    q->capacity = cap;
    q->head = q->tail = q->count = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
}

int job_queue_push(job_queue_t *q, job_t job) {
    pthread_mutex_lock(&q->lock);
    if (q->count >= q->capacity) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    q->jobs[q->tail] = job;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

int job_queue_pop(job_queue_t *q, job_t *job) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0) {
        pthread_cond_wait(&q->not_empty, &q->lock);
    }
    *job = q->jobs[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->count--;
    pthread_mutex_unlock(&q->lock);
    return 0;
}

void job_queue_destroy(job_queue_t *q) {
    free(q->jobs);
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
}

/* ---------- CIDR ---------- */
int cidr_to_ips(const char *cidr, uint32_t *ip_list, int max) {
    char ip_str[16];
    int prefix;
    if (sscanf(cidr, "%15[^/]/%d", ip_str, &prefix) != 2) return 0;
    if (prefix < 0 || prefix > 32) return 0;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return 0;
    uint32_t net = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    uint32_t network = net & mask;
    uint32_t broadcast = network | ~mask;
    int count = 0;
    for (uint32_t ip = network; ip <= broadcast && count < max; ip++) {
        ip_list[count++] = htonl(ip);
    }
    return count;
}

/* ---------- Порты ---------- */
void parse_ports(const char *arg, int *ports, int *count) {
    char *tmp = strdup(arg);
    char *token = strtok(tmp, ",");
    while (token != NULL && *count < MAX_PORTS) {
        char *dash = strchr(token, '-');
        if (dash) {
            int start = atoi(token);
            int end = atoi(dash + 1);
            if (start > 0 && end <= 65535 && start <= end) {
                for (int p = start; p <= end && *count < MAX_PORTS; p++) {
                    ports[(*count)++] = p;
                }
            }
        } else {
            int p = atoi(token);
            if (p > 0 && p <= 65535) {
                ports[(*count)++] = p;
            }
        }
        token = strtok(NULL, ",");
    }
    free(tmp);
}

/* ---------- Определение сервиса ---------- */
void detect_service(probe_result_t *res) {
    if (!opt_service_detect || res->state != 0 || res->type != JOB_TCP || res->banner[0] == '\0') {
        strcpy(res->service, "unknown");
        return;
    }
    for (int i = 0; service_table[i].signature != NULL; i++) {
        if (strstr(res->banner, service_table[i].signature) != NULL) {
            strncpy(res->service, service_table[i].service_name, sizeof(res->service)-1);
            res->service[sizeof(res->service)-1] = '\0';
            return;
        }
    }
    strcpy(res->service, "unknown");
}

/* ---------- TCP ---------- */
void do_tcp_probe(uint32_t ip, int port, int timeout_ms, probe_result_t *res) {
    res->ip = ip;
    res->port = port;
    res->type = JOB_TCP;
    res->banner[0] = '\0';
    res->rtt_ms = 0.0;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ip;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { res->state = -3; detect_service(res); return; }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    int ret = connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    if (ret == 0) {
        gettimeofday(&t2, NULL);
        res->rtt_ms = (t2.tv_sec - t1.tv_sec)*1000.0 + (t2.tv_usec - t1.tv_usec)/1000.0;
        res->state = 0;
    } else if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
        if (errno == ECONNREFUSED) res->state = -1;
        else res->state = -3;
        close(sock);
        detect_service(res);
        return;
    } else {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(sock, &wset);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int sel = select(sock+1, NULL, &wset, NULL, &tv);
        if (sel <= 0) {
            res->state = (sel == 0) ? -2 : -3;
            close(sock);
            detect_service(res);
            return;
        }
        int so_err = 0;
        socklen_t len = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &len);
        if (so_err != 0) {
            if (so_err == ECONNREFUSED) res->state = -1;
            else res->state = -3;
            close(sock);
            detect_service(res);
            return;
        }
        gettimeofday(&t2, NULL);
        res->rtt_ms = (t2.tv_sec - t1.tv_sec)*1000.0 + (t2.tv_usec - t1.tv_usec)/1000.0;
        res->state = 0;
    }

    if (res->state == 0 && opt_banner) {
        send(sock, "\r\n", 2, 0);
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(sock, &rset);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        if (select(sock+1, &rset, NULL, NULL, &tv) > 0) {
            int n = recv(sock, res->banner, BANNER_BUF_SIZE-1, 0);
            if (n > 0) {
                res->banner[n] = '\0';
                for (int i = 0; i < n; i++)
                    if (res->banner[i] == '\r' || res->banner[i] == '\n')
                        res->banner[i] = ' ';
            }
        }
    }
    close(sock);
    detect_service(res);
}

/* ---------- ICMP ---------- */
unsigned short icmp_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

void do_icmp_probe(uint32_t ip, int timeout_ms, probe_result_t *res) {
    res->ip = ip;
    res->port = 0;
    res->type = JOB_ICMP;
    res->banner[0] = '\0';
    res->rtt_ms = 0.0;
    strcpy(res->service, "ICMP Echo");

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { res->state = -3; return; }

    struct timeval tv_timeout;
    tv_timeout.tv_sec = timeout_ms / 1000;
    tv_timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip;

    char packet[sizeof(struct icmphdr) + ICMP_PAYLOAD];
    struct icmphdr *icmp = (struct icmphdr*)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid());
    icmp->un.echo.sequence = htons(1);
    memset(packet + sizeof(struct icmphdr), 0xAA, ICMP_PAYLOAD);
    icmp->checksum = 0;
    icmp->checksum = icmp_checksum(packet, sizeof(packet));

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&dest, sizeof(dest)) <= 0) {
        close(sock);
        res->state = -3;
        return;
    }

    char recv_buf[1024];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t len = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from, &from_len);
    gettimeofday(&t2, NULL);
    close(sock);

    if (len < 0) {
        res->state = (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : -3;
        return;
    }
    struct iphdr *ip_hdr = (struct iphdr*)recv_buf;
    int ip_hdr_len = ip_hdr->ihl * 4;
    struct icmphdr *icmp_reply = (struct icmphdr*)(recv_buf + ip_hdr_len);
    if (icmp_reply->type == ICMP_ECHOREPLY && icmp_reply->un.echo.id == htons(getpid())) {
        res->state = 0;
        res->rtt_ms = (t2.tv_sec - t1.tv_sec)*1000.0 + (t2.tv_usec - t1.tv_usec)/1000.0;
    } else {
        res->state = -3;
    }
}

/* ---------- UDP ---------- */
void do_udp_probe(uint32_t ip, int port, int timeout_ms, probe_result_t *res) {
    res->ip = ip;
    res->port = port;
    res->type = JOB_UDP;
    res->banner[0] = '\0';
    res->rtt_ms = 0.0;
    strcpy(res->service, "UDP");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { res->state = -3; return; }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = ip;

    char dummy = 0;
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    if (sendto(sock, &dummy, 1, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        close(sock);
        res->state = -3;
        return;
    }

    char buf[64];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &from_len);
    gettimeofday(&t2, NULL);
    close(sock);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) res->state = -2;
        else if (errno == ECONNREFUSED) res->state = -1;
        else res->state = -3;
    } else {
        res->state = 0;
        res->rtt_ms = (t2.tv_sec - t1.tv_sec)*1000.0 + (t2.tv_usec - t1.tv_usec)/1000.0;
    }
}

/* ---------- Рабочий поток ---------- */
void* worker(void *arg) {
    job_queue_t *q = (job_queue_t*)arg;
    probe_result_t res;
    while (1) {
        job_t job;
        job_queue_pop(q, &job);
        if (job.type == JOB_STOP) break;
        memset(&res, 0, sizeof(res));
        switch (job.type) {
            case JOB_TCP: do_tcp_probe(job.ip, job.port, opt_timeout_ms, &res); break;
            case JOB_UDP: do_udp_probe(job.ip, job.port, opt_timeout_ms, &res); break;
            case JOB_ICMP: do_icmp_probe(job.ip, opt_timeout_ms, &res); break;
            default: break;
        }
        pthread_mutex_lock(&result_lock);
        if (result_count < MAX_RESULTS) {
            results[result_count++] = res;
        }
        pthread_mutex_unlock(&result_lock);
    }
    return NULL;
}

/* ---------- Сортировка ---------- */
int cmp_result(const void *a, const void *b) {
    const probe_result_t *ra = (const probe_result_t*)a;
    const probe_result_t *rb = (const probe_result_t*)b;
    if (ra->ip != rb->ip) return (ra->ip < rb->ip) ? -1 : 1;
    if (ra->type != rb->type) return (ra->type - rb->type);
    return (ra->port - rb->port);
}

/* ---------- Текстовый вывод ---------- */
void print_results(void) {
    for (int i = 0; i < result_count; i++) {
        probe_result_t *r = &results[i];
        struct in_addr addr; addr.s_addr = r->ip;
        char ip_str[16]; strcpy(ip_str, inet_ntoa(addr));

        const char *color_open = "", *color_closed = "", *color_timeout = "", *color_error = "", *color_reset = "";
        if (opt_color) {
            color_reset = "\033[0m";
            color_open = "\033[32m";
            color_closed = "\033[90m";
            color_timeout = "\033[33m";
            color_error = "\033[31m";
        }

        const char *state_str;
        const char *color;
        if (r->state == 0) { state_str = "OPEN/UP"; color = color_open; }
        else if (r->state == -1) { state_str = "CLOSED"; color = color_closed; }
        else if (r->state == -2) { state_str = "TIMEOUT"; color = color_timeout; }
        else { state_str = "ERROR"; color = color_error; }

        if (r->type == JOB_ICMP) {
            printf("%-15s ICMP  %s%s%s", ip_str, color, state_str, color_reset);
            if (r->state == 0) printf(" %.2f ms", r->rtt_ms);
        } else if (r->type == JOB_TCP) {
            printf("%-15s TCP/%-5d %s%s%s", ip_str, r->port, color, state_str, color_reset);
            if (r->state == 0) printf(" %.2f ms", r->rtt_ms);
            if (opt_service_detect && r->service[0]) printf(" [%s]", r->service);
            if (opt_banner && r->banner[0]) printf(" \"%s\"", r->banner);
        } else {
            printf("%-15s UDP/%-5d %s%s%s", ip_str, r->port, color, state_str, color_reset);
            if (r->state == 0) printf(" %.2f ms", r->rtt_ms);
        }
        printf("\n");
    }
}

/* ---------- JSON вывод ---------- */
void print_json(void) {
    printf("[\n");
    for (int i = 0; i < result_count; i++) {
        probe_result_t *r = &results[i];
        struct in_addr addr; addr.s_addr = r->ip;
        char ip_str[16]; strcpy(ip_str, inet_ntoa(addr));
        const char *type_str = (r->type == JOB_TCP) ? "tcp" : (r->type == JOB_UDP) ? "udp" : "icmp";
        const char *state_str;
        switch (r->state) {
            case 0:  state_str = "open"; break;
            case -1: state_str = "closed"; break;
            case -2: state_str = "timeout"; break;
            default: state_str = "error";
        }
        printf("  {\n    \"ip\": \"%s\",\n", ip_str);
        if (r->type != JOB_ICMP) printf("    \"port\": %d,\n", r->port);
        printf("    \"type\": \"%s\",\n    \"state\": \"%s\",\n", type_str, state_str);
        if (r->state == 0) printf("    \"rtt_ms\": %.2f,\n", r->rtt_ms);
        if (opt_service_detect && r->service[0]) printf("    \"service\": \"%s\",\n", r->service);
        if (opt_banner && r->type == JOB_TCP && r->banner[0]) printf("    \"banner\": \"%s\",\n", r->banner);
        printf("  }%s\n", (i == result_count-1) ? "" : ",");
    }
    printf("]\n");
}

void print_json_to_file(FILE *f) {
    fprintf(f, "[\n");
    for (int i = 0; i < result_count; i++) {
        probe_result_t *r = &results[i];
        struct in_addr addr; addr.s_addr = r->ip;
        char ip_str[16]; strcpy(ip_str, inet_ntoa(addr));
        const char *type_str = (r->type == JOB_TCP) ? "tcp" : (r->type == JOB_UDP) ? "udp" : "icmp";
        const char *state_str;
        switch (r->state) {
            case 0:  state_str = "open"; break;
            case -1: state_str = "closed"; break;
            case -2: state_str = "timeout"; break;
            default: state_str = "error";
        }
        fprintf(f, "  {\n    \"ip\": \"%s\",\n", ip_str);
        if (r->type != JOB_ICMP) fprintf(f, "    \"port\": %d,\n", r->port);
        fprintf(f, "    \"type\": \"%s\",\n    \"state\": \"%s\",\n", type_str, state_str);
        if (r->state == 0) fprintf(f, "    \"rtt_ms\": %.2f,\n", r->rtt_ms);
        if (opt_service_detect && r->service[0]) fprintf(f, "    \"service\": \"%s\",\n", r->service);
        if (opt_banner && r->type == JOB_TCP && r->banner[0]) fprintf(f, "    \"banner\": \"%s\",\n", r->banner);
        fprintf(f, "  }%s\n", (i == result_count-1) ? "" : ",");
    }
    fprintf(f, "]");
}

/* ---------- HTML отчёт ---------- */
void generate_html_report(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Cannot create HTML file: %s\n", filename);
        return;
    }
    double rtts[MAX_RESULTS];
    int rtt_count = 0;
    for (int i = 0; i < result_count; i++) {
        if (results[i].state == 0 && results[i].rtt_ms > 0 && results[i].rtt_ms < 10000) {
            rtts[rtt_count++] = results[i].rtt_ms;
        }
    }
    fprintf(f,
        "<!DOCTYPE html>\n<html>\n<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<title>NetProbe Report</title>\n"
        "<script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js\"></script>\n"
        "<style>\n"
        "body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }\n"
        "h1 { color: #2c3e50; }\n"
        "table { border-collapse: collapse; width: 100%%; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }\n"
        "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n"
        "th { background-color: #2c3e50; color: white; }\n"
        "tr:nth-child(even) { background-color: #f9f9f9; }\n"
        ".open { background-color: #d4edda; color: #155724; }\n"
        ".closed { background-color: #f8d7da; color: #721c24; }\n"
        ".timeout { background-color: #fff3cd; color: #856404; }\n"
        ".error { background-color: #e2e3e5; color: #383d41; }\n"
        ".chart-container { width: 80%%; margin: 20px auto; }\n"
        "</style>\n"
        "</head>\n<body>\n"
        "<h1>NetProbe Scan Report</h1>\n"
        "<p>Generated on %s</p>\n",
        ctime(&(time_t){time(NULL)})
    );
    fprintf(f, "<table>\n<tr><th>IP</th><th>Type</th><th>Port</th><th>State</th><th>RTT (ms)</th><th>Service</th><th>Banner</th></tr>\n");
    for (int i = 0; i < result_count; i++) {
        probe_result_t *r = &results[i];
        struct in_addr addr; addr.s_addr = r->ip;
        char ip_str[16]; strcpy(ip_str, inet_ntoa(addr));
        const char *type_str = (r->type == JOB_TCP) ? "TCP" : (r->type == JOB_UDP) ? "UDP" : "ICMP";
        const char *state_class, *state_disp;
        switch (r->state) {
            case 0:  state_class = "open"; state_disp = "OPEN/UP"; break;
            case -1: state_class = "closed"; state_disp = "CLOSED"; break;
            case -2: state_class = "timeout"; state_disp = "TIMEOUT"; break;
            default: state_class = "error"; state_disp = "ERROR";
        }
        fprintf(f, "<tr class=\"%s\">", state_class);
        fprintf(f, "</td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%.2f</td><td>%s</td><td>%s</td></tr>\n",
                ip_str, type_str, r->port, state_disp, r->rtt_ms,
                r->service[0] ? r->service : "-",
                r->banner[0] ? r->banner : "-");
    }
    fprintf(f, "</table>\n");
    if (rtt_count > 0) {
        fprintf(f, "<div class=\"chart-container\">\n<canvas id=\"rttChart\" width=\"800\" height=\"400\"></canvas>\n</div>\n");
        fprintf(f, "<script>\nconst ctx = document.getElementById('rttChart').getContext('2d');\n");
        fprintf(f, "const rttData = [");
        for (int i = 0; i < rtt_count; i++) {
            fprintf(f, "%.2f%s", rtts[i], (i+1 < rtt_count) ? "," : "");
        }
        fprintf(f, "];\n");
        fprintf(f, "new Chart(ctx, { type: 'scatter', data: { datasets: [{ label: 'RTT per probe', data: rttData.map((v,i)=>({x:i, y:v})), backgroundColor: 'rgba(54,162,235,0.6)', pointRadius: 3 }] }, options: { scales: { y: { title: { display: true, text: 'RTT (ms)' } }, x: { title: { display: true, text: 'Probe #' } } } } });\n");
        fprintf(f, "</script>\n");
    }
    fprintf(f, "</body>\n</html>\n");
    fclose(f);
    printf("HTML report saved to %s\n", filename);
}

/* ---------- Демонизация ---------- */
void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);
    setsid();
    pid = fork();
    if (pid < 0) { perror("fork2"); exit(1); }
    if (pid > 0) exit(0);
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}

/* ---------- PID файл ---------- */
void write_pidfile(void) {
    FILE *f = fopen(opt_pidfile, "w");
    if (f) { fprintf(f, "%d\n", getpid()); fclose(f); }
}

/* ---------- Обработчик сигналов ---------- */
void signal_handler(int sig) {
    keep_running = 0;
}

/* ---------- База данных SQLite ---------- */
void init_db(void) {
    if (sqlite3_open(opt_db, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    }
    const char *sql = "CREATE TABLE IF NOT EXISTS scans ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "timestamp INTEGER NOT NULL,"
                      "ip TEXT NOT NULL,"
                      "port INTEGER NOT NULL,"
                      "type TEXT NOT NULL,"
                      "state INTEGER NOT NULL,"
                      "rtt REAL,"
                      "service TEXT,"
                      "banner TEXT"
                      ");"
                      "CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp);";
    char *errmsg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        exit(1);
    }
}

void save_to_db(probe_result_t *res, int count, time_t ts) {
    if (!db) return;
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO scans (timestamp, ip, port, type, state, rtt, service, banner) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }
    for (int i = 0; i < count; i++) {
        probe_result_t *r = &res[i];
        struct in_addr addr; addr.s_addr = r->ip;
        char ip_str[16]; strcpy(ip_str, inet_ntoa(addr));
        const char *type_str = (r->type == JOB_TCP) ? "tcp" : (r->type == JOB_UDP) ? "udp" : "icmp";
        sqlite3_bind_int64(stmt, 1, ts);
        sqlite3_bind_text(stmt, 2, ip_str, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, r->port);
        sqlite3_bind_text(stmt, 4, type_str, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 5, r->state);
        sqlite3_bind_double(stmt, 6, r->rtt_ms);
        sqlite3_bind_text(stmt, 7, r->service, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, r->banner, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            fprintf(stderr, "Insert failed: %s\n", sqlite3_errmsg(db));
        }
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
}

int load_last_scan(probe_result_t **res, int *count) {
    if (!db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT MAX(timestamp) FROM scans;", -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    time_t last_ts = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        last_ts = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (last_ts == 0) return 0;

    const char *sql = "SELECT ip, port, type, state, rtt, service, banner FROM scans WHERE timestamp = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(stmt, 1, last_ts);
    *count = 0;
    *res = malloc(MAX_RESULTS * sizeof(probe_result_t));
    while (sqlite3_step(stmt) == SQLITE_ROW && *count < MAX_RESULTS) {
        probe_result_t *r = &(*res)[(*count)++];
        const char *ip_str = (const char*)sqlite3_column_text(stmt, 0);
        inet_pton(AF_INET, ip_str, &r->ip);
        r->port = sqlite3_column_int(stmt, 1);
        const char *type_str = (const char*)sqlite3_column_text(stmt, 2);
        if (strcmp(type_str, "tcp") == 0) r->type = JOB_TCP;
        else if (strcmp(type_str, "udp") == 0) r->type = JOB_UDP;
        else r->type = JOB_ICMP;
        r->state = sqlite3_column_int(stmt, 3);
        r->rtt_ms = sqlite3_column_double(stmt, 4);
        const char *serv = (const char*)sqlite3_column_text(stmt, 5);
        strncpy(r->service, serv ? serv : "", sizeof(r->service)-1);
        const char *bann = (const char*)sqlite3_column_text(stmt, 6);
        strncpy(r->banner, bann ? bann : "", sizeof(r->banner)-1);
    }
    sqlite3_finalize(stmt);
    return 1;
}

/* ---------- Уведомления ---------- */
void send_notification(const char *msg) {
    char time_str[64];
    time_t now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    if (opt_notify) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "notify-send -t 5000 'NetProbe Alert' '%s'", msg);
        system(cmd);
    }
    if (opt_syslog) {
        openlog("netprobe", LOG_PID, LOG_DAEMON);
        syslog(LOG_NOTICE, "%s", msg);
        closelog();
    }
    // можно также писать в отдельный файл, если нужно
}

void save_previous_results(probe_result_t *res, int count) {
    pthread_mutex_lock(&prev_lock);
    if (prev_results) {
        free(prev_results);
        prev_results = NULL;
    }
    prev_results = malloc(count * sizeof(probe_result_t));
    if (prev_results) {
        memcpy(prev_results, res, count * sizeof(probe_result_t));
        prev_result_count = count;
    }
    pthread_mutex_unlock(&prev_lock);
}

void compare_and_notify(probe_result_t *new_res, int new_count) {
    if (!prev_results || prev_result_count == 0) return;
    // Простой двойной цикл для сравнения (для демонстрации)
    for (int i = 0; i < new_count; i++) {
        probe_result_t *n = &new_res[i];
        int found = 0;
        for (int j = 0; j < prev_result_count; j++) {
            probe_result_t *p = &prev_results[j];
            if (n->ip == p->ip && n->port == p->port && n->type == p->type) {
                found = 1;
                if (n->state != p->state) {
                    char msg[512];
                    struct in_addr addr;
                    addr.s_addr = n->ip;
                    const char *state_old = (p->state == 0) ? "OPEN" : (p->state == -1) ? "CLOSED" : (p->state == -2) ? "TIMEOUT" : "ERROR";
                    const char *state_new = (n->state == 0) ? "OPEN" : (n->state == -1) ? "CLOSED" : (n->state == -2) ? "TIMEOUT" : "ERROR";
                    snprintf(msg, sizeof(msg), "CHANGE: %s %s/%d %s -> %s (service: %s)",
                             inet_ntoa(addr),
                             (n->type == JOB_TCP) ? "TCP" : (n->type == JOB_UDP) ? "UDP" : "ICMP",
                             n->port, state_old, state_new, n->service);
                    send_notification(msg);
                }
                break;
            }
        }
        if (!found) {
            char msg[256];
            struct in_addr addr;
            addr.s_addr = n->ip;
            snprintf(msg, sizeof(msg), "NEW: %s %s/%d %s (service: %s)",
                     inet_ntoa(addr),
                     (n->type == JOB_TCP) ? "TCP" : (n->type == JOB_UDP) ? "UDP" : "ICMP",
                     n->port,
                     (n->state == 0) ? "OPEN" : "UNKNOWN",
                     n->service);
            send_notification(msg);
        }
    }
    for (int j = 0; j < prev_result_count; j++) {
        probe_result_t *p = &prev_results[j];
        int found = 0;
        for (int i = 0; i < new_count; i++) {
            if (p->ip == new_res[i].ip && p->port == new_res[i].port && p->type == new_res[i].type) {
                found = 1;
                break;
            }
        }
        if (!found) {
            char msg[256];
            struct in_addr addr;
            addr.s_addr = p->ip;
            snprintf(msg, sizeof(msg), "GONE: %s %s/%d (was %s)",
                     inet_ntoa(addr),
                     (p->type == JOB_TCP) ? "TCP" : (p->type == JOB_UDP) ? "UDP" : "ICMP",
                     p->port,
                     (p->state == 0) ? "OPEN" : "CLOSED");
            send_notification(msg);
        }
    }
}

/* ---------- Основной цикл сканирования ---------- */
static char *target_cidr = NULL;

void perform_scan(void) {
    uint32_t ips[256];
    int ip_count = cidr_to_ips(target_cidr, ips, 256);
    if (ip_count == 0) {
        fprintf(stderr, "Invalid CIDR: %s\n", target_cidr);
        return;
    }
    job_queue_t queue;
    job_queue_init(&queue, MAX_JOBS);

    for (int i = 0; i < ip_count; i++) {
        uint32_t ip = ips[i];
        if (do_icmp) {
            job_t job = { .ip = ip, .port = 0, .type = JOB_ICMP };
            job_queue_push(&queue, job);
        }
        if (do_tcp) {
            for (int p = 0; p < tcp_port_count; p++) {
                job_t job = { .ip = ip, .port = tcp_ports[p], .type = JOB_TCP };
                job_queue_push(&queue, job);
            }
        }
        if (do_udp) {
            for (int p = 0; p < udp_port_count; p++) {
                job_t job = { .ip = ip, .port = udp_ports[p], .type = JOB_UDP };
                job_queue_push(&queue, job);
            }
        }
    }

    pthread_t tids[MAX_THREADS];
    for (int i = 0; i < opt_threads; i++) {
        pthread_create(&tids[i], NULL, worker, &queue);
    }
    for (int i = 0; i < opt_threads; i++) {
        job_t stop = { .type = JOB_STOP };
        job_queue_push(&queue, stop);
    }
    for (int i = 0; i < opt_threads; i++) {
        pthread_join(tids[i], NULL);
    }

    qsort(results, result_count, sizeof(probe_result_t), cmp_result);

    time_t now = time(NULL);
    if (opt_db) {
        save_to_db(results, result_count, now);
    }
    if (opt_interval > 0 && opt_notify) {
        compare_and_notify(results, result_count);
    }

    if (opt_logfile && !opt_daemon) { // для демона логирование через файл уже сделано
        FILE *log = fopen(opt_logfile, "a");
        if (log) {
            fprintf(log, "{\"timestamp\": %ld, \"results\": ", now);
            print_json_to_file(log);
            fprintf(log, "}\n");
            fclose(log);
        }
    }
    if (!opt_logfile || !opt_daemon) {
        if (opt_json) print_json();
        else print_results();
        if (opt_html_file) generate_html_report(opt_html_file);
    }

    save_previous_results(results, result_count);
    job_queue_destroy(&queue);
    result_count = 0;
}

/* ---------- Справка ---------- */
void show_help(const char *prog) {
    printf("Usage: %s <CIDR> [options]\n", prog);
    printf("Options:\n");
    printf("  --tcp                 Enable TCP scanning\n");
    printf("  --udp                 Enable UDP scanning\n");
    printf("  --icmp                Enable ICMP echo scanning\n");
    printf("  --banner              Retrieve TCP banners\n");
    printf("  --service-detect      Identify service from banner\n");
    printf("  -p, --ports LIST      Ports: 22,80,443 or 8000-8100\n");
    printf("  -t, --threads N       Worker threads (default 4, max %d)\n", MAX_THREADS);
    printf("  -T, --timeout MS      Timeout in milliseconds (default %d)\n", DEFAULT_TIMEOUT);
    printf("  -j, --json            Output in JSON format\n");
    printf("  --html FILE           Generate HTML report\n");
    printf("  --color               Colored output\n");
    printf("  --interval SEC        Periodic scan every SEC seconds\n");
    printf("  --daemon              Run as daemon (requires --interval)\n");
    printf("  --pidfile FILE        Write PID to file\n");
    printf("  --logfile FILE        Append JSON results to file\n");
    printf("  --db FILE             Use SQLite database for history\n");
    printf("  --notify              Send desktop notifications on changes (requires --db or --interval)\n");
    printf("  --syslog              Log notifications to syslog\n");
    printf("  -h, --help            Show this help\n");
    printf("\nIf no --tcp/--udp/--icmp given, default: --icmp and --tcp ports 22,80,443\n");
}

/* ---------- Главная ---------- */
int main(int argc, char *argv[]) {
    static struct option long_opts[] = {
        {"tcp",     no_argument,       0, 'c'},
        {"udp",     no_argument,       0, 'u'},
        {"icmp",    no_argument,       0, 'i'},
        {"banner",  no_argument,       0, 'b'},
        {"service-detect", no_argument, 0, 's'},
        {"ports",   required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"timeout", required_argument, 0, 'T'},
        {"json",    no_argument,       0, 'j'},
        {"html",    required_argument, 0, 'H'},
        {"color",   no_argument,       0, 'C'},
        {"interval", required_argument, 0, 'I'},
        {"daemon",  no_argument,       0, 'D'},
        {"pidfile", required_argument, 0, 'P'},
        {"logfile", required_argument, 0, 'L'},
        {"db",      required_argument, 0, 'B'},
        {"notify",  no_argument,       0, 'N'},
        {"syslog",  no_argument,       0, 'S'},
        {"help",    no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "p:t:T:jCh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'c': do_tcp = 1; break;
            case 'u': do_udp = 1; break;
            case 'i': do_icmp = 1; break;
            case 'b': opt_banner = 1; break;
            case 's': opt_service_detect = 1; break;
            case 'p': parse_ports(optarg, tcp_ports, &tcp_port_count);
                      if (udp_port_count == 0) {
                          for (int i = 0; i < tcp_port_count && udp_port_count < MAX_PORTS; i++)
                              udp_ports[udp_port_count++] = tcp_ports[i];
                      }
                      break;
            case 't': opt_threads = atoi(optarg);
                      if (opt_threads < 1) opt_threads = 1;
                      if (opt_threads > MAX_THREADS) opt_threads = MAX_THREADS;
                      break;
            case 'T': opt_timeout_ms = atoi(optarg);
                      if (opt_timeout_ms < 100) opt_timeout_ms = 100;
                      break;
            case 'j': opt_json = 1; break;
            case 'H': opt_html_file = optarg; break;
            case 'C': opt_color = 1; break;
            case 'I': opt_interval = atoi(optarg);
                      if (opt_interval < 1) opt_interval = 1;
                      break;
            case 'D': opt_daemon = 1; break;
            case 'P': opt_pidfile = optarg; break;
            case 'L': opt_logfile = optarg; break;
            case 'B': opt_db = optarg; break;
            case 'N': opt_notify = 1; break;
            case 'S': opt_syslog = 1; break;
            case 'h': show_help(argv[0]); return 0;
            default:  show_help(argv[0]); return 1;
        }
    }
    if (optind < argc) {
        target_cidr = argv[optind];
    } else {
        show_help(argv[0]);
        return 1;
    }

    if (!do_tcp && !do_udp && !do_icmp) {
        do_icmp = 1;
        do_tcp = 1;
        if (tcp_port_count == 0) {
            parse_ports("22,80,443", tcp_ports, &tcp_port_count);
            for (int i = 0; i < tcp_port_count && udp_port_count < MAX_PORTS; i++)
                udp_ports[udp_port_count++] = tcp_ports[i];
        }
    }
    if (do_tcp && tcp_port_count == 0) {
        parse_ports("22,80,443", tcp_ports, &tcp_port_count);
    }

    if (opt_db) init_db();
    if (opt_notify && opt_db) {
        load_last_scan(&prev_results, &prev_result_count);
    }

    if (opt_interval > 0) {
        if (opt_daemon) daemonize();
        if (opt_pidfile) write_pidfile();
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        while (keep_running) {
            perform_scan();
            if (!keep_running) break;
            sleep(opt_interval);
        }
        if (opt_pidfile) unlink(opt_pidfile);
        if (db) sqlite3_close(db);
        return 0;
    } else {
        perform_scan();
        if (db) sqlite3_close(db);
        return 0;
    }
}