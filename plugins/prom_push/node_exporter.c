/* 
* Prometheus Node Exporter implemented in C, which reads system
* metrics from /proc and outputs them in Prometheus text format.
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/statvfs.h>
#include <sys/socket.h>

#define USER_HZ 100

/* --- (Host/IP) --- */
void print_node_info() {
    char hostname[256] = "unknown";
    char ip[64] = "127.0.0.1";
    gethostname(hostname, sizeof(hostname));

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
                inet_ntop(AF_INET, &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr), ip, sizeof(ip));
                break;
            }
        }
        freeifaddrs(ifaddr);
    }
    printf("node_info{hostname=\"%s\",ip=\"%s\"} 1\n", hostname, ip);
}

/* --- (Load Average) --- */
void print_loadavg() {
    FILE *fp = fopen("/proc/loadavg", "r");
    if (!fp) return;
    double l1, l5, l15;
    if (fscanf(fp, "%lf %lf %lf", &l1, &l5, &l15) == 3) {
        printf("node_load1 %.2f\nnode_load5 %.2f\nnode_load15 %.2f\n", l1, l5, l15);
    }
    fclose(fp);
}

/* --- (CPU) --- */
void print_cpu() {
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    long ticks = sysconf(_SC_CLK_TCK);
    printf("node_cpu_count %ld\n", num_cpus);
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return;
    char line[256];
    unsigned long long u, n, s, i, iw, irq, sirq, st;
    /* We only read the first line, which begins with “cpu ” (aggregate across all cores) */
    if (fgets(line, sizeof(line), fp) && strncmp(line, "cpu ", 4) == 0) {
        /* read: user, nice, system, idle, iowait, irq, softirq, steal */
        int matched = sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", 
                             &u, &n, &s, &i, &iw, &irq, &sirq, &st);
        if (matched >= 4) {
            double t = (double)ticks;
            /* Add the tag `cpu=“total”` for compatibility with Grafana */
            printf("node_cpu_seconds_total{cpu=\"total\",mode=\"user\"} %.2f\n", (double)u/t);
            printf("node_cpu_seconds_total{cpu=\"total\",mode=\"nice\"} %.2f\n", (double)n/t);
            printf("node_cpu_seconds_total{cpu=\"total\",mode=\"system\"} %.2f\n", (double)s/t);
            printf("node_cpu_seconds_total{cpu=\"total\",mode=\"idle\"} %.2f\n", (double)i/t);
            printf("node_cpu_seconds_total{cpu=\"total\",mode=\"iowait\"} %.2f\n", (double)iw/t);
            printf("node_cpu_seconds_total{cpu=\"total\",mode=\"irq\"} %.2f\n", (double)irq/t);
            printf("node_cpu_seconds_total{cpu=\"total\",mode=\"softirq\"} %.2f\n", (double)sirq/t);
            printf("node_cpu_seconds_total{cpu=\"total\",mode=\"steal\"} %.2f\n", (double)st/t);
        }
    }
    fclose(fp);
}

/* --- Ram & Swap --- */
void print_memory() {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return;
    char line[256], key[64];
    long long val;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%[^:]: %lld", key, &val) == 2) {
            if (strcmp(key, "MemTotal") == 0) printf("node_memory_MemTotal_bytes %lld\n", val * 1024);
            if (strcmp(key, "MemAvailable") == 0) printf("node_memory_MemAvailable_bytes %lld\n", val * 1024);
            if (strcmp(key, "SwapTotal") == 0) printf("node_memory_SwapTotal_bytes %lld\n", val * 1024);
            if (strcmp(key, "SwapFree") == 0) printf("node_memory_SwapFree_bytes %lld\n", val * 1024);
        }
    }
    fclose(fp);
}

/* --- Disk Space (Size and Usage) --- */
void print_disk_usage() {
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp) return;
    char line[512], dev[128], mount[128], type[64];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%s %s %s", dev, mount, type) == 3) {
            if (dev[0] != '/' || strstr(type, "tmpfs") || strstr(type, "devtmpfs")) continue;
            struct statvfs vfs;
            if (statvfs(mount, &vfs) == 0) {
                unsigned long long total = (unsigned long long)vfs.f_blocks * vfs.f_frsize;
                unsigned long long free = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
                printf("node_filesystem_size_bytes{device=\"%s\",mountpoint=\"%s\"} %llu\n", dev, mount, total);
                printf("node_filesystem_avail_bytes{device=\"%s\",mountpoint=\"%s\"} %llu\n", dev, mount, free);
                printf("node_filesystem_used_bytes{device=\"%s\",mountpoint=\"%s\"} %llu\n", dev, mount, total - free);
            }
        }
    }
    fclose(fp);
}

/* --- Disk I/O (Disk Load) --- */
void print_disk_io() {
    FILE *fp = fopen("/proc/diskstats", "r");
    if (!fp) return;
    char line[256], name[64];
    unsigned long r_s, w_s, io_ms;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%*d %*d %s %*u %*u %lu %*u %*u %*u %lu %*u %*u %*u %lu", name, &r_s, &w_s, &io_ms) == 4) {
            if (strstr(name, "loop") || strstr(name, "ram")) continue;
            printf("node_disk_read_bytes_total{device=\"%s\"} %lu\n", name, r_s * 512);
            printf("node_disk_written_bytes_total{device=\"%s\"} %lu\n", name, w_s * 512);
            printf("node_disk_io_time_seconds_total{device=\"%s\"} %.3f\n", name, (double)io_ms/1000.0);
        }
    }
    fclose(fp);
}

/* --- (Traffic RX/TX) --- */
void print_network() {
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) return;
    char line[256];
    fgets(line, sizeof(line), fp);
    fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp)) {
        char iface[32];
        unsigned long long rb, rp, tb, tp;
        /* format: interface: rx_bytes rx_packets ... tx_bytes tx_packets */
        char *ptr = strchr(line, ':');
        if (!ptr) continue;
        *ptr = ' ';
        if (sscanf(line, "%s %llu %llu %*u %*u %*u %*u %*u %*u %llu %llu", iface, &rb, &rp, &tb, &tp) == 5) {
            if (strcmp(iface, "lo") == 0) continue;
            printf("node_network_receive_bytes_total{device=\"%s\"} %llu\n", iface, rb);
            printf("node_network_receive_packets_total{device=\"%s\"} %llu\n", iface, rp);
            printf("node_network_transmit_bytes_total{device=\"%s\"} %llu\n", iface, tb);
            printf("node_network_transmit_packets_total{device=\"%s\"} %llu\n", iface, tp);
        }
    }
    fclose(fp);
}

int main() {
    print_node_info();
    print_loadavg();
    print_cpu();
    print_memory();
    print_disk_usage();
    print_disk_io();
    print_network();
    return 0;
}
