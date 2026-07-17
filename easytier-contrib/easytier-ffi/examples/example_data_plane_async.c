#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_PLANE_OP_PENDING 0
#define DATA_PLANE_OP_READY 1
#define DATA_PLANE_OP_FAILED -1
#define DATA_PLANE_OP_INVALID -2

extern int run_network_instance(const char *cfg_str);
extern void get_error_msg(const char **out);
extern void free_string(const char *s);

extern int data_plane_async_op_status(uint64_t op);
extern int data_plane_async_op_wait(uint64_t op, uint64_t timeout_ms);
extern int data_plane_async_op_cancel(uint64_t op);
extern int data_plane_async_op_free(uint64_t op);
extern void data_plane_free_bytes(const uint8_t *ptr, uint32_t len);

extern uint64_t data_plane_tcp_connect_start(
    const char *inst_name,
    const char *dst_ip,
    uint16_t dst_port,
    uint64_t timeout_ms);
extern uint64_t data_plane_tcp_connect_finish(
    uint64_t op,
    const char **out_local_ip,
    uint16_t *out_local_port);
extern uint64_t data_plane_tcp_bind_start(
    const char *inst_name,
    uint16_t local_port,
    uint64_t timeout_ms);
extern uint64_t data_plane_tcp_bind_finish(
    uint64_t op,
    const char **out_local_ip,
    uint16_t *out_local_port);
extern uint64_t data_plane_tcp_accept_start(uint64_t listener, uint64_t timeout_ms);
extern uint64_t data_plane_tcp_accept_finish(
    uint64_t op,
    const char **out_local_ip,
    uint16_t *out_local_port,
    const char **out_peer_ip,
    uint16_t *out_peer_port);
extern uint64_t data_plane_tcp_read_start(
    uint64_t stream,
    uint32_t max_len,
    uint64_t timeout_ms);
extern int data_plane_tcp_read_finish(
    uint64_t op,
    const uint8_t **out_buf,
    uint32_t *out_len);
extern uint64_t data_plane_tcp_write_start(
    uint64_t stream,
    const uint8_t *buf,
    uint32_t len,
    uint64_t timeout_ms);
extern int data_plane_tcp_write_finish(uint64_t op);
extern int data_plane_tcp_close(uint64_t stream);
extern int data_plane_tcp_listener_close(uint64_t listener);

extern uint64_t data_plane_udp_bind_start(
    const char *inst_name,
    uint16_t local_port,
    uint64_t timeout_ms);
extern uint64_t data_plane_udp_bind_finish(
    uint64_t op,
    const char **out_local_ip,
    uint16_t *out_local_port);
extern uint64_t data_plane_udp_send_to_start(
    uint64_t socket,
    const char *dst_ip,
    uint16_t dst_port,
    const uint8_t *buf,
    uint32_t len,
    uint64_t timeout_ms);
extern int data_plane_udp_send_to_finish(uint64_t op);
extern uint64_t data_plane_udp_recv_from_start(
    uint64_t socket,
    uint32_t max_len,
    uint64_t timeout_ms);
extern int data_plane_udp_recv_from_finish(
    uint64_t op,
    const uint8_t **out_buf,
    uint32_t *out_len,
    const char **out_ip,
    uint16_t *out_port);
extern int data_plane_udp_close(uint64_t socket);

static void print_last_error(const char *prefix) {
    const char *err = NULL;
    get_error_msg(&err);
    if (err) {
        fprintf(stderr, "%s: %s\n", prefix, err);
        free_string(err);
    } else {
        fprintf(stderr, "%s\n", prefix);
    }
}

static int parse_ip_port(const char *value, char *ip, size_t ip_len, uint16_t *port) {
    const char *colon = strrchr(value, ':');
    if (!colon || colon == value || !colon[1]) {
        fprintf(stderr, "expected IPv4 target in IP:PORT form, got %s\n", value);
        return -1;
    }
    size_t host_len = (size_t)(colon - value);
    if (host_len >= ip_len) {
        fprintf(stderr, "IP address is too long: %s\n", value);
        return -1;
    }
    char *end = NULL;
    long parsed_port = strtol(colon + 1, &end, 10);
    if (!end || *end != '\0' || parsed_port < 0 || parsed_port > 65535) {
        fprintf(stderr, "invalid port in %s\n", value);
        return -1;
    }
    memcpy(ip, value, host_len);
    ip[host_len] = '\0';
    *port = (uint16_t)parsed_port;
    return 0;
}

static int wait_op(uint64_t op, uint64_t timeout_ms) {
    uint64_t waited = 0;
    while (waited < timeout_ms) {
        int status = data_plane_async_op_wait(op, 50);
        if (status != DATA_PLANE_OP_PENDING) {
            return status;
        }
        waited += 50;
    }
    return data_plane_async_op_status(op);
}

static int wait_or_cancel(uint64_t op, uint64_t timeout_ms, const char *what) {
    int status = wait_op(op, timeout_ms);
    if (status == DATA_PLANE_OP_READY || status == DATA_PLANE_OP_FAILED) {
        return status;
    }
    if (status == DATA_PLANE_OP_PENDING) {
        fprintf(stderr, "%s did not finish within %llu ms\n", what, (unsigned long long)timeout_ms);
        data_plane_async_op_cancel(op);
        data_plane_async_op_free(op);
        return DATA_PLANE_OP_INVALID;
    }
    fprintf(stderr, "%s returned invalid op status %d\n", what, status);
    return status;
}

static int async_tcp_read_once(uint64_t stream, uint64_t timeout_ms) {
    uint64_t op = data_plane_tcp_read_start(stream, 512, timeout_ms);
    if (!op) {
        print_last_error("tcp read start failed");
        return -1;
    }
    if (wait_or_cancel(op, timeout_ms + 1000, "tcp read") == DATA_PLANE_OP_INVALID) {
        return -1;
    }

    const uint8_t *buf = NULL;
    uint32_t len = 0;
    int ret = data_plane_tcp_read_finish(op, &buf, &len);
    if (ret < 0) {
        print_last_error("tcp read finish failed");
        return -1;
    }
    printf("tcp read %d bytes: %.*s\n", ret, ret, buf ? (const char *)buf : "");
    data_plane_free_bytes(buf, len);
    return 0;
}

static int async_tcp_write_all(uint64_t stream, const char *data, uint64_t timeout_ms) {
    uint64_t op = data_plane_tcp_write_start(
        stream,
        (const uint8_t *)data,
        (uint32_t)strlen(data),
        timeout_ms);
    if (!op) {
        print_last_error("tcp write start failed");
        return -1;
    }
    if (wait_or_cancel(op, timeout_ms + 1000, "tcp write") == DATA_PLANE_OP_INVALID) {
        return -1;
    }
    int ret = data_plane_tcp_write_finish(op);
    if (ret < 0) {
        print_last_error("tcp write finish failed");
        return -1;
    }
    printf("tcp wrote %d bytes\n", ret);
    return 0;
}

static int run_tcp_connect_demo(const char *inst, const char *target) {
    char ip[128];
    uint16_t port = 0;
    if (parse_ip_port(target, ip, sizeof(ip), &port) != 0) {
        return -1;
    }

    uint64_t op = data_plane_tcp_connect_start(inst, ip, port, 30000);
    if (!op) {
        print_last_error("tcp connect start failed");
        return -1;
    }
    if (wait_or_cancel(op, 31000, "tcp connect") == DATA_PLANE_OP_INVALID) {
        return -1;
    }

    const char *local_ip = NULL;
    uint16_t local_port = 0;
    uint64_t stream = data_plane_tcp_connect_finish(op, &local_ip, &local_port);
    if (!stream) {
        print_last_error("tcp connect finish failed");
        return -1;
    }
    printf("tcp connected from %s:%u to %s:%u, handle=%llu\n",
           local_ip,
           local_port,
           ip,
           port,
           (unsigned long long)stream);
    free_string(local_ip);

    int ret = async_tcp_read_once(stream, 10000);
    data_plane_tcp_close(stream);
    return ret;
}

static int run_tcp_listen_demo(const char *inst, const char *port_text) {
    uint16_t port = (uint16_t)strtoul(port_text, NULL, 10);
    uint64_t op = data_plane_tcp_bind_start(inst, port, 30000);
    if (!op) {
        print_last_error("tcp bind start failed");
        return -1;
    }
    if (wait_or_cancel(op, 31000, "tcp bind") == DATA_PLANE_OP_INVALID) {
        return -1;
    }

    const char *local_ip = NULL;
    uint16_t local_port = 0;
    uint64_t listener = data_plane_tcp_bind_finish(op, &local_ip, &local_port);
    if (!listener) {
        print_last_error("tcp bind finish failed");
        return -1;
    }
    printf("tcp listening on %s:%u, handle=%llu\n",
           local_ip,
           local_port,
           (unsigned long long)listener);
    free_string(local_ip);

    op = data_plane_tcp_accept_start(listener, 60000);
    if (!op) {
        print_last_error("tcp accept start failed");
        data_plane_tcp_listener_close(listener);
        return -1;
    }
    if (wait_or_cancel(op, 61000, "tcp accept") == DATA_PLANE_OP_INVALID) {
        data_plane_tcp_listener_close(listener);
        return -1;
    }

    const char *peer_ip = NULL;
    uint16_t peer_port = 0;
    local_ip = NULL;
    local_port = 0;
    uint64_t stream = data_plane_tcp_accept_finish(
        op,
        &local_ip,
        &local_port,
        &peer_ip,
        &peer_port);
    data_plane_tcp_listener_close(listener);
    if (!stream) {
        print_last_error("tcp accept finish failed");
        return -1;
    }
    printf("tcp accepted %s:%u -> %s:%u, stream=%llu\n",
           peer_ip,
           peer_port,
           local_ip,
           local_port,
           (unsigned long long)stream);
    free_string(local_ip);
    free_string(peer_ip);

    int ret = async_tcp_read_once(stream, 10000);
    if (ret == 0) {
        ret = async_tcp_write_all(stream, "pong", 10000);
    }
    data_plane_tcp_close(stream);
    return ret;
}

static int run_udp_demo(const char *inst, const char *target) {
    char ip[128];
    uint16_t port = 0;
    if (parse_ip_port(target, ip, sizeof(ip), &port) != 0) {
        return -1;
    }

    uint64_t op = data_plane_udp_bind_start(inst, 0, 30000);
    if (!op) {
        print_last_error("udp bind start failed");
        return -1;
    }
    if (wait_or_cancel(op, 31000, "udp bind") == DATA_PLANE_OP_INVALID) {
        return -1;
    }

    const char *local_ip = NULL;
    uint16_t local_port = 0;
    uint64_t socket = data_plane_udp_bind_finish(op, &local_ip, &local_port);
    if (!socket) {
        print_last_error("udp bind finish failed");
        return -1;
    }
    printf("udp bound on %s:%u, handle=%llu\n",
           local_ip,
           local_port,
           (unsigned long long)socket);
    free_string(local_ip);

    const char payload[] = "ping";
    op = data_plane_udp_send_to_start(
        socket,
        ip,
        port,
        (const uint8_t *)payload,
        (uint32_t)strlen(payload),
        10000);
    if (!op) {
        print_last_error("udp send start failed");
        data_plane_udp_close(socket);
        return -1;
    }
    if (wait_or_cancel(op, 11000, "udp send") == DATA_PLANE_OP_INVALID) {
        data_plane_udp_close(socket);
        return -1;
    }
    int sent = data_plane_udp_send_to_finish(op);
    if (sent < 0) {
        print_last_error("udp send finish failed");
        data_plane_udp_close(socket);
        return -1;
    }
    printf("udp sent %d bytes to %s:%u\n", sent, ip, port);

    op = data_plane_udp_recv_from_start(socket, 512, 30000);
    if (!op) {
        print_last_error("udp recv start failed");
        data_plane_udp_close(socket);
        return -1;
    }
    if (wait_or_cancel(op, 31000, "udp recv") == DATA_PLANE_OP_INVALID) {
        data_plane_udp_close(socket);
        return -1;
    }

    const uint8_t *buf = NULL;
    uint32_t len = 0;
    const char *peer_ip = NULL;
    uint16_t peer_port = 0;
    int ret = data_plane_udp_recv_from_finish(op, &buf, &len, &peer_ip, &peer_port);
    if (ret < 0) {
        print_last_error("udp recv finish failed");
        data_plane_udp_close(socket);
        return -1;
    }
    printf("udp received %d bytes from %s:%u: %.*s\n",
           ret,
           peer_ip,
           peer_port,
           ret,
           buf ? (const char *)buf : "");
    data_plane_free_bytes(buf, len);
    free_string(peer_ip);
    data_plane_udp_close(socket);
    return 0;
}

static void print_usage(void) {
    printf("Set EASYTIER_FFI_CONFIG and EASYTIER_FFI_INSTANCE to run the async data-plane demo.\n");
    printf("Optional demos:\n");
    printf("  EASYTIER_FFI_TARGET=10.0.0.2:22          async TCP connect/read\n");
    printf("  EASYTIER_FFI_LISTEN_PORT=12345           async TCP bind/accept/read/write\n");
    printf("  EASYTIER_FFI_UDP_TARGET=10.0.0.2:9000    async UDP bind/send_to/recv_from\n");
}

int main(void) {
    const char *config = getenv("EASYTIER_FFI_CONFIG");
    const char *instance = getenv("EASYTIER_FFI_INSTANCE");
    if (!config || !instance) {
        print_usage();
        return 0;
    }

    if (run_network_instance(config) != 0) {
        print_last_error("run_network_instance failed");
        return 1;
    }
    printf("network instance started: %s\n", instance);

    int failed = 0;
    const char *target = getenv("EASYTIER_FFI_TARGET");
    if (target) {
        failed |= run_tcp_connect_demo(instance, target) != 0;
    }

    const char *listen_port = getenv("EASYTIER_FFI_LISTEN_PORT");
    if (listen_port) {
        failed |= run_tcp_listen_demo(instance, listen_port) != 0;
    }

    const char *udp_target = getenv("EASYTIER_FFI_UDP_TARGET");
    if (udp_target) {
        failed |= run_udp_demo(instance, udp_target) != 0;
    }

    if (!target && !listen_port && !udp_target) {
        printf("No dataplane demo env var was set; nothing else to run.\n");
        print_usage();
    }

    return failed ? 1 : 0;
}
