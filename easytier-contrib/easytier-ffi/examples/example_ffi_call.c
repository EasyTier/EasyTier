#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h> // for sleep

// FFI struct and function declarations
typedef struct {
    const char* key;
    const char* value;
} KeyValuePair;

typedef void (*config_server_event_callback)(
    const char* event_json,
    void* user_data
);

extern int parse_config(const char* cfg_str);
extern int run_network_instance(const char* cfg_str);
extern void get_error_msg(const char** out);
extern void free_string(const char* s);
extern int collect_network_infos(KeyValuePair* infos, size_t max_length);
extern int start_config_server_client(
    const char* config_server_url,
    const char* hostname,
    const char* machine_id,
    bool secure_mode,
    config_server_event_callback callback,
    void* user_data
);
extern int stop_config_server_client(void);
extern int is_config_server_client_connected(void);

static void on_config_server_event(const char* event_json, void* user_data) {
    (void)user_data;
    printf("config server event: %s\n", event_json);
}

int main() {
    const char* config = "inst_name = \"test\"\nnetwork = \"test_network\"\n";
    int ret;

    // 调用 parse_config
    ret = parse_config(config);
    if (ret != 0) {
        const char* err = NULL;
        get_error_msg(&err);
        if (err) {
            printf("parse_config error: %s\n", err);
            free_string(err);
        }
        return 1;
    }
    printf("parse_config success\n");

    // 调用 run_network_instance
    ret = run_network_instance(config);
    if (ret != 0) {
        const char* err = NULL;
        get_error_msg(&err);
        if (err) {
            printf("run_network_instance error: %s\n", err);
            free_string(err);
        }
        return 1;
    }
    printf("run_network_instance success\n");

    // 周期性调用 collect_network_infos 并打印
    const size_t max_infos = 8;
    KeyValuePair* infos = (KeyValuePair*)malloc(sizeof(KeyValuePair) * max_infos);
    if (!infos) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    for (int i = 0; i < 5; ++i) { // 循环5次作为示例
        memset(infos, 0, sizeof(KeyValuePair) * max_infos);
        int count = collect_network_infos(infos, max_infos);
        if (count < 0) {
            const char* err = NULL;
            get_error_msg(&err);
            if (err) {
                printf("collect_network_infos error: %s\n", err);
                free_string(err);
            }
            break;
        }
        printf("collect_network_infos: %d instance(s)\n", count);
        for (int j = 0; j < count; ++j) {
            printf("  [%d] key: %s\n      value: %s\n", j, infos[j].key, infos[j].value);
            free_string(infos[j].key);
            free_string(infos[j].value);
        }
        sleep(1);
    }
    free(infos);

    return 0;
}
