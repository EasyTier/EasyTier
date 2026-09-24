/**
 * @file easytier-ios.h
 * @brief iOS-facing C ABI for EasyTier.
 *
 * This library embeds EasyTier into an iOS app without a TUN device or
 * NEPacketTunnel: it manages EasyTier instances and bridges to the EasyTier
 * management RPC surface. Loopback port forwarding into the virtual network
 * is configured through easytier_ios_call_json_rpc() with
 * api.config.ConfigRpcService/PatchConfig port-forward patches; there is no
 * built-in forwarder.
 *
 * Error handling: functions returning `int` return 0 on success and -1 on
 * failure; functions returning `char *` return NULL on failure. Call
 * easytier_ios_last_error() on the same thread to retrieve details.
 *
 * Threading: all functions are safe to call from any thread. The last-error
 * buffer is thread-local, so query it on the thread that received the
 * failure.
 */

#ifndef EASYTIER_IOS_H
#define EASYTIER_IOS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Configure persistent EasyTier diagnostic logging.
 *
 * Enabling writes targeted connection trace/debug events into rotating log
 * files in `directory`; disabling turns the filter off and flushes output.
 *
 * @param directory UTF-8 directory path. Required when enabling; ignored when
 *                  disabling.
 * @param enabled Non-zero to enable, zero to disable.
 * @return 0 on success, -1 on failure.
 */
int easytier_ios_configure_diagnostic_logging(const char *directory,
                                               int enabled);

/**
 * @brief Append a host lifecycle or network-path marker to the active log.
 *
 * This is a no-op while diagnostic logging is disabled.
 *
 * @param message Non-null NUL-terminated UTF-8 event text.
 * @return 0 on success, -1 on failure.
 */
int easytier_ios_append_diagnostic_event(const char *message);

/** @brief Flush diagnostic log output. */
int easytier_ios_flush_diagnostic_logging(void);

/** @brief Delete all diagnostic log content and reopen the active log. */
int easytier_ios_clear_diagnostic_logs(void);

/**
 * @brief Start one EasyTier network instance from a TOML config string.
 *
 * The config's `instance_name` must be unique among instances started
 * through this library.
 *
 * @param toml Non-null pointer to a NUL-terminated UTF-8 TOML config string.
 * @return 0 on success, -1 on failure.
 */
int easytier_ios_run_instance(const char *toml);

/**
 * @brief Keep the named instances and stop all others.
 *
 * @param names_json Null, empty, or a NUL-terminated JSON array of instance
 *                   name strings. Null / empty / `[]` stops every running
 *                   instance.
 * @return 0 on success, -1 on failure.
 */
int easytier_ios_retain_instances(const char *names_json);

/**
 * @brief Stop exactly one named instance without affecting other instances.
 *
 * An unknown name is a no-op.
 *
 * @param instance_name Non-null NUL-terminated instance name.
 * @return 0 on success, -1 on failure.
 */
int easytier_ios_delete_instance(const char *instance_name);

/**
 * @brief Collect running instance information as a JSON object.
 *
 * The result maps each instance name to its running info JSON object.
 *
 * @param max_length Maximum number of instances to report.
 * @return A newly allocated NUL-terminated JSON string on success, NULL on
 *         failure.
 *
 * @ownership The caller owns the returned string and must release it with
 *            easytier_ios_free_string().
 */
char *easytier_ios_collect_network_infos(int max_length);

/**
 * @brief Call an exposed EasyTier management RPC method using protobuf JSON.
 *
 * `service_name` is the protobuf service name (e.g.
 * "api.config.ConfigRpcService"), `method_name` the RPC method name (e.g.
 * "PatchConfig"). `payload_json` must contain the protobuf JSON request,
 * including any `instance` selector required by the target RPC.
 *
 * Port forwarding into the virtual network is driven through this bridge
 * with api.config.ConfigRpcService/PatchConfig port-forward patches.
 *
 * @param service_name Non-null NUL-terminated RPC service name.
 * @param method_name  Non-null NUL-terminated RPC method name.
 * @param payload_json Non-null NUL-terminated protobuf JSON request body.
 * @return A newly allocated NUL-terminated JSON response string on success,
 *         NULL on failure.
 *
 * @ownership The caller owns the returned string and must release it with
 *            easytier_ios_free_string().
 */
char *easytier_ios_call_json_rpc(const char *service_name,
                                 const char *method_name,
                                 const char *payload_json);

/**
 * @brief Return the last error message on this thread.
 *
 * Combines wrapper-side errors recorded by this library with the
 * easytier-ffi last FFI error.
 *
 * @return A newly allocated NUL-terminated string, or NULL when there is no
 *         recorded error.
 *
 * @ownership The caller owns the returned string and must release it with
 *            easytier_ios_free_string().
 */
char *easytier_ios_last_error(void);

/**
 * @brief Release a string returned by this library.
 *
 * Use this for strings returned by easytier_ios_collect_network_infos(),
 * easytier_ios_call_json_rpc() and easytier_ios_last_error(). Passing NULL
 * is a no-op. The string must not be used after this call.
 *
 * @param s NULL, or a string previously returned by this library.
 */
void easytier_ios_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* EASYTIER_IOS_H */
