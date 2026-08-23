/**
 * @file easytier-ios.h
 * @brief iOS-facing C ABI for EasyTier.
 *
 * This library embeds EasyTier into an iOS app without a TUN device or
 * NEPacketTunnel: it manages EasyTier instances and forwards local loopback
 * TCP connections into the virtual network through the data plane.
 *
 * Error handling: functions returning `int` return 0 on success (or a
 * non-negative value such as a bound port) and -1 on failure. Call
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
 * @brief Start one EasyTier network instance from a TOML config string.
 *
 * The config's `instance_name` must be unique among instances started
 * through this library. The instance returns before its data-plane runtime
 * is fully up; starting a forwarder right away may briefly fail and should
 * be retried by the caller.
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
 * @brief Start a loopback TCP forwarder into the virtual network.
 *
 * Listens on 127.0.0.1:`listen_port` (0 = auto-assign) and relays every
 * accepted connection to `target_ip`:`target_port` through the data plane
 * of the instance named `inst_name`.
 *
 * One instance admits a single native data-plane session, so only one
 * forwarder may be active per instance; starting a second one fails.
 *
 * @param inst_name   Non-null NUL-terminated instance name.
 * @param target_ip   Non-null NUL-terminated IPv4 address (virtual network).
 * @param target_port Target port in the virtual network.
 * @param listen_port Loopback port to bind; 0 picks a free port.
 * @return The bound local port (> 0) on success, -1 on failure.
 */
int easytier_ios_start_tcp_forwarder(const char *inst_name,
                                     const char *target_ip,
                                     uint16_t target_port,
                                     uint16_t listen_port);

/**
 * @brief Stop the TCP forwarder bound to `local_port`.
 *
 * @param local_port Port previously returned by
 *                   easytier_ios_start_tcp_forwarder().
 * @return 0 on success, -1 when no forwarder is registered on that port.
 */
int easytier_ios_stop_tcp_forwarder(int local_port);

/**
 * @brief Return the last error message on this thread.
 *
 * Combines forwarder-side errors recorded by this library with the
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
 * Use this for strings returned by easytier_ios_collect_network_infos() and
 * easytier_ios_last_error(). Passing NULL is a no-op. The string must not
 * be used after this call.
 *
 * @param s NULL, or a string previously returned by this library.
 */
void easytier_ios_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* EASYTIER_IOS_H */
