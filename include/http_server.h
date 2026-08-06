#ifndef APOLLO_HTTP_SERVER_H
#define APOLLO_HTTP_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#define APOLLO_HTTP_SERVER_PORT 9999
#define APOLLO_HTTP_STAGING_PATH "/data/apollo/http/"

// Start HTTP server on a background pthread.
// Returns 0 on success, non-zero on failure.
int http_server_start(void);

// Stop HTTP server (called on Apollo quit).
void http_server_stop(void);

#ifdef __cplusplus
}
#endif

#endif
