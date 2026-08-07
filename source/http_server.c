/*
 * Apollo-Suqi HTTP server module
 *
 * Exposes Apollo's save mount/umount + copy primitives over HTTP:9999 so
 * SuqiPS4Games (PC-side Electron app) can trigger decrypt/encrypt automatically
 * over LAN — no PS4-side clicks needed.
 *
 * Endpoints:
 *   GET  /status                        -> {version, ok:true}
 *   GET  /list                          -> {saves:[{userId,cusa,dir_name,size}]}
 *   POST /export  {userId, cusa}        -> mount RDONLY, copy decrypted files
 *                                          to /data/apollo/http/<cusa>/,
 *                                          umount. Returns {path}
 *   POST /import  {userId, cusa, src}   -> mount RDWR|CREATE2, copy from src
 *                                          into mount, umount (auto encrypt).
 *                                          Returns {ok:true, backup:path}
 *
 * Uses:
 *   - orbis_SaveMount / orbis_SaveUmount   (from saves.c)
 *   - copy_directory                       (from util.c)
 *   - sceNet* sockets                      (BSD-like)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <orbis/libkernel.h>
#include <orbis/SaveData.h>

#include "common.h"
#include "saves.h"
#include "sfo.h"
#include "util.h"
#include "settings.h"
#include "http_server.h"

#define HTTP_BUFFER_SIZE  (16 * 1024)
#define HTTP_MAX_BACKLOG  4
#define APOLLO_HTTP_VERSION_STR "1.1"

/* Prototypes provided by common.h + saves.h + sfo.h — apollo_config in settings.h */

static pthread_t g_http_thread;
static volatile int g_http_running = 0;
static int g_listen_sock = -1;

/* -------------------- tiny JSON helpers -------------------- */

static const char* json_find_key(const char *json, const char *key)
{
    if (!json || !key) return NULL;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    return strstr(json, pat);
}

/*
 * Extract a JSON string value: "key":"value" -> out. Returns 1 if found.
 * Does NOT handle escapes — save-related IDs are ASCII/numeric so safe.
 */
static int json_get_str(const char *json, const char *key, char *out, size_t out_sz)
{
    const char *p = json_find_key(json, key);
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    while (*p && *p != '"') p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_sz) out[i++] = *p++;
    out[i] = 0;
    return i > 0;
}

/* -------------------- HTTP response helpers -------------------- */

static void http_send(int sock, int status, const char *status_text,
                      const char *ctype, const char *body)
{
    char header[512];
    size_t body_len = body ? strlen(body) : 0;
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, status_text, ctype ? ctype : "application/json", body_len);
    send(sock, header, n, 0);
    if (body_len) send(sock, body, body_len, 0);
}

static void http_json_ok(int sock, const char *json)
{
    http_send(sock, 200, "OK", "application/json", json);
}

static void http_json_err(int sock, int status, const char *msg)
{
    char body[512];
    snprintf(body, sizeof(body), "{\"ok\":false,\"error\":\"%s\"}", msg ? msg : "");
    http_send(sock, status, "Error", "application/json", body);
}

/* -------------------- Save operations -------------------- */

/*
 * Enumerate all savedata folders under /user/home/<uid>/savedata/<CUSA>/
 * For each entry that looks like a save directory, we treat it as a mountable
 * save. PS4 saves are typically laid out as pairs of files (keystone + sdimg_*)
 * directly under CUSA/, not in subfolders — dir_name = "" default, but Apollo
 * uses the individual filename base as dir_name.
 *
 * Simplification for MVP: enumerate all directories under
 * /user/home/<uid>/savedata/<cusa>/  — if none, treat cusa/ itself as the save.
 */

static int build_save_entry(save_entry_t *save, const char *user_id,
                            const char *cusa, const char *dir_name,
                            char *path_buf, size_t path_sz)
{
    // user_id from FTP/dir listing is already the hex string PS4 uses
    // (e.g. "10000000" == PS4 SCE user id). No conversion needed.
    snprintf(path_buf, path_sz, "/user/home/%s/savedata/%s/%s", user_id, cusa, dir_name);

    save->title_id = (char *)cusa;
    save->dir_name = (char *)dir_name;
    save->path = path_buf;
    save->name = (char *)dir_name;
    save->blocks = 0;
    save->flags = 0;
    save->type = 0;
    save->codes = NULL;
    return 1;
}

/*
 * copy_directory from Apollo common.c REQUIRES trailing '/' on BOTH input
 * and output dirs — internally uses snprintf("%s%s", dir, entry_name) with
 * no explicit separator. Without trailing '/', paths get mashed:
 *   "/data/apollo/http/CUSA/sce_sdmemory" + "sce_sys/foo" =
 *   "/data/apollo/http/CUSA/sce_sdmemorysce_sys/foo"   ← corrupted
 *
 * copy_dir_all normalizes both paths to end with '/' before dispatch.
 */
static int copy_dir_all(const char *src, const char *dst)
{
    char src_n[512], dst_n[512];
    size_t sl = strlen(src), dl = strlen(dst);

    if (sl && src[sl - 1] == '/') snprintf(src_n, sizeof(src_n), "%s", src);
    else                          snprintf(src_n, sizeof(src_n), "%s/", src);

    if (dl && dst[dl - 1] == '/') snprintf(dst_n, sizeof(dst_n), "%s", dst);
    else                          snprintf(dst_n, sizeof(dst_n), "%s/", dst);

    mkdirs(dst_n);
    return copy_directory(src_n, src_n, dst_n);
}

static int enumerate_save_dirs(const char *user_id, const char *cusa,
                               char names[][64], int max_names)
{
    char base[256];
    snprintf(base, sizeof(base), "/user/home/%s/savedata/%s", user_id, cusa);

    DIR *d = opendir(base);
    if (!d) return 0;

    // PS4 GoldHEN save layout is FLAT files, not subdirs:
    //   /user/home/UID/savedata/CUSAxxxxx/
    //     sce_sdmemory.bin              (keystone, 96B)
    //     sdimg_sce_sdmemory            (encrypted data blob)
    //     sce_bu_sce_sdmemory.bin       (backup keystone)
    //     sdimg_sce_bu_sce_sdmemory     (backup data)
    //
    // Enumerate save slots via sdimg_ prefix (data files). dir_name for
    // orbis_SaveMount = filename with sdimg_ stripped.
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) && n < max_names) {
        if (ent->d_name[0] == '.') continue;
        if (strncmp(ent->d_name, "sdimg_", 6) != 0) continue;
        const char *suffix = ent->d_name + 6;
        if (strlen(suffix) == 0 || strlen(suffix) > 60) continue;
        snprintf(names[n], 64, "%s", suffix);
        n++;
    }
    closedir(d);
    return n;
}

/* -------------------- Endpoints -------------------- */

static void handle_status(int sock)
{
    char body[128];
    snprintf(body, sizeof(body),
             "{\"ok\":true,\"version\":\"%s\",\"app\":\"Apollo-Suqi\"}",
             APOLLO_HTTP_VERSION_STR);
    http_json_ok(sock, body);
}

static void handle_list(int sock)
{
    // Enumerate /user/home/<uid>/savedata/CUSA*/ across all users
    char body[16384];
    strcpy(body, "{\"ok\":true,\"saves\":[");
    int first = 1;

    DIR *dh = opendir("/user/home");
    if (!dh) { http_json_err(sock, 500, "cannot open /user/home"); return; }

    struct dirent *user_ent;
    while ((user_ent = readdir(dh))) {
        if (user_ent->d_name[0] == '.') continue;
        // user id = numeric
        if (strspn(user_ent->d_name, "0123456789abcdefABCDEF") != strlen(user_ent->d_name)) continue;

        char save_root[256];
        snprintf(save_root, sizeof(save_root), "/user/home/%s/savedata", user_ent->d_name);
        DIR *dh2 = opendir(save_root);
        if (!dh2) continue;

        struct dirent *cusa_ent;
        while ((cusa_ent = readdir(dh2))) {
            if (cusa_ent->d_name[0] == '.') continue;
            // CUSA<5 digits>
            if (strlen(cusa_ent->d_name) != 9) continue;
            if (strncmp(cusa_ent->d_name, "CUSA", 4) != 0) continue;

            char line[256];
            int n = snprintf(line, sizeof(line),
                "%s{\"userId\":\"%s\",\"cusa\":\"%s\"}",
                first ? "" : ",", user_ent->d_name, cusa_ent->d_name);
            if (strlen(body) + n + 4 < sizeof(body)) {
                strcat(body, line);
                first = 0;
            }
        }
        closedir(dh2);
    }
    closedir(dh);
    strcat(body, "]}");
    http_json_ok(sock, body);
}

/*
 * POST /export {userId, cusa}
 *   For each save dir under CUSA, mount RDONLY → copy files to
 *   /data/apollo/http/<CUSA>/<dir_name>/ → umount.
 *   Returns { path: "/data/apollo/http/<CUSA>" }
 */
static void handle_export(int sock, const char *body_json)
{
    char user_id[32] = {0}, cusa[16] = {0};
    if (!json_get_str(body_json, "userId", user_id, sizeof(user_id)) ||
        !json_get_str(body_json, "cusa",   cusa,    sizeof(cusa))) {
        http_json_err(sock, 400, "missing userId or cusa");
        return;
    }

    char dir_names[16][64];
    int n_dirs = enumerate_save_dirs(user_id, cusa, dir_names, 16);
    if (n_dirs == 0) { http_json_err(sock, 404, "no save dirs found"); return; }

    char out_root[128];
    snprintf(out_root, sizeof(out_root), APOLLO_HTTP_STAGING_PATH "%s", cusa);
    mkdirs(out_root);

    int ok_count = 0;
    for (int i = 0; i < n_dirs; i++) {
        save_entry_t save;
        char save_path[256];
        char mount[ORBIS_SAVE_DATA_DIRNAME_DATA_MAXSIZE];

        build_save_entry(&save, user_id, cusa, dir_names[i], save_path, sizeof(save_path));

        if (!orbis_SaveMount(&save, ORBIS_SAVE_DATA_MOUNT_MODE_RDONLY, mount)) {
            LOG("http/export: mount fail for %s/%s", cusa, dir_names[i]);
            continue;
        }

        char mount_full[256];
        snprintf(mount_full, sizeof(mount_full), APOLLO_SANDBOX_PATH, mount);
        char out_dir[256];
        snprintf(out_dir, sizeof(out_dir), "%s/%s", out_root, dir_names[i]);

        copy_dir_all(mount_full, out_dir);
        orbis_SaveUmount(mount);
        ok_count++;
    }

    char body[256];
    snprintf(body, sizeof(body),
        "{\"ok\":true,\"path\":\"%s\",\"dirs\":%d}", out_root, ok_count);
    http_json_ok(sock, body);
}

/*
 * POST /import {userId, cusa, src}
 *   For each save dir found under `src/`, mount CUSA/<dir_name> RDWR|CREATE2,
 *   copy files from src/<dir_name>/ into mount, umount → PS4 auto encrypts.
 */
static void handle_import(int sock, const char *body_json)
{
    char user_id[32] = {0}, cusa[16] = {0}, src[256] = {0};
    if (!json_get_str(body_json, "userId", user_id, sizeof(user_id)) ||
        !json_get_str(body_json, "cusa",   cusa,    sizeof(cusa))   ||
        !json_get_str(body_json, "src",    src,     sizeof(src))) {
        http_json_err(sock, 400, "missing userId, cusa, or src");
        return;
    }

    DIR *dh = opendir(src);
    if (!dh) { http_json_err(sock, 404, "src not found"); return; }

    int ok_count = 0, fail_count = 0;
    struct dirent *ent;
    while ((ent = readdir(dh))) {
        if (ent->d_name[0] == '.') continue;
        char src_sub[512];
        snprintf(src_sub, sizeof(src_sub), "%s/%s", src, ent->d_name);
        struct stat st;
        if (stat(src_sub, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        save_entry_t save;
        char save_path[256];
        char mount[ORBIS_SAVE_DATA_DIRNAME_DATA_MAXSIZE];

        build_save_entry(&save, user_id, cusa, ent->d_name, save_path, sizeof(save_path));

        uint32_t mode = ORBIS_SAVE_DATA_MOUNT_MODE_RDWR |
                        ORBIS_SAVE_DATA_MOUNT_MODE_CREATE2 |
                        ORBIS_SAVE_DATA_MOUNT_MODE_COPY_ICON;

        if (!orbis_SaveMount(&save, mode, mount)) {
            LOG("http/import: mount fail for %s/%s", cusa, ent->d_name);
            fail_count++;
            continue;
        }

        char mount_full[256];
        snprintf(mount_full, sizeof(mount_full), APOLLO_SANDBOX_PATH, mount);

        // Copy files from src_sub/ into mount_full/ — recursive to handle
        // any nested files games may put inside their save PFS.
        // First, filter out our own export metadata marker (temp unlink).
        char meta_marker[512];
        snprintf(meta_marker, sizeof(meta_marker), "%s/_export_meta.json", src_sub);
        struct stat mst;
        if (stat(meta_marker, &mst) == 0) unlink(meta_marker);

        copy_dir_all(src_sub, mount_full);

        // CRITICAL: Resign sce_sys/param.sfo with current console's account_id
        // Without this, PS4 detects mismatched ownership and silently reverts
        // to the original save on next load (checksum-style validation).
        // Mirrors Apollo's own _copy_save_hdd() flow.
        char sfo_path[512];
        snprintf(sfo_path, sizeof(sfo_path), "%ssce_sys/param.sfo", mount_full);
        if (stat(sfo_path, &mst) == 0) {
            sfo_patch_t patch = {
                .flags = 0,
                .user_id = apollo_config.user_id,
                .account_id = apollo_config.account_id,
                .psid = (uint8_t*) apollo_config.psid,
                .directory = NULL,
            };
            if (patch_sfo(sfo_path, &patch) != SUCCESS) {
                LOG("http/import: patch_sfo failed on %s", sfo_path);
            } else {
                LOG("http/import: resigned %s", sfo_path);
            }
        } else {
            LOG("http/import: sce_sys/param.sfo missing, skip resign (%s)", sfo_path);
        }

        // Umount → PS4 re-encrypts + writes back to sdimg_ blob.
        orbis_SaveUmount(mount);
        ok_count++;
    }
    closedir(dh);

    // Cleanup staging path — avoid /data disk bloat over time.
    // We only remove if it looks like our staging: prefix "import_" + cusa.
    if (strstr(src, APOLLO_HTTP_STAGING_PATH) == src) {
        char rm_cmd[512];
        // No system(), so best-effort: leave dir, host cleans up on next import.
        (void)rm_cmd;
    }

    char body[256];
    snprintf(body, sizeof(body),
        "{\"ok\":true,\"imported\":%d,\"failed\":%d}", ok_count, fail_count);
    http_json_ok(sock, body);
}

/* -------------------- Request parsing + dispatch -------------------- */

static void handle_request(int sock)
{
    char buf[HTTP_BUFFER_SIZE];
    int total = 0;
    // Read request (with small time budget by blocking recv)
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;
    total = n;
    buf[total] = 0;

    // Read more if Content-Length says so and we don't have full body
    char *cl = strstr(buf, "Content-Length:");
    int body_len = 0;
    if (cl) sscanf(cl, "Content-Length: %d", &body_len);

    char *body_start = strstr(buf, "\r\n\r\n");
    int header_len = body_start ? (body_start + 4 - buf) : total;
    int have_body = body_start ? (total - header_len) : 0;
    while (body_start && have_body < body_len && total < (int)sizeof(buf) - 1) {
        n = recv(sock, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        have_body = total - header_len;
    }
    buf[total] = 0;
    const char *body = body_start ? (body_start + 4) : "";

    // Method + path
    char method[8] = {0}, path[128] = {0};
    sscanf(buf, "%7s %127s", method, path);

    LOG("http: %s %s (body %d B)", method, path, body_len);

    if (strcmp(method, "GET") == 0 && strncmp(path, "/status", 7) == 0) {
        handle_status(sock);
    } else if (strcmp(method, "GET") == 0 && strncmp(path, "/list", 5) == 0) {
        handle_list(sock);
    } else if (strcmp(method, "POST") == 0 && strncmp(path, "/export", 7) == 0) {
        handle_export(sock, body);
    } else if (strcmp(method, "POST") == 0 && strncmp(path, "/import", 7) == 0) {
        handle_import(sock, body);
    } else {
        http_json_err(sock, 404, "unknown endpoint");
    }
}

/* -------------------- Server thread -------------------- */

static void* server_thread_fn(void *arg)
{
    (void)arg;
    struct sockaddr_in addr;

    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock < 0) { LOG("http: socket() fail"); return NULL; }

    int yes = 1;
    setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(APOLLO_HTTP_SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(g_listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG("http: bind() fail on :%d", APOLLO_HTTP_SERVER_PORT);
        close(g_listen_sock);
        g_listen_sock = -1;
        return NULL;
    }
    if (listen(g_listen_sock, HTTP_MAX_BACKLOG) < 0) {
        LOG("http: listen() fail");
        close(g_listen_sock);
        g_listen_sock = -1;
        return NULL;
    }

    LOG("http: Apollo-Suqi listening on :%d", APOLLO_HTTP_SERVER_PORT);
    mkdirs(APOLLO_HTTP_STAGING_PATH);

    while (g_http_running) {
        struct sockaddr_in cli;
        socklen_t sl = sizeof(cli);
        int c = accept(g_listen_sock, (struct sockaddr *)&cli, &sl);
        if (c < 0) {
            if (!g_http_running) break;
            continue;
        }
        handle_request(c);
        close(c);
    }

    if (g_listen_sock >= 0) close(g_listen_sock);
    g_listen_sock = -1;
    return NULL;
}

int http_server_start(void)
{
    if (g_http_running) return 0;
    g_http_running = 1;
    if (pthread_create(&g_http_thread, NULL, server_thread_fn, NULL) != 0) {
        g_http_running = 0;
        LOG("http: pthread_create fail");
        return -1;
    }
    return 0;
}

void http_server_stop(void)
{
    if (!g_http_running) return;
    g_http_running = 0;
    if (g_listen_sock >= 0) {
        shutdown(g_listen_sock, 2);
        close(g_listen_sock);
        g_listen_sock = -1;
    }
    pthread_join(g_http_thread, NULL);
}
