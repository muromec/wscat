#include <string.h>
#include <re.h>
#include "http.h"

#define DEBUG_MODULE "ws"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

enum ws_state {
    START,
    IDLE,
    WAIT_DATA,
    CLOSED
};

struct websocket {
    struct request *http;
    enum ws_state state;
    struct mbuf *rbuf;
    size_t wait;
    char *rkey;
};

struct frame_header {
    unsigned char opbits;
    unsigned char len;
    unsigned short len16;
};

static void destruct(void *arg)
{
    struct websocket *ws = arg;

    ws->rkey = mem_deref(ws->rkey);
    ws->http = mem_deref(ws->http);
};


static void signal_handler(int sig)
{
    DEBUG_NOTICE("terminating on signal %d...\n", sig);
    re_cancel();
}

static void http_done(struct request *req, int code, void *arg) {
    DEBUG_WARNING("HTTP %d\n", code);

    re_cancel();
    // Event loop already stopped so CLOSE event
    // would not fire and request not freed.
    // Don`t do so in non-cli programms
}

static void http_err(int err, void *arg) {
    DEBUG_WARNING("Connection error %d\n", err);
    re_cancel();
}

static bool drain_input(struct websocket *ws, struct mbuf *data)
{
    struct frame_header *frame;
    unsigned char bits, opcode, mask;
    unsigned long len, len64;
    unsigned int mask_key;

    if(mbuf_get_left(data) <= 2) {
        return false;
    }

    frame = (void*)mbuf_buf(data);

    bits = frame->opbits >> 4;
    opcode = frame->opbits & 0xF;
    mask = frame->len & 0x80;
    len = frame->len & 0x7f;

    data->pos += 2;

    switch(len) {
    case 126:
        if(mbuf_get_left(data) <= 2) {
            return false;
        }
        len = htons(mbuf_read_u16(data));
        break;
    case 127:

        if(mbuf_get_left(data) <= 8) {
            return false;
        }

        len64 = mbuf_read_u64(data);
        len = ntohl(len64 >> 32);
        len |= (unsigned long)ntohl(len64) << 32;
        break;
    }

    if(mask) {

        if(mbuf_get_left(data) <= 2) {
            return false;
        }

        mask_key = mbuf_read_u32(data);
    }

    if(mbuf_get_left(data) >= len) {
        fwrite(mbuf_buf(data), len, 1, stdout);
        fflush(stdout);

        data->pos += len;
        return true;
    }

    fwrite(mbuf_buf(data), mbuf_get_left(data), 1, stdout);

    ws->state = WAIT_DATA;
    ws->wait = len - mbuf_get_left(data);

    return false;
}

static void stream_cb(struct request* req, enum stream_ev event, struct mbuf *data, void *arg)
{
    struct websocket *ws = arg;

    char *key = NULL;
    switch(event) {
    case HTTP_STREAM_EST:
        http_response_header(req, "Sec-WebSocket-Accept", &ws->rkey);
        ws->state = IDLE;
        break;
    case HTTP_STREAM_CLOSE:
        re_cancel();
        break;
    case HTTP_STREAM_DATA:
        switch(ws->state) {
        case IDLE:
        idle:
            while(drain_input(ws, data)) ;;
            break;
        case WAIT_DATA:
            if(ws->wait >= mbuf_get_left(data)) {
                ws->wait -= mbuf_get_left(data);
                fwrite(mbuf_buf(data), mbuf_get_left(data), 1, stdout);
            } else {
                fwrite(mbuf_buf(data), ws->wait, 1, stdout);
                fflush(stdout);

                ws->state = IDLE;
                data->pos += ws->wait;
                ws->wait = 0;
                goto idle;
            }
            break;
        default:
            DEBUG_WARNING("broken state machine %d\n", ws->state);
        }
        break;
    }

}


int main(int argc, char *argv[])
{
    int err;
    struct httpc app;

    err = libre_init();

    struct sa nsv[16];
 
    unsigned char rbytes[8];
    char rbytes64[13];
    size_t b64_out;

    uint32_t nsc = ARRAY_SIZE(nsv);

    err = dns_srv_get(NULL, 0, nsv, &nsc);

    err = dnsc_alloc(&app.dnsc, NULL, nsv, nsc);

    struct websocket *ws = mem_zalloc(sizeof(struct websocket), destruct);
    struct request *request;
    rand_bytes(rbytes, 8);
    b64_out = 12;
    err = base64_encode(rbytes, 8, rbytes64, &b64_out);
    rbytes64[12] = '\0';

    http_init(&app, &request, "http://127.0.0.1:8888/ws");
    ws->http = mem_ref(request);

    http_header(request, "Upgrade", "websocket");
    http_header(request, "Connection", "Upgrade");
    http_header(request, "Sec-WebSocket-Version", "13"); //XXX
    http_header(request, "Sec-WebSocket-Key", rbytes64);
    http_cb(request, ws, http_done, http_err);
    http_stream(request, ws, stream_cb);
    http_send(request);

    err = re_main(signal_handler);

    goto out;

fail:
    DEBUG_WARNING("failed\n");
out:
    mem_deref(ws);
    mem_deref(app.dnsc);
    mem_deref(app.tls);

    libre_close();

    /* check for memory leaks */
    tmr_debug();
    mem_debug();


}
