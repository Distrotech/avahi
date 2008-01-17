/* $Id$ */

/***
  This file is part of avahi.
 
  avahi is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.
 
  avahi is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with avahi; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>
#include <avahi-common/domain.h>
#include <avahi-core/domain-util.h>

#include <openssl/hmac.h>

#include "internal.h"
#include "browse.h"
#include "socket.h"
#include "log.h"
#include "hashmap.h"
#include "wide-area.h"
#include "addr-util.h"
#include "rr-util.h"

#define CACHE_ENTRIES_MAX 500

static AvahiWideAreaLookup* find_lookup(AvahiWideAreaLookupEngine *e, uint16_t id) {
    AvahiWideAreaLookup *l;
    int i = (int) id;

    assert(e);

    if (!(l = avahi_hashmap_lookup(e->lookups_by_id, &i)))
        return NULL;

    assert(l->id == id);

    if (l->dead)
        return NULL;

    return l;
}

static int send_to_dns_server(AvahiWideAreaLookup *l, AvahiDnsPacket *p) {
    AvahiAddress *a;

    assert(l);
    assert(p);

    if (l->engine->n_dns_servers <= 0)
        return -1;

    assert(l->engine->current_dns_server < l->engine->n_dns_servers);

    a = &l->engine->dns_servers[l->engine->current_dns_server];
    l->dns_server_used = *a;

    if (a->proto == AVAHI_PROTO_INET) {

        if (l->engine->fd_ipv4 < 0)
            return -1;

        return avahi_send_dns_packet_ipv4(l->engine->fd_ipv4, AVAHI_IF_UNSPEC, p, NULL, &a->data.ipv4, AVAHI_DNS_PORT);

    } else {
        assert(a->proto == AVAHI_PROTO_INET6);

        if (l->engine->fd_ipv6 < 0)
            return -1;

        return avahi_send_dns_packet_ipv6(l->engine->fd_ipv6, AVAHI_IF_UNSPEC, p, NULL, &a->data.ipv6, AVAHI_DNS_PORT);
    }
}

static void next_dns_server(AvahiWideAreaLookupEngine *e) {
    assert(e);

    e->current_dns_server++;

    if (e->current_dns_server >= e->n_dns_servers)
        e->current_dns_server = 0;
}

static void lookup_stop(AvahiWideAreaLookup *l) {
    assert(l);

    l->callback = NULL;

    if (l->time_event) {
        avahi_time_event_free(l->time_event);
        l->time_event = NULL;
    }
}

static void sender_timeout_callback(AvahiTimeEvent *e, void *userdata) {
    AvahiWideAreaLookup *l = userdata;
    struct timeval tv;

    assert(l);

    /* Try another DNS server after three retries */
    if (l->n_send >= 3 && avahi_address_cmp(&l->engine->dns_servers[l->engine->current_dns_server], &l->dns_server_used) == 0) {
        next_dns_server(l->engine);

        if (avahi_address_cmp(&l->engine->dns_servers[l->engine->current_dns_server], &l->dns_server_used) == 0)
            /* There is no other DNS server, fail */
            l->n_send = 1000;
    }

    if (l->n_send >= 6) {
        avahi_log_warn(__FILE__": Query timed out.");
        avahi_server_set_errno(l->engine->server, AVAHI_ERR_TIMEOUT);
        l->callback(l->engine, AVAHI_BROWSER_FAILURE, AVAHI_LOOKUP_RESULT_WIDE_AREA, NULL, l->userdata);
        lookup_stop(l);
        return;
    }

    assert(l->packet);
    send_to_dns_server(l, l->packet);
    l->n_send++;

    avahi_time_event_update(e, avahi_elapse_time(&tv, 1000, 0));
}

AvahiWideAreaLookup *avahi_wide_area_lookup_new(
    AvahiWideAreaLookupEngine *e,
    AvahiKey *key,
    AvahiWideAreaLookupCallback callback,
    void *userdata) {

    struct timeval tv;
    AvahiWideAreaLookup *l, *t;
    uint8_t *p;

    assert(e);
    assert(key);
    assert(callback);
    assert(userdata);

    l = avahi_new(AvahiWideAreaLookup, 1);
    l->engine = e;
    l->dead = 0;
    l->key = avahi_key_ref(key);
    l->cname_key = avahi_key_new_cname(l->key);
    l->callback = callback;
    l->userdata = userdata;

    /* If more than 65K wide area quries are issued simultaneously,
     * this will break. This should be limited by some higher level */

    for (;; e->next_id++)
        if (!find_lookup(e, e->next_id))
            break; /* This ID is not yet used. */

    l->id = e->next_id++;

    /* We keep the packet around in case we need to repeat our query */
    l->packet = avahi_dns_packet_new(0);

    avahi_dns_packet_set_field(l->packet, AVAHI_DNS_FIELD_ID, (uint16_t) l->id);
    avahi_dns_packet_set_field(l->packet, AVAHI_DNS_FIELD_FLAGS, AVAHI_DNS_FLAGS(0, 0, 0, 0, 1, 0, 0, 0, 0, 0));

    p = avahi_dns_packet_append_key(l->packet, key, 0);
    assert(p);

    avahi_dns_packet_set_field(l->packet, AVAHI_DNS_FIELD_QDCOUNT, 1);

    if (send_to_dns_server(l, l->packet) < 0) {
        avahi_log_error(__FILE__": Failed to send packet.");
        avahi_dns_packet_free(l->packet);
        avahi_key_unref(l->key);
        if (l->cname_key)
            avahi_key_unref(l->cname_key);
        avahi_free(l);
        return NULL;
    }

    l->n_send = 1;

    l->time_event = avahi_time_event_new(e->server->time_event_queue, avahi_elapse_time(&tv, 500, 0), sender_timeout_callback, l);

    avahi_hashmap_insert(e->lookups_by_id, &l->id, l);

    t = avahi_hashmap_lookup(e->lookups_by_key, l->key);
    AVAHI_LLIST_PREPEND(AvahiWideAreaLookup, by_key, t, l);
    avahi_hashmap_replace(e->lookups_by_key, avahi_key_ref(l->key), t);

    AVAHI_LLIST_PREPEND(AvahiWideAreaLookup, lookups, e->lookups, l);

    return l;
}

static void lookup_destroy(AvahiWideAreaLookup *l) {
    AvahiWideAreaLookup *t;
    assert(l);

    lookup_stop(l);

    t = avahi_hashmap_lookup(l->engine->lookups_by_key, l->key);
    AVAHI_LLIST_REMOVE(AvahiWideAreaLookup, by_key, t, l);
    if (t)
        avahi_hashmap_replace(l->engine->lookups_by_key, avahi_key_ref(l->key), t);
    else
        avahi_hashmap_remove(l->engine->lookups_by_key, l->key);

    AVAHI_LLIST_REMOVE(AvahiWideAreaLookup, lookups, l->engine->lookups, l);
    
    avahi_hashmap_remove(l->engine->lookups_by_id, &l->id);
    avahi_dns_packet_free(l->packet);

    if (l->key)
        avahi_key_unref(l->key);

    if (l->cname_key)
        avahi_key_unref(l->cname_key);

    avahi_free(l);
}

void avahi_wide_area_lookup_free(AvahiWideAreaLookup *l) {
    assert(l);

    if (l->dead)
        return;

    l->dead = 1;
    l->engine->cleanup_dead = 1;
    lookup_stop(l);
}

void avahi_wide_area_cleanup(AvahiWideAreaLookupEngine *e) {
    AvahiWideAreaLookup *l, *n;
    assert(e);

    while (e->cleanup_dead) {
        e->cleanup_dead = 0;

        for (l = e->lookups; l; l = n) {
            n = l->lookups_next;
            
            if (l->dead)
                lookup_destroy(l);
        }
    }
}

static void cache_entry_free(AvahiWideAreaCacheEntry *c) {
    AvahiWideAreaCacheEntry *t;
    assert(c);

    if (c->time_event)
        avahi_time_event_free(c->time_event);

    AVAHI_LLIST_REMOVE(AvahiWideAreaCacheEntry, cache, c->engine->cache, c);

    t = avahi_hashmap_lookup(c->engine->cache_by_key, c->record->key);
    AVAHI_LLIST_REMOVE(AvahiWideAreaCacheEntry, by_key, t, c);
    if (t)
        avahi_hashmap_replace(c->engine->cache_by_key, avahi_key_ref(c->record->key), t);
    else
        avahi_hashmap_remove(c->engine->cache_by_key, c->record->key);

    c->engine->cache_n_entries --;

    avahi_record_unref(c->record);
    avahi_free(c);
}

static void expiry_event(AvahiTimeEvent *te, void *userdata) {
    AvahiWideAreaCacheEntry *e = userdata;

    assert(te);
    assert(e);

    cache_entry_free(e);
}

static AvahiWideAreaCacheEntry* find_record_in_cache(AvahiWideAreaLookupEngine *e, AvahiRecord *r) {
    AvahiWideAreaCacheEntry *c;

    assert(e);
    assert(r);

    for (c = avahi_hashmap_lookup(e->cache_by_key, r->key); c; c = c->by_key_next)
        if (avahi_record_equal_no_ttl(r, c->record))
            return c;

    return NULL;
}

static void run_callbacks(AvahiWideAreaLookupEngine *e, AvahiRecord *r) {
    AvahiWideAreaLookup *l;

    assert(e);
    assert(r);

    for (l = avahi_hashmap_lookup(e->lookups_by_key, r->key); l; l = l->by_key_next) {
        if (l->dead || !l->callback)
            continue;

        l->callback(e, AVAHI_BROWSER_NEW, AVAHI_LOOKUP_RESULT_WIDE_AREA, r, l->userdata);
    }

    if (r->key->clazz == AVAHI_DNS_CLASS_IN && r->key->type == AVAHI_DNS_TYPE_CNAME) {
        /* It's a CNAME record, so we have to scan the all lookups to see if one matches */

        for (l = e->lookups; l; l = l->lookups_next) {
            AvahiKey *key;

            if (l->dead || !l->callback)
                continue;
            
            if ((key = avahi_key_new_cname(l->key))) {
                if (avahi_key_equal(r->key, key))
                    l->callback(e, AVAHI_BROWSER_NEW, AVAHI_LOOKUP_RESULT_WIDE_AREA, r, l->userdata);

                avahi_key_unref(key);
            }
        }
    }
}

static void add_to_cache(AvahiWideAreaLookupEngine *e, AvahiRecord *r) {
    AvahiWideAreaCacheEntry *c;
    int is_new;

    assert(e);
    assert(r);

    if ((c = find_record_in_cache(e, r))) {
        is_new = 0;

        /* Update the existing entry */
        avahi_record_unref(c->record);
    } else {
        AvahiWideAreaCacheEntry *t;

        is_new = 1;

        /* Enforce cache size */
        if (e->cache_n_entries >= CACHE_ENTRIES_MAX)
            /* Eventually we should improve the caching algorithm here */
            goto finish;

        c = avahi_new(AvahiWideAreaCacheEntry, 1);
        c->engine = e;
        c->time_event = NULL;

        AVAHI_LLIST_PREPEND(AvahiWideAreaCacheEntry, cache, e->cache, c);

        /* Add the new entry to the cache entry hash table */
        t = avahi_hashmap_lookup(e->cache_by_key, r->key);
        AVAHI_LLIST_PREPEND(AvahiWideAreaCacheEntry, by_key, t, c);
        avahi_hashmap_replace(e->cache_by_key, avahi_key_ref(r->key), t);

        e->cache_n_entries ++;
    }

    c->record = avahi_record_ref(r);

    gettimeofday(&c->timestamp, NULL);
    c->expiry = c->timestamp;
    avahi_timeval_add(&c->expiry, r->ttl * 1000000);

    if (c->time_event)
        avahi_time_event_update(c->time_event, &c->expiry);
    else
        c->time_event = avahi_time_event_new(e->server->time_event_queue, &c->expiry, expiry_event, c);

finish:

    if (is_new)
        run_callbacks(e, r);
}

static int map_dns_error(uint16_t error) {
    static const int table[16] = {
        AVAHI_OK,
        AVAHI_ERR_DNS_FORMERR,
        AVAHI_ERR_DNS_SERVFAIL,
        AVAHI_ERR_DNS_NXDOMAIN,
        AVAHI_ERR_DNS_NOTIMP,
        AVAHI_ERR_DNS_REFUSED,
        AVAHI_ERR_DNS_YXDOMAIN,
        AVAHI_ERR_DNS_YXRRSET,
        AVAHI_ERR_DNS_NXRRSET,
        AVAHI_ERR_DNS_NOTAUTH,
        AVAHI_ERR_DNS_NOTZONE,
        AVAHI_ERR_INVALID_DNS_ERROR,
        AVAHI_ERR_INVALID_DNS_ERROR,
        AVAHI_ERR_INVALID_DNS_ERROR,
        AVAHI_ERR_INVALID_DNS_ERROR,
        AVAHI_ERR_INVALID_DNS_ERROR
    };

    assert(error <= 15);

    return table[error];
}

static void handle_packet(AvahiWideAreaLookupEngine *e, AvahiDnsPacket *p) {
    AvahiWideAreaLookup *l = NULL;
    int i, r;

    AvahiBrowserEvent final_event = AVAHI_BROWSER_ALL_FOR_NOW;

    assert(e);
    assert(p);

    /* Some superficial validity tests */
    if (avahi_dns_packet_check_valid(p) < 0 || avahi_dns_packet_is_query(p)) {
        avahi_log_warn(__FILE__": Ignoring invalid response for wide area datagram.");
        goto finish;
    }

    /* Look for the lookup that issued this query */
    if (!(l = find_lookup(e, avahi_dns_packet_get_field(p, AVAHI_DNS_FIELD_ID))) || l->dead)
        goto finish;

    /* Check whether this a packet indicating a failure */
    if ((r = avahi_dns_packet_get_field(p, AVAHI_DNS_FIELD_FLAGS) & 15) != 0 ||
        avahi_dns_packet_get_field(p, AVAHI_DNS_FIELD_ANCOUNT) == 0) {

        avahi_server_set_errno(e->server, r == 0 ? AVAHI_ERR_NOT_FOUND : map_dns_error(r));
        /* Tell the user about the failure */
        final_event = AVAHI_BROWSER_FAILURE;

        /* We go on here, since some of the records contained in the
           reply might be interesting in some way */
    }

    /* Skip over the question */
    for (i = (int) avahi_dns_packet_get_field(p, AVAHI_DNS_FIELD_QDCOUNT); i > 0; i--) {
        AvahiKey *k;

        if (!(k = avahi_dns_packet_consume_key(p, NULL))) {
            avahi_log_warn(__FILE__": Wide area response packet too short or invalid while reading question key. (Maybe an UTF8 problem?)");
            avahi_server_set_errno(e->server, AVAHI_ERR_INVALID_PACKET);
            final_event = AVAHI_BROWSER_FAILURE;
            goto finish;
        }

        avahi_key_unref(k);
    }

    /* Process responses */
    for (i = (int) avahi_dns_packet_get_field(p, AVAHI_DNS_FIELD_ANCOUNT) +
             (int) avahi_dns_packet_get_field(p, AVAHI_DNS_FIELD_NSCOUNT) +
             (int) avahi_dns_packet_get_field(p, AVAHI_DNS_FIELD_ARCOUNT); i > 0; i--) {

        AvahiRecord *rr;

        if (!(rr = avahi_dns_packet_consume_record(p, NULL))) {
            avahi_log_warn(__FILE__": Wide area response packet too short or invalid while reading response ecord. (Maybe an UTF8 problem?)");
            avahi_server_set_errno(e->server, AVAHI_ERR_INVALID_PACKET);
            final_event = AVAHI_BROWSER_FAILURE;
            goto finish;
        }

        add_to_cache(e, rr);
        avahi_record_unref(rr);
    }

finish:

    if (l && !l->dead) {
        if (l->callback)
            l->callback(e, final_event, AVAHI_LOOKUP_RESULT_WIDE_AREA, NULL, l->userdata);

        lookup_stop(l);
    }
}

static void socket_event(AVAHI_GCC_UNUSED AvahiWatch *w, int fd, AVAHI_GCC_UNUSED AvahiWatchEvent events, void *userdata) {
    AvahiWideAreaLookupEngine *e = userdata;
    AvahiDnsPacket *p = NULL;

    if (fd == e->fd_ipv4)
        p = avahi_recv_dns_packet_ipv4(e->fd_ipv4, NULL, NULL, NULL, NULL, NULL);
    else {
        assert(fd == e->fd_ipv6);
        p = avahi_recv_dns_packet_ipv6(e->fd_ipv6, NULL, NULL, NULL, NULL, NULL);
    }

    if (p) {
        handle_packet(e, p);
        avahi_dns_packet_free(p);
    }
}

AvahiWideAreaLookupEngine *avahi_wide_area_engine_new(AvahiServer *s) {
    AvahiWideAreaLookupEngine *e;

    assert(s);

    e = avahi_new(AvahiWideAreaLookupEngine, 1);
    e->server = s;
    e->cleanup_dead = 0;

    /* Create sockets */
    e->fd_ipv4 = s->config.use_ipv4 ? avahi_open_unicast_socket_ipv4() : -1;
    e->fd_ipv6 = s->config.use_ipv6 ? avahi_open_unicast_socket_ipv6() : -1;

    if (e->fd_ipv4 < 0 && e->fd_ipv6 < 0) {
        avahi_log_error(__FILE__": Failed to create wide area sockets: %s", strerror(errno));

        if (e->fd_ipv6 >= 0)
            close(e->fd_ipv6);

        if (e->fd_ipv4 >= 0)
            close(e->fd_ipv4);

        avahi_free(e);
        return NULL;
    }

    /* Create watches */

    e->watch_ipv4 = e->watch_ipv6 = NULL;

    if (e->fd_ipv4 >= 0)
        e->watch_ipv4 = s->poll_api->watch_new(e->server->poll_api, e->fd_ipv4, AVAHI_WATCH_IN, socket_event, e);
    if (e->fd_ipv6 >= 0)
        e->watch_ipv6 = s->poll_api->watch_new(e->server->poll_api, e->fd_ipv6, AVAHI_WATCH_IN, socket_event, e);

    e->n_dns_servers = e->current_dns_server = 0;
    e->next_id = (uint16_t) rand();

    /* Initialize cache */
    AVAHI_LLIST_HEAD_INIT(AvahiWideAreaCacheEntry, e->cache);
    e->cache_by_key = avahi_hashmap_new((AvahiHashFunc) avahi_key_hash, (AvahiEqualFunc) avahi_key_equal, (AvahiFreeFunc) avahi_key_unref, NULL);
    e->cache_n_entries = 0;

    /* Initialize lookup list */
    e->lookups_by_id = avahi_hashmap_new((AvahiHashFunc) avahi_int_hash, (AvahiEqualFunc) avahi_int_equal, NULL, NULL);
    e->lookups_by_key = avahi_hashmap_new((AvahiHashFunc) avahi_key_hash, (AvahiEqualFunc) avahi_key_equal, (AvahiFreeFunc) avahi_key_unref, NULL);
    AVAHI_LLIST_HEAD_INIT(AvahiWideAreaLookup, e->lookups);

    return e;
}

void avahi_wide_area_engine_free(AvahiWideAreaLookupEngine *e) {
    assert(e);

    avahi_wide_area_clear_cache(e);

    while (e->lookups)
        lookup_destroy(e->lookups);

    avahi_hashmap_free(e->cache_by_key);
    avahi_hashmap_free(e->lookups_by_id);
    avahi_hashmap_free(e->lookups_by_key);

    if (e->watch_ipv4)
        e->server->poll_api->watch_free(e->watch_ipv4);

    if (e->watch_ipv6)
        e->server->poll_api->watch_free(e->watch_ipv6);

    if (e->fd_ipv6 >= 0)
        close(e->fd_ipv6);

    if (e->fd_ipv4 >= 0)
        close(e->fd_ipv4);

    avahi_free(e);
}

void avahi_wide_area_clear_cache(AvahiWideAreaLookupEngine *e) {
    assert(e);

    while (e->cache)
        cache_entry_free(e->cache);

    assert(e->cache_n_entries == 0);
}

void avahi_wide_area_set_servers(AvahiWideAreaLookupEngine *e, const AvahiAddress *a, unsigned n) {
    assert(e);

    if (a) {
        for (e->n_dns_servers = 0; n > 0 && e->n_dns_servers < AVAHI_WIDE_AREA_SERVERS_MAX; a++, n--) 
            if ((a->proto == AVAHI_PROTO_INET && e->fd_ipv4 >= 0) || (a->proto == AVAHI_PROTO_INET6 && e->fd_ipv6 >= 0))
                e->dns_servers[e->n_dns_servers++] = *a;
    } else {
        assert(n == 0);
        e->n_dns_servers = 0;
    }

    e->current_dns_server = 0;

    avahi_wide_area_clear_cache(e);
}

void avahi_wide_area_cache_dump(AvahiWideAreaLookupEngine *e, AvahiDumpCallback callback, void* userdata) {
    AvahiWideAreaCacheEntry *c;

    assert(e);
    assert(callback);

    callback(";; WIDE AREA CACHE ;;; ", userdata);

    for (c = e->cache; c; c = c->cache_next) {
        char *t = avahi_record_to_string(c->record);
        callback(t, userdata);
        avahi_free(t);
    }
}

unsigned avahi_wide_area_scan_cache(AvahiWideAreaLookupEngine *e, AvahiKey *key, AvahiWideAreaLookupCallback callback, void *userdata) {
    AvahiWideAreaCacheEntry *c;
    AvahiKey *cname_key;
    unsigned n = 0;

    assert(e);
    assert(key);
    assert(callback);

    for (c = avahi_hashmap_lookup(e->cache_by_key, key); c; c = c->by_key_next) {
        callback(e, AVAHI_BROWSER_NEW, AVAHI_LOOKUP_RESULT_WIDE_AREA|AVAHI_LOOKUP_RESULT_CACHED, c->record, userdata);
        n++;
    }

    if ((cname_key = avahi_key_new_cname(key))) {

        for (c = avahi_hashmap_lookup(e->cache_by_key, cname_key); c; c = c->by_key_next) {
            callback(e, AVAHI_BROWSER_NEW, AVAHI_LOOKUP_RESULT_WIDE_AREA|AVAHI_LOOKUP_RESULT_CACHED, c->record, userdata);
            n++;
        }

        avahi_key_unref(cname_key);
    }

    return n;
}

int avahi_wide_area_has_servers(AvahiWideAreaLookupEngine *e) {
    assert(e);

    return e->n_dns_servers > 0;
}

/* TODO: should this be located in this file? */
/* r = avahi_tsig_sign_packet("dynamic.endorfine.org", key, 16, p, AVAHI_TSIG_HMAC_MD5, id) */
/* check for NULL on return */
AvahiRecord* avahi_tsig_sign_packet(const unsigned char* keyname, const unsigned char* key, unsigned keylength, AvahiDnsPacket *p, unsigned algorithm, uint16_t id) {
    AvahiRecord *r;

    unsigned char keyed_hash[EVP_MAX_MD_SIZE]; /*used for signing */
    HMAC_CTX ctx;
    unsigned hash_length;

    char *canonic; /*used in conversions */

    int i; /* used in debug runs */

    r = avahi_record_new_full(keyname, AVAHI_DNS_CLASS_ANY, AVAHI_DNS_TYPE_TSIG, 0);

    if (!r) {
      avahi_log_error("avahi_record_new_full() failed.");
        return NULL;
    }

    r->ttl = 0;

    r->data.tsig.time_signed = time(NULL);

    /* printf("TIME:%X:%d\n", r->data.tsig.time_signed, r->data.tsig.time_signed); */

    r->data.tsig.fudge = 300;

    r->data.tsig.error = 0; /* no error, we are always transmitting */

    r->data.tsig.original_id = id; /* MUST match DNS transaction ID, but it is not hashed */

    switch (algorithm){

    case AVAHI_TSIG_HMAC_MD5   :
                                   r->data.tsig.algorithm_name = avahi_strdup("hmac-md5.sig-alg.reg.int");
                                   if(!(r->data.tsig.algorithm_name)) /* OOM check */
                                      return NULL;

                                   r->data.tsig.mac_size = 16;

                                   r->data.tsig.other_len = 0; /*no other data */

                                   r->data.tsig.other_data = NULL;

                                   break;

    case AVAHI_TSIG_HMAC_SHA1  :  /* Requires BIND 9.4 that now implements RFC 4635 (formerly the Eastlake draft)*/
                                   r->data.tsig.algorithm_name = avahi_strdup("hmac-sha1");
                                   if(!(r->data.tsig.algorithm_name)) /* OOM check */
                                      return NULL;

                                   r->data.tsig.mac_size = 20;

                                   r->data.tsig.other_len = 0; /*no other data */

                                   r->data.tsig.other_data = NULL;

                                   break;

    case AVAHI_TSIG_HMAC_SHA256:  /* Requires BIND 9.4 that now implements RFC 4635 (formerly the Eastlake draft)*/
                                   r->data.tsig.algorithm_name = avahi_strdup("hmac-sha256");
                                   if(!(r->data.tsig.algorithm_name)) /* OOM check */
                                      return NULL;

                                   r->data.tsig.mac_size = 32;

                                   r->data.tsig.other_len = 0; /*no other data */

                                   r->data.tsig.other_data = NULL;

                                   break;

    default:   avahi_log_error("Unknown algorithm requested from tsig_sign_packet()");
               return NULL;
    }


    /*generate MAC */

    switch (algorithm){

    case AVAHI_TSIG_HMAC_MD5   :   HMAC_Init(&ctx, key, keylength, EVP_md5());
                                   break;

    case AVAHI_TSIG_HMAC_SHA1  :   /* New from RFC 4635*/
                                   HMAC_Init(&ctx, key, keylength, EVP_sha1());
                                   break;

    case AVAHI_TSIG_HMAC_SHA256:   /* New from RFC 4635*/
                                   HMAC_Init(&ctx, key, keylength, EVP_sha256());
                                   break;

    default:   avahi_log_error("Invalid algorithm requested from tsig_sign_packet()");
               return NULL;
    }

    /* printf("size:%d\n", (unsigned int)p->size); */

    /*feed all the data to be hashed in */
    /*HMAC_Update(&ctx, <data/>, <length/>);*/
    HMAC_Update(&ctx, (unsigned char *)AVAHI_DNS_PACKET_DATA(p), (unsigned int)p->size); /*packet in wire format*/

    canonic = avahi_c_to_canonical_string(keyname); /* key name in canonical wire format (DNS labels) */
    HMAC_Update(&ctx, canonic, strlen(canonic) +1);

    HMAC_Update(&ctx, avahi_uint16_to_canonical_string(AVAHI_DNS_CLASS_ANY), 2); /* class - always ANY for TSIG*/

    HMAC_Update(&ctx, avahi_uint32_to_canonical_string(0), 4); /* TTL - always 0 for TSIG */

    canonic = avahi_c_to_canonical_string(r->data.tsig.algorithm_name); /* IANA algorithm name in canonical wire format (DNS labels)*/
    HMAC_Update(&ctx, canonic, strlen(canonic) +1);

    HMAC_Update(&ctx, avahi_time_t_to_canonical_string(r->data.tsig.time_signed), 6); /*uint48 representation of unix time */

    HMAC_Update(&ctx, avahi_uint16_to_canonical_string(r->data.tsig.fudge), 2);

    HMAC_Update(&ctx, avahi_uint16_to_canonical_string(r->data.tsig.error), 2);

    HMAC_Update(&ctx, avahi_uint16_to_canonical_string(r->data.tsig.other_len), 2);

    /* but no standard keyed hash uses this section to date */
    if (r->data.tsig.other_len > 0)
       HMAC_Update(&ctx, r->data.tsig.other_data, r->data.tsig.other_len);

    HMAC_Final(&ctx, keyed_hash, &hash_length);
    HMAC_cleanup(&ctx);

    r->data.tsig.mac = avahi_strndup(keyed_hash, hash_length);

    /* printf("computed MAC:");
    for(i=0; i<hash_length; i++)
        printf("%02x ", keyed_hash[i]);

    printf("\nlength:%d", hash_length); */

    return r;
}

/* TODO: should this be located in this file? */
/* call as wide_area_publish(<record/>,"dynamic.endorfine.org",<id/>, <socket/>, <publish/delete>) */
int avahi_wide_area_publish(AvahiRecord *r, const char *zone, uint16_t id, int fd, unsigned action) {
    char result;

    char globalname[AVAHI_DOMAIN_NAME_MAX]; /* size accounts for escapes if any */
    char globalfield[AVAHI_DOMAIN_NAME_MAX];
    char *backup = NULL;
    char *backupfield = NULL;
    uint16_t backupclass;
    uint32_t backupttl;
    char *tmp;

    AvahiDnsPacket *p;
    AvahiKey *k;

    AvahiAddress a;

    AvahiRecord *tsig;

    /* TODO: in merged version into upstream, key needs to be an external configurable pulled from /etc */
    static const char key[16] = { 0x12, 0xA6, 0x05, 0xCC, 0x38, 0xF9, 0x1F, 0x1E,
                                  0x24, 0x21, 0x6C, 0xA4, 0xD0, 0x1E, 0x88, 0x38 };

    /* TODO: in merged version into upstream, address needs to be an external configurable pulled from /etc */

    /* testing with farpoint.endorfine.org statically configured */

    avahi_address_parse("69.56.173.108", AVAHI_PROTO_UNSPEC, &a);

    p = avahi_dns_packet_new_update(0); /* MTU */

    if (!p) { /*OOM check */
      avahi_log_error("avahi_dns_packet_new_update() failed.");
      assert(p);
    }

    /* give packet its DNS transaction ID */
    avahi_dns_packet_set_field(p, AVAHI_DNS_FIELD_ID, id);

    /*SOA RR defining zone to be updated */
    k = avahi_key_new(zone, AVAHI_DNS_CLASS_IN, AVAHI_DNS_TYPE_SOA);

    if (!k) { /*OOM check */
      avahi_log_error("avahi_key_new() failed.");
      assert(k);
    }

    result = avahi_dns_packet_append_key(p, k, 0); /* add zone record */

    avahi_dns_packet_set_field(p, AVAHI_DNS_FIELD_ZOCOUNT, 1); /*increment record count  for ZOCOUNT */

    if (!result) {
      avahi_log_error("appending of rdata failed.");
      assert(result);
    }

    /* give record global DNS name under our domain */

    if(r->key->name == (strstr(r->key->name, ".arpa") - strlen(r->key->name) + 5))
        return(0); /* skip over ".arpa" records */

    if(r->key->name == (strstr(r->key->name, ".local") - strlen(r->key->name) + 6)) {
        strcpy(globalname, r->key->name);
        tmp = strstr(globalname, ".local");
        tmp[1] = 0; /* delete extension from copy */
        strcat(globalname, zone);

        backup = r->key->name; /* back up key, restore it at exit */
        r->key->name = globalname; /* fix key for wide-pub*/

        if (r->key->type == AVAHI_DNS_TYPE_PTR || r->key->type == AVAHI_DNS_TYPE_CNAME || r->key->type == AVAHI_DNS_TYPE_NS || r->key->type == AVAHI_DNS_TYPE_SRV) {

            /* same transformation on r->data.ptr.name and r->data.srv.name */

            switch (r->key->type) {  /* share same layout in union */
            case AVAHI_DNS_TYPE_PTR:
            case AVAHI_DNS_TYPE_CNAME:
            case AVAHI_DNS_TYPE_NS:
                                    strcpy(globalfield, r->data.ptr.name);
                                    tmp = strstr(globalfield, ".local");
                                    tmp[1] = 0; /* delete extension from copy */
                                    strcat(globalfield, zone);

                                    backupfield = r->data.ptr.name; /* back up field, restore it at exit */
                                    r->data.ptr.name = globalfield; /* fix field for wide-pub*/
                                    break;

            case AVAHI_DNS_TYPE_SRV:
                                    strcpy(globalfield, r->data.srv.name);
                                    tmp = strstr(globalfield, ".local");
                                    tmp[1] = 0; /* delete extension from copy */
                                    strcat(globalfield, zone);

                                    backupfield = r->data.srv.name; /* back up field, restore it at exit */
                                    r->data.srv.name = globalfield; /* fix field for wide-pub*/
                                    break;
           }
        }

    } else {
        avahi_log_error("invalid record, not .local nor .arpa in extension.");
    }

    if(action == AVAHI_WIDEAREA_DELETE) { /* deleting pre-existing record */
        backupclass = r->key->clazz;
        r->key->clazz = AVAHI_DNS_CLASS_NONE;

        backupttl = r->ttl; /* TODO: fix library limit, support 0 TTL */
        r->ttl = 0;

        result = avahi_dns_packet_append_record(p, r, 0, 0); /* bind max TTL to 0, deletion */
    } else { /* publishing new record */
            if(r->key->type == AVAHI_DNS_TYPE_A) { /* standardize TTLs independent of record for wide-area */
                result = avahi_dns_packet_append_record(p, r, 0, 1); /* bind max TTL to 1 sec */
            } else {
                result = avahi_dns_packet_append_record(p, r, 0, 3); /* bind max TTL to 3 secs */
            }
    }

    avahi_dns_packet_set_field(p, AVAHI_DNS_FIELD_UPCOUNT, 1); /*increment record count for UPCOUNT */

    if (!result) {
      avahi_log_error("appending of rdata failed.");
      assert(result);
    }

    /* get it MAC signed */
    tsig = avahi_tsig_sign_packet("dynamic.endorfine.org", key, sizeof(key), p, AVAHI_TSIG_HMAC_MD5, id);
    /* r = tsig_sign_packet(keyname, key, keylength, packet, hmac_algorithm, id) */

    if (!tsig) { /*OOM check */
      avahi_log_error("tsig record generation failed.");
      assert(tsig);
    }

    /* append TSIG record - note the RRset it goes into! */
    avahi_dns_packet_append_record(p, tsig, 0, 30); /* NOTE: max TTL irrelevant, record comes with a 0 TTL */

    avahi_dns_packet_set_field(p, AVAHI_DNS_FIELD_ADCOUNT, 1); /*increment record count  for ADCOUNT */

    if (!p) { /*OOM check */
      avahi_log_error("appending of rdata failed.");
      assert(p);
    }

    /* put packet on the wire */
    /* avahi_send_dns_packet_ipv4(<socket/>, <interface/>, <packet/>, <srcaddr/>, <dstaddr/>, <dstport/>);*/
    avahi_send_dns_packet_ipv4(fd, AVAHI_IF_UNSPEC, p, NULL, &a.data.ipv4, AVAHI_DNS_PORT);

    /* cleanup */
    r->key->name = backup; /* restore original key */

    if (backupfield)
      if (r->key->type == AVAHI_DNS_TYPE_SRV) { /* SRV has a different layout than other records in the union */
       r->data.srv.name = backupfield; /* restore field if altered */
      } else {
       r->data.ptr.name = backupfield; /* restore field if altered */
      }

    if(action == AVAHI_WIDEAREA_DELETE) { /* restore class if altered */
        r->key->clazz = backupclass;
        r->ttl = backupttl;
    }

    return 0;
}
