#ifndef foowideareahfoo
#define foowideareahfoo

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

#include "lookup.h"
#include "browse.h"

typedef struct AvahiWideAreaLookupEngine AvahiWideAreaLookupEngine;
typedef struct AvahiWideAreaLookup AvahiWideAreaLookup;

typedef void (*AvahiWideAreaLookupCallback)(
    AvahiWideAreaLookupEngine *e,
    AvahiBrowserEvent event,
    AvahiLookupResultFlags flags,
    AvahiRecord *r,
    void *userdata);

typedef struct AvahiWideAreaCacheEntry AvahiWideAreaCacheEntry;

struct AvahiWideAreaCacheEntry {
    AvahiWideAreaLookupEngine *engine;

    AvahiRecord *record;
    struct timeval timestamp;
    struct timeval expiry;

    AvahiTimeEvent *time_event;

    AVAHI_LLIST_FIELDS(AvahiWideAreaCacheEntry, by_key);
    AVAHI_LLIST_FIELDS(AvahiWideAreaCacheEntry, cache);
};

struct AvahiWideAreaLookup {
    AvahiWideAreaLookupEngine *engine;
    int dead;

    uint32_t id;  /* effectively just an uint16_t, but we need it as an index for a hash table */
    AvahiTimeEvent *time_event;

    AvahiKey *key, *cname_key;

    int n_send;
    AvahiDnsPacket *packet;

    AvahiWideAreaLookupCallback callback;
    void *userdata;

    AvahiAddress dns_server_used;

    AVAHI_LLIST_FIELDS(AvahiWideAreaLookup, lookups);
    AVAHI_LLIST_FIELDS(AvahiWideAreaLookup, by_key);
};

struct AvahiWideAreaLookupEngine {
    AvahiServer *server;

    int fd_ipv4, fd_ipv6;
    AvahiWatch *watch_ipv4, *watch_ipv6;

    uint16_t next_id;

    /* Cache */
    AVAHI_LLIST_HEAD(AvahiWideAreaCacheEntry, cache);
    AvahiHashmap *cache_by_key;
    unsigned cache_n_entries;

    /* Lookups */
    AVAHI_LLIST_HEAD(AvahiWideAreaLookup, lookups);
    AvahiHashmap *lookups_by_id;
    AvahiHashmap *lookups_by_key;

    int cleanup_dead;

    AvahiAddress dns_servers[AVAHI_WIDE_AREA_SERVERS_MAX];
    unsigned n_dns_servers;
    unsigned current_dns_server;
};

AvahiWideAreaLookupEngine *avahi_wide_area_engine_new(AvahiServer *s);
void avahi_wide_area_engine_free(AvahiWideAreaLookupEngine *e);

unsigned avahi_wide_area_scan_cache(AvahiWideAreaLookupEngine *e, AvahiKey *key, AvahiWideAreaLookupCallback callback, void *userdata);
void avahi_wide_area_cache_dump(AvahiWideAreaLookupEngine *e, AvahiDumpCallback callback, void* userdata);
void avahi_wide_area_set_servers(AvahiWideAreaLookupEngine *e, const AvahiAddress *a, unsigned n);
void avahi_wide_area_clear_cache(AvahiWideAreaLookupEngine *e);
void avahi_wide_area_cleanup(AvahiWideAreaLookupEngine *e);
int avahi_wide_area_has_servers(AvahiWideAreaLookupEngine *e);

AvahiRecord* avahi_tsig_sign_packet(const unsigned char* keyname, const unsigned char* key, unsigned keylength, AvahiDnsPacket *p, unsigned algorithm, uint16_t id);
int avahi_wide_area_publish(AvahiRecord *r, const char *zone, uint16_t id, int fd, unsigned action);

AvahiWideAreaLookup *avahi_wide_area_lookup_new(AvahiWideAreaLookupEngine *e, AvahiKey *key, AvahiWideAreaLookupCallback callback, void *userdata);
void avahi_wide_area_lookup_free(AvahiWideAreaLookup *q);



#endif

