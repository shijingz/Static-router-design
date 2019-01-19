#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"


/*
    handle arp request
*/
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req)//, char* interface)
{
     time_t curtime = time(NULL);
     if(difftime(curtime, req->sent) >= 1.0)
     {
        if(req->times_sent >= 5)
        {
             //send icmp
            printf("arp request exceeds 5 times\n");
            struct sr_packet* cur_packet = req->packets;
            while (cur_packet != NULL)
            {
                //generate icmp type 3 code 1
                struct sr_ethernet_hdr* e_hdr = 0;
                struct sr_ethernet_hdr* e_hdr_old = 0;
                struct sr_ip_hdr* ip_hdr = 0;
                struct sr_ip_hdr* ip_hdr_old = 0;
                struct sr_icmp_t3_hdr* icmp_t3_hdr = 0;

                uint8_t * buf = (uint8_t*)malloc(cur_packet->len);
                unsigned int buf_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
                uint8_t * buf_w_icmp = (uint8_t*)malloc(buf_len);

                memcpy(buf, cur_packet->buf, cur_packet->len);

                // lpm again -- new version
        
                uint32_t send_max_mask = 0;
                struct sr_rt* send_routing_table = sr->routing_table;
                struct sr_if* send_interface;
                uint32_t send_ip_masked;
                struct sr_rt* lpm_routing_table_for_src = NULL;

                ip_hdr = (struct sr_ip_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr));
                ip_hdr_old = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
                memcpy(ip_hdr, ip_hdr_old, sizeof(struct sr_ip_hdr));
        
                while(send_routing_table!=NULL)
                {
                    printf("is not null\n");
                    send_ip_masked = ip_hdr_old->ip_src & (send_routing_table->mask).s_addr;
                    printf("masked ip:%x\n",send_ip_masked);
                    printf("rt dest ip:%x\n",(send_routing_table->dest).s_addr);

                    if(send_ip_masked == (send_routing_table->dest).s_addr)
                    {
                        printf("prefix match\n");
                        if((send_max_mask < (send_routing_table->mask).s_addr)||(lpm_routing_table_for_src == NULL))
                        {
                            printf("find entry in rt\n");
                            send_max_mask = (send_routing_table->mask).s_addr;
                            lpm_routing_table_for_src  = send_routing_table;
                        }
                    }
                    send_routing_table = send_routing_table->next;
                }

                send_interface = sr_get_interface(sr, lpm_routing_table_for_src->interface);

                //
                e_hdr = (struct sr_ethernet_hdr*)buf_w_icmp;
                e_hdr_old = (struct sr_ethernet_hdr*)buf;
                memcpy(e_hdr->ether_dhost, e_hdr_old->ether_shost, ETHER_ADDR_LEN);
                //memcpy(e_hdr->ether_shost, e_hdr_old->ether_dhost, ETHER_ADDR_LEN);
                memcpy(e_hdr->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
                e_hdr->ether_type = htons(ethertype_ip);

                // ip_hdr = (struct sr_ip_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr));
                // ip_hdr_old = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
                // memcpy(ip_hdr, ip_hdr_old, sizeof(struct sr_ip_hdr));
                //ip_hdr->ip_len = htons(buf_len - sizeof(struct sr_ethernet_hdr));
                //ip_hdr->ip_src = (sr_get_interface(sr, req->packets->iface))->ip;
                sr_set_ip_hdr(ip_hdr, 0, send_interface->ip,htons(buf_len - sizeof(struct sr_ethernet_hdr)));

                icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
                icmp_t3_hdr->icmp_type = 3;
                icmp_t3_hdr->icmp_code = 1;
                icmp_t3_hdr->icmp_sum = 0;
                icmp_t3_hdr->unused = 0;
                icmp_t3_hdr->next_mtu = 0;// use only when code set to 4 
                memcpy(icmp_t3_hdr->data, ip_hdr_old, ICMP_DATA_SIZE);
                icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));

                printf("interface: %s\n", send_interface->name);

                sr_send_packet(sr, buf_w_icmp, buf_len, send_interface->name);//TODO!!!interface

                free(buf);
                free(buf_w_icmp);                                                              

                cur_packet = cur_packet->next;
            }

            sr_arpreq_destroy(&(sr->cache), req);
        }
        else
        {
            //send arp request
            unsigned int arp_req_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
            uint8_t* arp_req_buf = (uint8_t*)malloc(arp_req_len);
            struct sr_ethernet_hdr* e_hdr = 0;
            struct sr_arp_hdr* arp_hdr = 0;
            struct sr_if* iface;

            e_hdr = (struct sr_ethernet_hdr*)arp_req_buf;
            arp_hdr = (struct sr_arp_hdr*)(arp_req_buf + sizeof(struct sr_ethernet_hdr));        

            iface = sr_get_interface(sr, req->packets->iface);
            memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
            memset(e_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
            e_hdr->ether_type = htons(ethertype_arp);

            arp_hdr->ar_hrd = htons(arp_hrd_ethernet);           
            arp_hdr->ar_pro = htons(ethertype_ip);
            arp_hdr->ar_hln = ETHER_ADDR_LEN;
            arp_hdr->ar_pln = sizeof(uint32_t);
            arp_hdr->ar_op = htons(arp_op_request);
            memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
            arp_hdr->ar_sip = iface->ip;
            memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
            arp_hdr->ar_tip = req->ip;

            sr_send_packet(sr, arp_req_buf, arp_req_len, req->packets->iface);
                                        
            free(arp_req_buf);

            req->sent = curtime;
            req->times_sent++;
         }
     }
}





/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* TODO: FILL IN YOUR CODE HERE */
    struct sr_arpreq* req = sr->cache.requests;
    while(req != NULL)
    {
        handle_arpreq(sr, req);
        req = req->next;
    }

    /* You should not need to touch the rest of this code. */
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

