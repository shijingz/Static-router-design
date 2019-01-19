/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* TODO: FILL IN YOUR CODE HERE */

  struct sr_ethernet_hdr* e_hdr = 0;
  struct sr_arp_hdr*      a_hdr = 0;
  e_hdr = (struct sr_ethernet_hdr*)packet;
  a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

  //if received an IP packet
  if (e_hdr->ether_type == htons(ethertype_ip))
  {
    //printf("received an ip packet\n");
    sr_ip_packet_handle(sr, packet, len, interface);    
  }
  //if received an ARP request
  else if ((e_hdr->ether_type == htons(ethertype_arp)) &&
            (a_hdr->ar_op      == htons(arp_op_request)))
  {
    //printf("received an ARP request\n");
    sr_arp_req_handle(sr, packet, len, interface);
  }
  else if ((e_hdr->ether_type == htons(ethertype_arp)) &&
            (a_hdr->ar_op      == htons(arp_op_reply)))
  {
    //printf("received an ARP reply\n");
    sr_arp_reply_handle(sr, packet, len, interface);
  }

}/* end sr_ForwardPacket */

void sr_ip_packet_handle(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
  struct sr_ip_hdr* ip_hdr = 0;
  struct sr_ethernet_hdr* e_hdr = 0;
  struct sr_icmp_t3_hdr* icmp_t3_hdr = 0;
  struct sr_ip_hdr* ip_hdr_old = 0;
  struct sr_ethernet_hdr* e_hdr_old = 0;
  uint16_t checksum_new;
  uint16_t checksum_old;
  int icmp_flag = 0;

  uint8_t * buf = (uint8_t*)malloc(len*sizeof(uint8_t));
  memcpy(buf, packet, len);

  ip_hdr = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));

  checksum_old = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  
  checksum_new = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

  // checksum valid
  if(checksum_new == checksum_old)
  {
    //printf("ip packet checksum correct\n");
    //printf("dest ip:%x\n",ip_hdr->ip_dst);
    struct sr_if* if_list = sr->if_list;
    while(if_list!=NULL)
    {
      //printf("my ip:%x\n",if_list->ip);
      if(if_list->ip == ip_hdr->ip_dst)
      {
        icmp_flag = 1;
        break;
      }
      if_list = if_list->next;
    }

    // dest ip != router's interface ip --> forward
    if(icmp_flag == 0)
    {
      // TTL expire
      //printf("dest is elsewhere\n");
      if(ip_hdr->ip_ttl == 1)
      {
        //printf("TTL expire\n");
        //generate icmp type 11 code 0
        unsigned int buf_len;
        buf_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
        uint8_t * buf_w_icmp = (uint8_t*)malloc(buf_len);

        ip_hdr = (struct sr_ip_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr));
        ip_hdr_old = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
        memcpy(ip_hdr, ip_hdr_old, sizeof(struct sr_ip_hdr));

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

        ///
        e_hdr = (struct sr_ethernet_hdr*)buf_w_icmp;
        e_hdr_old = (struct sr_ethernet_hdr*)buf;
        memcpy(e_hdr->ether_dhost, e_hdr_old->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_hdr->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
        e_hdr->ether_type = htons(ethertype_ip);

        
        //ip_hdr->ip_len = htons(buf_len - sizeof(struct sr_ethernet_hdr));
        //ip_hdr->ip_src = (sr_get_interface(sr, interface))->ip;
        sr_set_ip_hdr(ip_hdr, 0, send_interface->ip, htons(buf_len - sizeof(struct sr_ethernet_hdr)));

        icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        icmp_t3_hdr->icmp_type = 11;
        icmp_t3_hdr->icmp_code = 0;
        icmp_t3_hdr->icmp_sum = 0;
        icmp_t3_hdr->unused = 0;
        icmp_t3_hdr->next_mtu = 0;// use only when code set to 4 
        memcpy(icmp_t3_hdr->data, ip_hdr_old, ICMP_DATA_SIZE);
        icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));

        //print_hdr_eth(buf_w_icmp);
        //print_hdr_ip(buf_w_icmp + sizeof(struct sr_ethernet_hdr));
        //print_hdr_icmp(buf_w_icmp + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

        sr_send_packet(sr, buf_w_icmp, buf_len, send_interface->name);//TODO!!!interface

        free(buf);
        free(buf_w_icmp);
        return;        
      }
      else
      {
        ip_hdr->ip_ttl -=1;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
      }

      // longest prefix match
      struct sr_rt* routing_table = sr->routing_table;
      struct sr_rt* lpm_routing_table = NULL;
      uint32_t ip_masked;
      uint32_t max_mask = 0;
      
      while(routing_table!=NULL)
      {
        ip_masked = ip_hdr->ip_dst & (routing_table->mask).s_addr;
        //printf("masked ip:%x\n",ip_masked);
        //printf("rt dest ip:%x\n",(routing_table->dest).s_addr);

        if(ip_masked == (routing_table->dest).s_addr)
        {
          //printf("prefix match\n");
          if((max_mask < (routing_table->mask).s_addr)||(lpm_routing_table == NULL))
          {
            //printf("find entry in rt\n");
            max_mask = (routing_table->mask).s_addr;
            lpm_routing_table = routing_table;
          }
        }
        routing_table = routing_table->next;
      }

      // ICMP type 3 code 0
      if(lpm_routing_table == NULL)
      {
        printf("routing table not match\n");
        //generate icmp type 3 code 0
        unsigned int buf_len;
        buf_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
        uint8_t * buf_w_icmp = (uint8_t*)malloc(buf_len);

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

        
        sr_set_ip_hdr(ip_hdr, 0, send_interface->ip, htons(buf_len - sizeof(struct sr_ethernet_hdr)));

        e_hdr = (struct sr_ethernet_hdr*)buf_w_icmp;
        e_hdr_old = (struct sr_ethernet_hdr*)buf;
        memcpy(e_hdr->ether_dhost, e_hdr_old->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_hdr->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
        e_hdr->ether_type = htons(ethertype_ip);

        
        //ip_hdr->ip_len = htons(buf_len - sizeof(struct sr_ethernet_hdr));
        //ip_hdr->ip_src = (sr_get_interface(sr, interface))->ip;
        //sr_set_ip_hdr(ip_hdr, 0, (sr_get_interface(sr, interface))->ip, htons(buf_len - sizeof(struct sr_ethernet_hdr)));


        //sr_set_ip_hdr(ip_hdr, 0, (sr_get_interface(sr, interface))->ip, htons(buf_len - sizeof(struct sr_ethernet_hdr))); // -- old version

        // // lpm again -- new version
        
        // uint32_t send_max_mask = 0;
        // struct sr_rt* send_routing_table = sr->routing_table;
        // struct sr_if* send_interface;
        // uint32_t send_ip_masked;
        // struct sr_rt* lpm_routing_table_for_src = NULL;
        // while(send_routing_table!=NULL)
        // {
        //   send_ip_masked = ip_hdr_old->ip_src & (send_routing_table->mask).s_addr;
        //   //printf("masked ip:%x\n",ip_masked);
        //   //printf("rt dest ip:%x\n",(routing_table->dest).s_addr);

        //   if(send_ip_masked == (send_routing_table->dest).s_addr)
        //   {
        //     //printf("prefix match\n");
        //     if((send_max_mask < (send_routing_table->mask).s_addr)||(lpm_routing_table_for_src == NULL))
        //     {
        //       //printf("find entry in rt\n");
        //       send_max_mask = (send_routing_table->mask).s_addr;
        //       lpm_routing_table_for_src  = send_routing_table;
        //     }
        //   }
        //   send_routing_table = send_routing_table->next;
        // }
        // send_interface = sr_get_interface(sr, lpm_routing_table_for_src->interface);
        // sr_set_ip_hdr(ip_hdr, 0, send_interface->ip, htons(buf_len - sizeof(struct sr_ethernet_hdr)));

        icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        icmp_t3_hdr->icmp_type = 3;
        icmp_t3_hdr->icmp_code = 0;
        icmp_t3_hdr->icmp_sum = 0;
        icmp_t3_hdr->unused = 0;
        icmp_t3_hdr->next_mtu = 0;// use only when code set to 4 
        memcpy(icmp_t3_hdr->data, ip_hdr_old, ICMP_DATA_SIZE);
        icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));

        sr_send_packet(sr, buf_w_icmp, buf_len, send_interface->name);//TODO!!!interface

        free(buf);
        free(buf_w_icmp); 
        return;       
      }

      // get dest MAC address
      else
      {
        //printf("routing table match\n");
        struct sr_arpentry* next_mac_addr = sr_arpcache_lookup(&(sr->cache), (lpm_routing_table->gw).s_addr);
        if(next_mac_addr == NULL)
        {
          // TODO!!!send arp request
          //printf("cache miss\n");
          struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), (lpm_routing_table->gw).s_addr, buf, len, lpm_routing_table->interface);
          handle_arpreq(sr, req);
          free(buf);
        }
        else
        {
          //printf("cache hit, send packet\n");
          //print_hdr_eth(buf);
          //printf("\n");

          //print_hdr_ip(buf + sizeof(struct sr_ip_hdr));
          //printf("\n");
          e_hdr = (struct sr_ethernet_hdr*)buf;
          //memcpy(e_hdr->ether_shost, e_hdr->ether_dhost, ETHER_ADDR_LEN);
          struct sr_if* iface = sr_get_interface(sr, lpm_routing_table->interface);
          memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_dhost, next_mac_addr->mac, ETHER_ADDR_LEN);
          
          sr_send_packet(sr, buf, len, lpm_routing_table->interface);

          free(next_mac_addr);
          free(buf);

          return;
        }
      }
    }

    // dest ip == router's interface ip
    else if(ip_hdr->ip_p == ip_protocol_icmp)
    {
      //printf("received icmp packet\n");
      uint16_t icmp_checksum_old, icmp_checksum_new;
      struct sr_icmp_hdr* icmp_hdr = (struct sr_icmp_hdr*)(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      icmp_checksum_old = icmp_hdr->icmp_sum;
      icmp_hdr->icmp_sum = 0;
      icmp_checksum_new = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(struct sr_ip_hdr));//sizeof(struct sr_icmp_hdr));
      //printf("check sum new:%x\n",icmp_checksum_new);
      //printf("check sum old:%x\n",icmp_checksum_old);

      if(icmp_checksum_new == icmp_checksum_old)
      {
        
        if(icmp_hdr->icmp_type == 8)
        {
          // send echo reply type 0
          //printf("received icmp type8 code0\n");
          icmp_hdr->icmp_type = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(struct sr_icmp_hdr));

          //ip_hdr->ip_src = ip_hdr->ip_dst;
          sr_set_ip_hdr(ip_hdr, 1, 0, ip_hdr->ip_len);

          struct sr_if* send_iface = sr_get_interface(sr, interface);

          e_hdr = (struct sr_ethernet_hdr*) buf;
          uint8_t e_tmp[ETHER_ADDR_LEN];
          //memcpy(e_tmp, e_hdr->ether_dhost, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_shost, send_iface->addr, ETHER_ADDR_LEN);

          sr_send_packet(sr, buf, len, interface);
          free(buf);
        }

        /*if(icmp_hdr->icmp_type == 8)
        {
          // send echo reply type 0
          printf("received icmp type8 code0\n");
          icmp_hdr->icmp_type = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(struct sr_icmp_hdr));

          uint32_t send_max_mask = 0;
          struct sr_rt* send_routing_table = sr->routing_table;
          struct sr_if* send_interface;
          uint32_t send_ip_masked;
          struct sr_rt* lpm_routing_table_for_src = NULL;

          //ip_hdr = (struct sr_ip_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr));
          ip_hdr = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
          //memcpy(ip_hdr, ip_hdr_old, sizeof(struct sr_ip_hdr));
        
          while(send_routing_table!=NULL)
          {
            printf("is not null\n");
            send_ip_masked = ip_hdr->ip_src & (send_routing_table->mask).s_addr;
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

          //ip_hdr->ip_src = ip_hdr->ip_dst;
          sr_set_ip_hdr(ip_hdr, 1, 0, ip_hdr->ip_len);

          e_hdr = (struct sr_ethernet_hdr*) buf;
          uint8_t e_tmp[ETHER_ADDR_LEN];
          //memcpy(e_tmp, e_hdr->ether_dhost, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_shost, send_interface->addr, ETHER_ADDR_LEN);

          sr_send_packet(sr, buf, len, send_interface->name);//interface);
          free(buf);
        }*/
        // else
        // {
        //   // ICMP Port unreachable (type 3, code 3)
        //   unsigned int buf_len;
        //   buf_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
        //   uint8_t * buf_w_icmp = (uint8_t*)malloc(buf_len);

        //   e_hdr = (struct sr_ethernet_hdr*)buf_w_icmp;
        //   e_hdr_old = (struct sr_ethernet_hdr*)buf;
        //   memcpy(e_hdr->ether_dhost, e_hdr_old->ether_shost, ETHER_ADDR_LEN);
        //   memcpy(e_hdr->ether_shost, e_hdr_old->ether_dhost, ETHER_ADDR_LEN);
        //   e_hdr->ether_type = htons(ethertype_ip);

        //   ip_hdr = (struct sr_ip_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr));
        //   ip_hdr_old = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
        //   memcpy(ip_hdr, ip_hdr_old, sizeof(struct sr_ip_hdr));
        //   //ip_hdr->ip_len = htons(buf_len - sizeof(struct sr_ethernet_hdr));
        //   //ip_hdr->ip_src = ip_hdr->ip_dst;
        //   sr_set_ip_hdr(ip_hdr, 0, ip_hdr->ip_dst, htons(buf_len - sizeof(struct sr_ethernet_hdr)));
        //   //ip_hdr->ip_src = (sr_get_interface(sr, interface))->ip;

        //   icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        //   icmp_t3_hdr->icmp_type = 3;
        //   icmp_t3_hdr->icmp_code = 3;
        //   icmp_t3_hdr->icmp_sum = 0;
        //   icmp_t3_hdr->unused = 0;
        //   icmp_t3_hdr->next_mtu = 0;// use only when code set to 4 
        //   memcpy(icmp_t3_hdr->data, ip_hdr_old, ICMP_DATA_SIZE);
        //   icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));

        //   sr_send_packet(sr, buf_w_icmp, buf_len, interface);//TODO!!!interface

        //   free(buf);
        //   free(buf_w_icmp); 
        // }
      }
      else
      {
        printf("ICMP checksum error\n");
        return;
      }
      
    }
    else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17)
    {
      // ICMP Port unreachable (type 3, code 3)
      unsigned int buf_len;
      buf_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
      uint8_t * buf_w_icmp = (uint8_t*)malloc(buf_len);

      e_hdr = (struct sr_ethernet_hdr*)buf_w_icmp;
      e_hdr_old = (struct sr_ethernet_hdr*)buf;

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

      memcpy(e_hdr->ether_dhost, e_hdr_old->ether_shost, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
      e_hdr->ether_type = htons(ethertype_ip);

      // ip_hdr = (struct sr_ip_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr));
      // ip_hdr_old = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
      // memcpy(ip_hdr, ip_hdr_old, sizeof(struct sr_ip_hdr));
      //ip_hdr->ip_len = htons(buf_len - sizeof(struct sr_ethernet_hdr));
      //ip_hdr->ip_src = (sr_get_interface(sr, interface))->ip;
      sr_set_ip_hdr(ip_hdr, 0, send_interface->ip, htons(buf_len - sizeof(struct sr_ethernet_hdr)));

      icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(buf_w_icmp + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      icmp_t3_hdr->icmp_type = 3;
      icmp_t3_hdr->icmp_code = 3;
      icmp_t3_hdr->icmp_sum = 0;
      icmp_t3_hdr->unused = 0;
      icmp_t3_hdr->next_mtu = 0;// use only when code set to 4 
      memcpy(icmp_t3_hdr->data, ip_hdr_old, ICMP_DATA_SIZE);
      icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));

      sr_send_packet(sr, buf_w_icmp, buf_len, send_interface->name);//TODO!!!interface

      free(buf);
      free(buf_w_icmp); 
    }        
  }

  // checksum error
  else
  {
    printf("IP checksum error\n");
    return;
  }

  return;
}


void sr_arp_req_handle(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
  uint8_t * buf = (uint8_t*)malloc(len);
  struct sr_arp_hdr* arp_hdr_old = 0;
  struct sr_ethernet_hdr* e_hdr_old = 0;
  uint32_t recv_ip;

  memcpy(buf, packet, len);
  e_hdr_old = (struct sr_ethernet_hdr*)buf;
  arp_hdr_old = (struct sr_arp_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
  recv_ip = arp_hdr_old->ar_tip;
  //printf("received ip:%x\n",recv_ip);

  struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr_old->ar_sha, arp_hdr_old->ar_sip);//recv_ip);

  struct sr_if* iface = sr->if_list;
  while (iface != NULL)
  {
    //printf("my ip:%x\n",iface->ip);
    if (iface->ip == recv_ip)
    {
      //reply to this request
      //printf("ARP request for me\n");
      unsigned int arp_reply_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
      uint8_t* arp_reply_buf = (uint8_t*)malloc(arp_reply_len);
      struct sr_ethernet_hdr* e_hdr = 0;
      struct sr_arp_hdr* arp_hdr = 0;

      e_hdr = (struct sr_ethernet_hdr*)arp_reply_buf;
      arp_hdr = (struct sr_arp_hdr*)(arp_reply_buf + sizeof(struct sr_ethernet_hdr));        

      memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_dhost, e_hdr_old->ether_shost, ETHER_ADDR_LEN);
      e_hdr->ether_type = htons(ethertype_arp);

      arp_hdr->ar_hrd = htons(arp_hrd_ethernet);           
      arp_hdr->ar_pro = htons(ethertype_ip);
      arp_hdr->ar_hln = ETHER_ADDR_LEN;
      arp_hdr->ar_pln = sizeof(uint32_t);
      arp_hdr->ar_op = htons(arp_op_reply);
      memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
      arp_hdr->ar_sip = iface->ip;
      memcpy(arp_hdr->ar_tha, arp_hdr_old->ar_sha, ETHER_ADDR_LEN);
      arp_hdr->ar_tip = arp_hdr_old->ar_sip;

      sr_send_packet(sr, arp_reply_buf, arp_reply_len, interface);
                                        
      free(arp_reply_buf);
      return;
    }
    iface = iface->next;
  }
}

void sr_arp_reply_handle(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface )
{

    

    uint8_t * buf = (uint8_t*)malloc(len);
    struct sr_arp_hdr* arp_hdr_old = 0;
    struct sr_ethernet_hdr* e_hdr_old = 0;
    uint32_t recv_ip;

    memcpy(buf, packet, len);
    e_hdr_old = (struct sr_ethernet_hdr*)buf;
    arp_hdr_old = (struct sr_arp_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
    recv_ip = arp_hdr_old->ar_tip;
    //printf("start to search tip\n");
    //printf("recv ip:%x\n",recv_ip);
    //printf("recv ip:\n");
    //print_addr_ip_int(recv_ip);
    //printf("\n");

    //printf("arp reply's ar_tha MAC addr:\n");
    //print_addr_eth(arp_hdr_old->ar_tha);
    //printf("\n");

    //printf("arp reply's source ip:\n");
    //print_addr_ip_int(arp_hdr_old->ar_sip);
    //printf("\n");

    struct sr_if* iface = sr->if_list;

    while (iface != NULL)
    {
      //printf("my ip:%x\n",iface->ip);
      if (iface->ip == recv_ip)
      {
        //printf("arp reply for me\n");
        //printf("my ip:\n");
        //print_addr_ip_int(iface->ip);
        //printf("\n");
        struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr_old->ar_sha, arp_hdr_old->ar_sip);//recv_ip);
        if (req != NULL)
        {
          //printf("find entry in cache\n");
          struct sr_packet* cur_packet = req->packets;
          struct sr_ethernet_hdr* e_hdr = 0;

          while (cur_packet != NULL)
          {
            uint8_t* packet_buf = (uint8_t*)malloc(cur_packet->len);
            memcpy(packet_buf, cur_packet->buf, cur_packet->len);
            e_hdr = (struct sr_ethernet_hdr*)packet_buf;
            
            //printf("ar_tha: %x\n",arp_hdr_old->ar_tha);
            //printf("ar_sha: %x\n",arp_hdr_old->ar_sha);
            //printf("ar_tha:\n");
            //print_addr_eth(arp_hdr_old->ar_tha);
            //printf("ar_sha:\n");
            //print_addr_eth(arp_hdr_old->ar_sha);

            memcpy(e_hdr->ether_shost, arp_hdr_old->ar_tha, ETHER_ADDR_LEN);
            memcpy(e_hdr->ether_dhost, arp_hdr_old->ar_sha, ETHER_ADDR_LEN);
            e_hdr->ether_type = htons(ethertype_ip);

            sr_send_packet(sr, packet_buf, cur_packet->len, req->packets->iface);

            cur_packet = cur_packet->next;
            free(packet_buf);
          }
          sr_arpreq_destroy(&(sr->cache), req);          
        }
        break;
      }
      iface = iface->next;
    }

}

void sr_set_ip_hdr(struct sr_ip_hdr* ip_hdr, int echo_indicator, uint32_t ip_src_new, uint16_t ip_len_new)
{
  uint32_t temp;
  ip_hdr->ip_id = htons(ip_id_num);
  ip_id_num++;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  temp = ip_hdr->ip_src;
  //ip_hdr->ip_src = ip_hdr->ip_dst;
  if(echo_indicator == 1)
  {
    ip_hdr->ip_src = ip_hdr->ip_dst;    
  }
  else
  {
    ip_hdr->ip_src = ip_src_new;
  }
  ip_hdr->ip_dst = temp;
  ip_hdr->ip_len = ip_len_new;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
}
