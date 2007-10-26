#ifndef _IPT_RLSNMPSTATS_H
#define _IPT_RLSNMPSTATS_H

#define IPADDR_SRC   0x01     /* Match source IP addr */
#define IPADDR_DST   0x02     /* Match destination IP addr */

#define IPADDR_SRC_INV  0x10  /* Negate the condition */
#define IPADDR_DST_INV  0x20  /* Negate the condition */

struct ipt_rlsnmpstats {
   u_int32_t src, dst;
};

struct ipt_rlsnmpstats_info {

   struct ipt_rlsnmpstats ipaddr;
   
   /* Flags from above */
   u_int8_t flags;
};

#endif  
