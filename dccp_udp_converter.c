/*
 * Copyright (C) 2018-2022 by Markus Amend, Deutsche Telekom AG
 *
 * U-DCCP converter
 *
 * This is not Open Source software. 
 * This work is made available to you under a source-available license, as 
 * detailed below.
 *
 * Permission is hereby granted, free of charge, subject to below Commons 
 * Clause, to any person obtaining a copy of this software and associated 
 * documentation files (the "Software"), to deal in the Software without 
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 *
 * “Commons Clause” License Condition v1.0
 *
 * The Software is provided to you by the Licensor under the License, as
 * defined below, subject to the following condition.
 *
 * Without limiting other conditions in the License, the grant of rights under
 * the License will not include, and the License does not grant to you, the
 * right to Sell the Software.
 *
 * For purposes of the foregoing, “Sell” means practicing any or all of the
 * rights granted to you under the License to provide to third parties, for a
 * fee or other consideration (including without limitation fees for hosting 
 * or consulting/ support services related to the Software), a product or 
 * service whose value derives, entirely or substantially, from the
 * functionality of the Software. Any license notice or attribution required
 * by the License must also include this Commons Clause License Condition
 * notice.
 *
 * Licensor: Deutsche Telekom AG
 */

/*
 * Netfilter hook.
 * Convert DCCP extended header as defined in RFC 4340
 * for a UDP like appearance. A reconversion is also part.
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          Source Port          |           Dest Port           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Data Offset  | CCVal | CsCov |           Checksum            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     |       |X|               |                               .
 *    | Res | Type  |=|   Reserved    |  Sequence Number (high bits)  .
 *    |     |       |1|               |                               .
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    .                  Sequence Number (low bits)                   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                       -- DCCP extended header --
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * U  |          Source Port          |           Dest Port           |
 * D  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * P  |          Length               |           Checksum            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Type  | CCVal |  Data Offset  |  Sequence Number (high bits)  .
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    .                  Sequence Number (low bits)                   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                   -- Converted DCCP extended header --
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/dccp.h>
#include <net/udp.h>
#include <linux/skbuff.h>

/* Can be modified when module is loaded using module parameters */
static u16	srv_port = 1337;
static u16	port_num = 1;

MODULE_LICENSE("Proprietary");
MODULE_AUTHOR("Markus Amend");
MODULE_DESCRIPTION("Convert DCCP to UDP and vice versa");
MODULE_VERSION("0.2");
MODULE_ALIAS("dccp_udp_conv");
module_param(srv_port, ushort, 0644);
module_param(port_num, ushort, 0644);

#define PORT_IN_RANGE(port)	(((port) >= srv_port) && ((port) < srv_port+port_num))

//TODO: IPv6


//nfho is a nf_hook_ops struct. This struct stores all the
//required information to register a Netfilter hook.
static struct nf_hook_ops nfho_dccp_4,
                          nfho_dccp_6,
                          nfho_udp_4,
                          nfho_udp_6;

#if defined(__LITTLE_ENDIAN_BITFIELD)
struct dccp_ccval_type {
       __u8    type:4,
               ccval:4;
};
#elif defined(__BIG_ENDIAN_BITFIELD)
struct dccp_ccval_type {
       __u8    ccval:4,
               type: 4;
}
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif

__wsum csum_u = 0, csum_d = 0, csum_v = 0;

unsigned int dccp_hook(void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {

    struct iphdr *iph_d;
    struct dccp_hdr *dccp_header_d;

    if (!skb) {
        //printk(KERN_INFO "no skb");
        return NF_ACCEPT;
    }

    iph_d = (struct iphdr *)skb_network_header(skb);

    if (!iph_d) {
        return NF_ACCEPT;
    }

    /*
     * REMEMBER: Requires X=1 for conversion, otherwise we cannot guarantee lossles transformation
     * REMEMBER: For re-converting assume CsCov to be any value,
     *           since the UDP checksum already covers the whole datagram
     */

    if(iph_d->protocol==IPPROTO_DCCP) {

        dccp_header_d = dccp_hdr(skb);


        //exit if dccp header is corrupt or not an extended header
        if (!dccp_header_d || !dccp_header_d->dccph_x) {
            return NF_ACCEPT; 
        } 

        //check if packet is from the MP-DCCP and not from another application
	if (!PORT_IN_RANGE (htons(dccp_header_d->dccph_sport)) &&
		!PORT_IN_RANGE (htons(dccp_header_d->dccph_dport))) {
            return NF_ACCEPT;
        }

        //Following: DCCP to UDP conversion

        //shift CCVal and Type header field to the ninth octet
        *((struct dccp_ccval_type*) ((char*) dccp_header_d + 8)) = (struct dccp_ccval_type)
                                                                    { .type=dccp_header_d->dccph_type,
                                                                      .ccval=dccp_header_d->dccph_ccval};

        //shift Data Offset header field ot the tenth octet
        dccp_header_d->dccph_seq2 = dccp_header_d->dccph_doff;

        //replace original dccp Data Offset header field with the UDP length
        *(uint16_t *) &dccp_header_d->dccph_doff = htons(skb->len - (iph_d->ihl*4));

	//set ip header protocol field to UDP
        iph_d->protocol=IPPROTO_UDP;
        //re-calculate ip header checksum
        iph_d->check = 0;
        iph_d->check = ip_fast_csum((unsigned char *)iph_d, iph_d->ihl);

	//reset dccp checksum for following calculation with skb_checksum()
        dccp_header_d->dccph_checksum = 0;

        //build checksum over header and payload
        csum_d = skb_checksum(skb, skb_transport_offset(skb),
                               (int) (skb->len - (iph_d->ihl*4)),0);

        //build checksum over the UDP pseudo header and csum
        dccp_header_d->dccph_checksum = csum_tcpudp_magic(iph_d->saddr,iph_d->daddr,
                                                           (int) (skb->len - (iph_d->ihl*4)),
                                                           IPPROTO_UDP,csum_d);

        //-> UDP header is successfully built

    }
 
    return NF_ACCEPT; 
}

//Re-convert UDP datagrams to DCCP
unsigned int udp_hook(void *priv,
                       struct sk_buff *skb,
                       const struct nf_hook_state *state) {

    struct iphdr *iph_u;
    struct dccp_hdr *dccp_header_u;
    bool linearize_func_used = false;

    if (!skb) {
        //printk(KERN_INFO "no skb");
        return NF_ACCEPT;
    }

    iph_u = (struct iphdr *)skb_network_header(skb);

    if (!iph_u) {
        return NF_ACCEPT;
    }

    if (iph_u->protocol==IPPROTO_UDP) {

        dccp_header_u = dccp_hdr(skb);

        if (!dccp_header_u) {
            return NF_ACCEPT;
        }

        //check if packet is from the MP-DCCP and not from another application
	if (!PORT_IN_RANGE (htons(dccp_header_u->dccph_sport)) &&
		!PORT_IN_RANGE (htons(dccp_header_u->dccph_dport))) {
            return NF_ACCEPT;
        }

    if (skb_is_nonlinear(skb)){
        linearize_func_used = true;
        if (skb_linearize(skb)){
            //printk(KERN_INFO "linearize error");
            return NF_DROP;
        }
    }

        //Read again dccp header and IP header
        dccp_header_u = dccp_hdr(skb);
        iph_u = (struct iphdr *)skb_network_header(skb);


        //validate UDP checksum otherwise DROP
        if (!skb_csum_unnecessary(skb)){
            csum_v = skb_checksum(skb, skb_transport_offset(skb),
                               (int) (skb->len - (iph_u->ihl*4)),0);
            if(csum_tcpudp_magic(iph_u->saddr, iph_u->daddr,
                        (int) (skb->len - (iph_u->ihl*4)), IPPROTO_UDP,csum_v)) {
                printk(KERN_INFO "bad dccp checksumf");
                return NF_DROP;            
            }
        skb->ip_summed = 1;
        }
 
        //Following: UDP to DCCP conversion

        //restore Data Offset field 
        dccp_header_u->dccph_doff = dccp_header_u->dccph_seq2;

        //restore CCVal field
        dccp_header_u->dccph_ccval = ((struct dccp_ccval_type*) ((char*) dccp_header_u + 8))->ccval;

        //CsCov cannot be restored and has no impact since UDP checksum
        //already passed, see above.
        //CsCov is set to 0 for now but could be any other value.
        //In terms of optimization CsCov should be different to 0 to only comprise the header and no payload
        //However, this requires adaption of the dccph_checksum calculation below.
        dccp_header_u->dccph_cscov = 0;

	//restore Type field
        dccp_header_u->dccph_type = ((struct dccp_ccval_type*) ((char*) dccp_header_u + 8))->type;

        //RFC4340 defines reserved bits to be 0
        dccp_header_u->dccph_reserved=0;
        dccp_header_u->dccph_seq2 = 0;

        //Conversion only happens for X=1, therefore it has to be set to 1
        dccp_header_u->dccph_x = 1;


        //set ip header protocol field to DCCP 
        iph_u->protocol=IPPROTO_DCCP;

        //reset udp checksum for following calculation with skb_checksum()
        dccp_header_u->dccph_checksum = 0;

        //build checksum over header and payload


        csum_u = skb_checksum(skb, skb_transport_offset(skb),
                               (int) (skb->len - (iph_u->ihl*4)),0);

        //build checksum over the DCCP pseudo header and csum
        dccp_header_u->dccph_checksum = csum_tcpudp_magic(iph_u->saddr,iph_u->daddr,
                                                           (int) (skb->len - (iph_u->ihl*4)),
                                                           IPPROTO_DCCP,csum_u);

        //-> successfully restored the DCCP datagram
    }

    return NF_ACCEPT;
}

//initialize will setup the Netfilter hook when the kernel
//module is loaded.
static int __init initialize(void) {

        //IPv4
        nfho_dccp_4.hook     = dccp_hook;
        nfho_dccp_4.hooknum  = NF_INET_POST_ROUTING;//Netfilter chain apply to
        nfho_dccp_4.pf       = PF_INET; //pf = protocol family. PF_INET means IPv4 traffic.
        nfho_dccp_4.priority = NF_IP_PRI_FIRST; //Netfilter priority
        nf_register_net_hook(&init_net, &nfho_dccp_4); //register the hook function.

        //IPv6
        nfho_dccp_6.hook     = dccp_hook;
        nfho_dccp_6.hooknum  = NF_INET_POST_ROUTING;//Netfilter chain apply to
        nfho_dccp_6.pf       = PF_INET6; //pf = protocol family. PF_INET means IPv4 traffic.
        nfho_dccp_6.priority = NF_IP_PRI_FIRST; //Netfilter priority
        //nf_register_net_hook(&init_net, &nfho_dccp_6); //register the hook function.


        //IPv4
        nfho_udp_4.hook     = udp_hook;
        nfho_udp_4.hooknum  = NF_INET_PRE_ROUTING;//Netfilter chain apply to
        nfho_udp_4.pf       = PF_INET; //pf = protocol family. PF_INET means IPv4 traffic.
        nfho_udp_4.priority = NF_IP_PRI_FIRST; //Netfilter priority
        nf_register_net_hook(&init_net, &nfho_udp_4); //register the hook function.

        //IPv6
        nfho_udp_6.hook     = udp_hook;
        nfho_udp_6.hooknum  = NF_INET_PRE_ROUTING;//Netfilter chain apply to
        nfho_udp_6.pf       = PF_INET6; //pf = protocol family. PF_INET means IPv4 traffic.
        nfho_udp_6.priority = NF_IP_PRI_FIRST; //Netfilter priority
        //nf_register_net_hook(&init_net, &nfho_udp_4); //register the hook function.


        printk(KERN_INFO "DCCP<->UDP conversion initialized\n");
        return 0;
}



//unregister the hooks if kernel module is exited
static void __exit cleanup(void) {
	printk(KERN_INFO "DCCP<->UDP conversion deregistered\n");
        nf_unregister_net_hook(&init_net,&nfho_dccp_4); //unregister the hook
        //nf_unregister_net_hook(&init_net,&nfho_dccp_6); //unregister the hook
        nf_unregister_net_hook(&init_net,&nfho_udp_4); //unregister the hook
        //nf_unregister_net_hook(&init_net,&nfho_udp_6); //unregister the hook
}

module_init(initialize);
module_exit(cleanup);
