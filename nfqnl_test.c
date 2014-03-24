#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <pcre.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#define OVECCOUNT 30    /* should be a multiple of 3 */


#ifdef __LITTLE_ENDIAN
#define IPQUAD(addr)	        \
  ((unsigned char *)&addr)[0],  \
    ((unsigned char *)&addr)[1],\
    ((unsigned char *)&addr)[2],\
    ((unsigned char *)&addr)[3]
#else
#define IPQUAD(addr)            \
  ((unsigned char *)&addr)[3],  \
    ((unsigned char *)&addr)[2],\
    ((unsigned char *)&addr)[1],\
    ((unsigned char *)&addr)[0]
#endif


/* Packets encryption */
void Encryption(unsigned char *start,int begin,int end)
{
	char key[]="abcdefghijklm";
	char keyLen=strlen(key);
	int i;
	
	for(i=0;i<end-begin;i++)
	{
		*(start+begin+i) ^= key[i%keyLen];
		printf("%c",*(start+begin+i));
	}
}

/* Intercept,Modify,Forward packet */
static u_int32_t Modify_pkt (struct nfq_data *tb)
{
    int id = 0,data_len;
    struct nfqnl_msg_packet_hdr *ph;

    unsigned char *data;                                                /* *data point to the begin of packet */

	pcre *re_start,*re_end;     	                                                            
	const char *error;
    int erroffset,pos_start,pos_end;
	int ovector_start[OVECCOUNT],ovector_end[OVECCOUNT];                /* matching position(begin:ovector[2*i] and end:ovector[2*i+1]) */   
	char buffer[2000];
	char pattern_start[] = "Content-Type:.*?\n";                        /* Regular expression matching */
	char pattern_end[] = "\n------WebKitFormBoundary.*?\n";

	/* */
        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
                id = ntohl(ph->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                        ntohs(ph->hw_protocol), ph->hook, id);
        }
	
        data_len = nfq_get_payload(tb, (unsigned char **)&data);              /* Get packet content*/
        if (data_len >= 0)
                printf("payload_len=%d\n", data_len);
		
	struct iphdr *ip_info = (struct iphdr *)data;                         /* Get ip header*/
	struct tcphdr *tcp_info = (struct tcphdr*)(data + sizeof(*ip_info));  /* Get tcp header*/

	int ipdata_len = data_len;                                            /* ip packet's length */
	int iphead_len = ip_info->ihl * 4;                                    /* ip header's length'*/
	int tcphead_len = tcp_info->doff;                                     /* tcp header's length */
	 	
	unsigned int srcip = ip_info->saddr;
	unsigned int dstip = ip_info->daddr;
	unsigned char *start =  data + iphead_len + tcphead_len;           /* tcp content start position */   
	int data_length = ipdata_len - iphead_len - tcphead_len;

	if(ip_info->protocol == IPPROTO_TCP)
	{
		printf("Dest IP: %u.%u.%u.%u, Src IP:%u.%u.%u.%u\n",IPQUAD(dstip), IPQUAD(srcip));
			
		int i,begin,end;
		/* Get tcp content */
		for (i = 0; i < data_length; i++)      
			buffer[i] = (char)*(start+i);
		buffer[i] = '\0';
			
		/*  Matching about upload file content */
		re_start = pcre_compile(pattern_start, 0, &error, &erroffset, NULL);
		re_end = pcre_compile(pattern_end, 0, &error, &erroffset, NULL);
		pos_start = pcre_exec(re_start, NULL, buffer, data_length, 0, 0, ovector_start, OVECCOUNT); /* position of pattern_start */ 
		pos_end = pcre_exec(re_end, NULL, buffer, data_length, 0, 0, ovector_end, OVECCOUNT);       /* position of pattern_end */

		if(pos_start > 0 && pos_end > 0)
		{
			begin = ovector_start[1] + 2;                                                       /* start position of file content  */
			end = ovector_end[0] - 2;                                                           /* end position of file content */ 

			Encryption(start,begin,end);
			nfq_tcp_compute_checksum_ipv4(tcp_info,ip_info);
		}
		else
			printf("Match is failed!\n");
		}
		fputc('\n', stdout);

		return id;
}
        
/* Callback Function  */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
	unsigned char *pdata;
	int ret;

        u_int32_t id = Modify_pkt(nfa);
        printf("entering callback\n");
	ret = nfq_get_payload(nfa, (unsigned char **)&pdata);
        return nfq_set_verdict(qh, id, NF_ACCEPT, ret, pdata);
}

/* Main Function */
int main(int argc, char **argv)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        printf("binding this socket to queue '0'\n");
        qh = nfq_create_queue(h,  0, &cb, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(h);

        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                printf("pkt received\n");
                nfq_handle_packet(h, buf, rv);
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(h, AF_INET);
#endif

        printf("closing library handle\n");
        nfq_close(h);

        exit(0);
}
