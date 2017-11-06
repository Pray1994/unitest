/*
unittest.c - 发送端模块的源文件
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/spinlock_types.h>
#include <linux/kfifo.h>
#include <linux/slab.h>
MODULE_LICENSE("GPL");
//#define DEBUG 1

/* 开/关调试 */
#ifdef DEBUG
  #define MSG_DEBUG(msg...) printk(KERN_INFO msg)
#else
  #define MSG_DEBUG(msg...)
#endif
static unsigned int cnt = 0;
struct mydata *pdata;

struct mydata{
	unsigned int cnt;
	unsigned int rtt;
};
/**
 * my_tcp_hdr - 返回tcp头部的指针。仅限处于LOCAL_OUT和LOCAL_IN处
 * 的函数调用。
 * @hooknum: 
 * @skb:
*/
static inline struct tcphdr * my_tcp_hdr(unsigned int hooknum, 
		struct sk_buff *skb){
		if (NF_INET_LOCAL_IN == hooknum){
			return (struct tcphdr *)((char *)ip_hdr(skb) + ip_hdrlen(skb));
		} else if (NF_INET_LOCAL_OUT == hooknum){
			return tcp_hdr(skb);
		} else{
			return NULL;
		}
}

/**
 * my_tcphdr_len - 返回tcp头部的长度。仅限处于LOCAL_OUT和LOCAL_IN处
 * 的函数调用。
 * @hooknum: 
 * @skb:
*/static inline unsigned int my_tcphdr_len(unsigned int hooknum, 
		struct sk_buff *skb){
		if (NF_INET_LOCAL_IN == hooknum || NF_INET_LOCAL_OUT == hooknum){
			return my_tcp_hdr(hooknum,skb)->doff*4;
		}
		return 0;
}

static
unsigned int
nfsample(unsigned int hooknum,struct sk_buff * skb,const struct net_device *in,
		const struct net_device *out,int (*okfn) (struct sk_buff *))
{
	struct tcphdr *tcp_header;
	struct iphdr *ip_header;
	struct tcp_sock *tp=tcp_sk(skb->sk);
	
  __wsum skbcsum;
  unsigned char *tp_payload = NULL;
	unsigned int iph_len, tot_len, tcph_len;
	unsigned int tcp_payload_len;
	if (skb_is_nonlinear(skb)){
		skb_linearize(skb);
		MSG_DEBUG("skb is nonlinear, linearize the skb...\n");
	}

	ip_header = ip_hdr(skb);
	if (ip_header->protocol != IPPROTO_TCP){
		//IP头部的protocol字段是在内核中的那一层被填上的
		return NF_ACCEPT;
	}
  if (ntohs(tcp_header->dest) != 5001 && ntohs(tcp_header->source) != 5001) {
    
    return NF_ACCEPT;
  }

  tcp_header = my_tcp_hdr(hooknum, skb);
  tcph_len = my_tcphdr_len(hooknum, skb);
  
  tot_len = ntohs(ip_header->tot_len);//ip包总长度，包括头部和数据部分
	iph_len = ip_hdrlen(skb);
	tcp_payload_len = tot_len - iph_len - tcph_len;
  
	 //如果tcp的数据部分长度大于4的话，这主要是考虑到iperf的前三个报文是建立
	  //连接的，不对它们进行统计
    if (tcp_payload_len >= 8) {
      ++cnt;
      pdata->cnt = cnt;
		if (tp) {
			pdata->rtt = tp->srtt;
		}
		else {
			pdata->rtt = 0;
		}
      	tp_payload = (unsigned char *)(tcp_header) + tcph_len;
      	*((struct mydata *)tp_payload) = *pdata;
      	MSG_DEBUG("%u\n", pdata->rtt);
      
      ip_send_check(ip_header);//计算ip校验和
      //CHECKSUM_NONE表示csum域中的校验值是无意义的，需要L4层自己校验payload和伪头。
      //有可能是硬件检验出错或者硬件没有校验功能。
      skb->ip_summed = CHECKSUM_NONE;
      tcp_header->check = 0;
      skbcsum = csum_partial((u_char *)tcp_header, tot_len - iph_len, 0);
      tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, 
      tot_len - iph_len, IPPROTO_TCP, skbcsum);//计算tcp校验和
    }
    

  return NF_ACCEPT;
}


struct nf_hook_ops nfsample_ops = 
{
	.list =  {NULL,NULL},
  .hook =nfsample,
  .pf = PF_INET,
  .hooknum = NF_INET_LOCAL_OUT,
  .priority = NF_IP_PRI_FILTER+2
};

static int __init nfsample_init(void) 
{	
  MSG_DEBUG("\n===nfsample_INIT ===\n");
  pdata = (struct mydata *)kmalloc(sizeof(struct mydata), GFP_KERNEL);
  memset(pdata, 0, sizeof(struct mydata));
	nf_register_hook(&nfsample_ops);
	return 0;
}


static void __exit nfsample_exit(void) 
{
	MSG_DEBUG("\n===nfsample_EXIT ===\n");
  nf_unregister_hook(&nfsample_ops);
  kfree(pdata);
}
module_init(nfsample_init);
module_exit(nfsample_exit); 
MODULE_AUTHOR("swjtu");
MODULE_DESCRIPTION("unittest");
