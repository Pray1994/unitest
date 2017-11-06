/*
0.
  unittest_in.c文件是接收端这边需要插入模块的源文件。用于打印丢包信息
1.
  接收端每隔TIME_EVAL时间，统计上一个TIME_EVAL时间段内丢包率。
  对编码报文的编号最大可以到2^32，每次编号都是从0开始，
  我们可以认为在一次测试过程中，编码报文的编号不可能超过2^32，
  有这个前提假设，我们的处理流程会简单很多。
2.
  由于是将丢包信息打印到/var/log/message中，建议测试之前将message清空，
  echo "" > /var/log/messages.
  然后测试完毕后，利用grep处理/var/log/message文件，然后利用matlab画图

3.
  该代码不具备可移植性，未使用htonl等处理结构体，
  不具备线程安全性

4.
  为了避免浮点运算，它是实际RTT值的8倍，单位是HZ。
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
#include <linux/jiffies.h> 
MODULE_LICENSE("GPL");
#define KFIFO_SIZE_POWER 18

//#define DEBUG 1
/* 开/关调试 */
#ifdef DEBUG
  #define MSG_DEBUG(msg...) printk(KERN_INFO msg)
#else
  #define MSG_DEBUG(msg...)
#endif

// #define LDT_PRINT
#ifdef LDT_PRINT
  #define LDT(msg...) printk(KERN_INFO msg)
#else
  #define LDT(msg...)
#endif

#define OUTPUT_FILE "/root/LogFile"
#define MYPORT 5001 //PORT为我们所关注的TCP连接的某一个端口
#define TIME_EVAL 1000000 
static unsigned int cnt = 0;
static struct kfifo *pkfifoSpace;//队列指针
struct timeval stime,etime;
//struct timespec stime, etime;
unsigned char BTime = 0;
long diff = 0;
static spinlock_t fifoLock; //自旋锁
char buf[60];
struct file* fp = NULL;
struct mydata *pdata;

// 此结构体将发送给服务器端程序
typedef struct mydata{
  unsigned int cnt;
  unsigned int rtt;
}data;

/**
 * nffifo_init - 使用内核中的队列数据结构kfifo之前进行初始化工作
 */
static int nffifo_init(void)
{
	pkfifoSpace = kfifo_alloc((sizeof(unsigned int) << KFIFO_SIZE_POWER), 
		GFP_ATOMIC, &fifoLock);
  if (pkfifoSpace == NULL) 
  {
		printk("kfifo_alloc failed !\n");
    return -EFAULT;
  }
  spin_lock_init(&fifoLock); //Initial fifo spinlock 
  return 0;
}

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

/**
 * cal_drop_rate - 计算丢包率，并打印出在过去TIME_EVAL时间段内，发送端发了
 * enum - snum 个报文，接收端收到了 fifolen / sizeof(unsigned int) 个报文。
 */
void cal_drop_rate(long eval_time, unsigned int eve_tcp_len, unsigned int rtt)
{
  unsigned int fifolen = kfifo_len(pkfifoSpace);
  unsigned int numpkt = fifolen / sizeof(unsigned int);
  LDT("%u   ", numpkt);
  unsigned int ret;
  unsigned int snum = 0xffffffff;
  unsigned int endnum = 0;
  int i = 0;
  MSG_DEBUG("fifolen = %u\n",fifolen);
  /*精髓在这儿，在队列中找到最大值和最小值，这样才能防止出现重传造成的不正确。*/
  for (i = 0; i < fifolen / sizeof(unsigned int); ++i) {
    kfifo_get(pkfifoSpace, (unsigned char *)&ret, sizeof(ret));
    snum = min(ret, snum);
    endnum = max(ret, endnum);
  }
  long eve_s;
  // 每隔一秒printk一次数据
  for (eve_s = eval_time; eve_s > 1000000; eve_s -= 1000000) {
    unsigned long eve_lost = ( ((endnum - snum + 1 - numpkt) * 1000000 ) / (endnum - snum + 1)) / (eval_time / 10000);
//  printk("drop rate:%u / %u\n",numpkt, endnum - snum + 1);
    unsigned int rate = (numpkt * eve_tcp_len) / 10000;
    if (rate % 100 < 10) {
      sprintf(buf, "%u.0%u", rate / 100, rate % 100);
    } else {
      sprintf(buf, "%u.%u", rate / 100, rate % 100);
    }
  
    if (eve_lost % 100 < 10) {
      sprintf(buf, "%s   %u.0%u", buf, eve_lost / 100, eve_lost % 100);
    } else {
      sprintf(buf, "%s   %u.%u", buf, eve_lost / 100, eve_lost % 100);
    }

    sprintf(buf, "%s   %u\n", buf, rtt);
  }

  printk("%s", buf);
}

static
unsigned int
nfsample_in(unsigned int hooknum,struct sk_buff * skb,const struct net_device *in,
		const struct net_device *out,int (*okfn) (struct sk_buff *)) 
{
	struct tcphdr *tcp_header;
	struct iphdr *ip_header;
  unsigned int iph_len, tot_len, tcph_len, tcp_payload_len;
  
  unsigned char *tp_payload = NULL;
	ip_header = ip_hdr(skb);
  tcp_header = my_tcp_hdr(hooknum, skb);

  // 过滤非TCP报文
	if (ip_header->protocol != IPPROTO_TCP ){
		return NF_ACCEPT;
	}

  // 过滤非iperf端口5001
  if (ntohs(tcp_header->dest) != MYPORT && ntohs(tcp_header->source) != MYPORT) {
    
    return NF_ACCEPT;
  }

	if (skb_is_nonlinear(skb)){
		skb_linearize(skb);
		MSG_DEBUG("skb is nonlinear, linearize the skb...\n");
	}

	tcph_len = my_tcphdr_len(hooknum, skb);
  tot_len = ntohs(ip_header->tot_len);//ip包总长度，包括头部和数据部分
  iph_len = ip_hdrlen(skb);
  tcp_payload_len = tot_len - iph_len - tcph_len;

  MSG_DEBUG("tcp_payload_len = %u\n",tcp_payload_len);
  if (likely(tcp_payload_len >= 8)) {
    
    tp_payload = (unsigned char *)(tcp_header) + tcph_len;
    cnt = ((struct mydata *)tp_payload)->cnt;
    unsigned int rtt = jiffies_to_usecs(((struct mydata *)tp_payload)->rtt) >> 3;

  LDT("rtt = %d\n",rtt);
  LDT("cnt = %d\n",cnt);
    kfifo_put(pkfifoSpace, (unsigned char *)&cnt, sizeof(cnt));
    if (BTime == 0) {
      do_gettimeofday(&stime);
      MSG_DEBUG("%d.%d\n",stime.tv_sec, stime.tv_usec);
      //etime_last = stime;
      //stime = current_kernel_time();
      BTime = 1;

    } else {
      do_gettimeofday(&etime);
      MSG_DEBUG("%d.%d\n",etime.tv_sec,etime.tv_usec);
      //etime = current_kernel_time();
      diff = (etime.tv_sec - stime.tv_sec)*1000000 + 
        (etime.tv_usec - stime.tv_usec);
      MSG_DEBUG("diff = %ld\n",diff);
      if (diff >= TIME_EVAL) {
        //超过了100ms，统计丢包率
        cal_drop_rate(diff, tot_len, rtt);
        stime = etime;
      } //if (diff...)
    } //if (Btime == 0)
  } //if (likely(...))

  return NF_ACCEPT;
}


struct nf_hook_ops nfsample_in_ops = 
{
	.list =  {NULL,NULL},
  .hook =nfsample_in,
  .pf = PF_INET,
  .hooknum = NF_INET_LOCAL_IN,
  .priority = NF_IP_PRI_FILTER+2
};

static int __init nfsample_in_init(void) 
{	
  printk("\n===nfsample_in_INIT ===\n");
  pdata = (struct mydata *)kmalloc(sizeof(struct mydata), GFP_KERNEL);
  memset(pdata, 0, sizeof(struct mydata));
  
  nf_register_hook(&nfsample_in_ops);
  nffifo_init();
  
	return 0;
}


static void __exit nfsample_in_exit(void) 
{
	printk("\n===nfsample_in_EXIT ===\n");
  /*
  if(fp != NULL)
    filp_close(fp, NULL);
  */
  kfifo_reset(pkfifoSpace);
	kfifo_free(pkfifoSpace);
  kfree(pdata);
  nf_unregister_hook(&nfsample_in_ops);
}
module_init(nfsample_in_init);
module_exit(nfsample_in_exit); 
MODULE_AUTHOR("swjtu");
MODULE_DESCRIPTION("unittest_in");
