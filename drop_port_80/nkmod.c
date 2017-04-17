#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops hk; 
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct 
struct tcphdr *tcp_header;          //tcp header struct 
struct iphdr *ip_header;  

char sipaddr[16];
char target[16]="192.168.2.1";
  
unsigned int nf_hook_ex(const struct nf_hook_ops *ops, 
						struct sk_buff *skb, 
						const struct net_device *in, 
						const struct net_device *out, 
						int (*okfn)(struct sk_buff *)){
 
        sock_buff = (struct sk_buff *) skb;
 
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
       
        if(!sock_buff) { return NF_ACCEPT;}

		if(ip_header->protocol == 6){//tcp header
			tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);  // lấy TCP header

			if(tcp_header->dest==0x5000){ //drop packet port destination  80
				printk("Drop packet\n");
				return NF_DROP;
			}	
		}else if(ip_header->protocol == 17) {//upd header
			udp_header = (struct udphdr *)skb_transport_header(sock_buff);  // lấy TCP header
			if(udp_header->dest==0x5000){ //drop packet port destination  80
				printk("Drop packet\n");
				return NF_DROP;
			}
		}
		return NF_ACCEPT;
}
 
/* Được gọi khi sử dụng lệnh 'insmod' */
int kmod_init(void){
        /* gán thông tin cho biến `hk` */
        hk = (struct nf_hook_ops){
                .hook = nf_hook_ex, 
				/* đây là hàm callback `nf_hook_ex` kiểu nf_hookfn - định nghĩa trong include/linux/netfilter.h, line 47
				- các tham số của hook mà người dùng định nghĩa phải khớp với kiểu nf_hookfn */
                .hooknum = NF_INET_PRE_ROUTING, 
				/* Sự kiện mà hook này đăng ký  */
                .pf = PF_INET, 
				/* Chỉ xử lý các Internet (IPv4) packet  */
                .priority = NF_IP_PRI_FIRST
				/* Cài đặt độ ưu tiên của hook này ở mức độ cao nhất*/
        };
        nf_register_hook(&hk); 
 	printk("mod load\n");
  return 0;
}
 
/* Được gọi khi sử dụng lệnh 'rmmod' */
void kmod_exit(void){
	printk("mod unload\n");
        nf_unregister_hook(&hk);
}
 
/* Some standard macros to pass the kernel compile script some information */
module_init(kmod_init);
module_exit(kmod_exit);
MODULE_LICENSE("GPL");
