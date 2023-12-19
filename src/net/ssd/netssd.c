#include "netssd.h"


MODULE_DESCRIPTION("Spread Spectrum Network Driver");
MODULE_AUTHOR("Aidan Morgan (aidan.j.morgan@gmail.com)");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#define IPPROTO_NETSSDPROTO 14


int netssd_init_module(void);
void netssd_cleanup_module(void);

void netssd_close(struct sock *sk, long timeout);
int netssd_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int netssd_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len);
int netssd_hash(struct sock * sock);

int netssd_rcv(struct sk_buff *skb){
    printk(KERN_INFO "rcv is called\n");
    return 0;
}

int netssd_err(struct sk_buff *skb, u32 info) {
    return 0;
}

// the actual socket implementation
struct netssd_sock {
    struct inet_sock inet; // should be first member
    __u16 len;
};

struct proto netssd_proto = {
        .name              = "NETSSD",
        .owner             = THIS_MODULE,
        .close             = netssd_close,
        .sendmsg           = netssd_sendmsg,
        .hash              = netssd_hash,
        .recvmsg           = netssd_recvmsg,
        .obj_size          = sizeof(struct netssd_sock),
//        .slab_flags        = SLAB_DESTROY_BY_RCU
};

static const struct net_protocol netssd_protocol = {
        .handler = netssd_rcv,
        .err_handler = netssd_err,
        .no_policy = 1,
};

static struct inet_protosw netssd_protosw;

int netssd_init_module(void)
{
    int rc = 0;
    rc = proto_register(&netssd_proto, 1);

    if(rc == 0){
        printk(KERN_INFO "Protocol registration is successful\n");
    }
    else {
        cleanup_module();
        return rc;
    }

    rc = inet_add_protocol(&netssd_protocol, IPPROTO_NETSSDPROTO);
    if(rc == 0){
        printk(KERN_INFO "Protocol insertion successful\n");
    }
    else {
        cleanup_module();
        return rc;
    }

    memset(&netssd_protosw, 0 ,sizeof(netssd_protosw));
    netssd_protosw.type = SOCK_RAW;
    netssd_protosw.protocol = IPPROTO_NETSSDPROTO;
    netssd_protosw.prot = &netssd_proto;

    extern const struct proto_ops inet_dgram_ops;

    netssd_protosw.ops = &inet_dgram_ops;
    netssd_protosw.flags = INET_PROTOSW_REUSE;
    inet_register_protosw(&netssd_protosw);


    return 0;
}

void netssd_cleanup_module(void)
{
    int rc = 0;
    rc = inet_del_protocol(&netssd_protocol, IPPROTO_NETSSDPROTO);

    proto_unregister(&netssd_proto);

    return;
}


module_init(netssd_init_module);
module_exit(netssd_cleanup_module);



void netssd_close(struct sock *sk, long timeout)
{

}

int netssd_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
    return 0;
}

int netssd_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)
{
    return 0;
}

int netssd_hash(struct sock * sock)
{
    return 0;
}
