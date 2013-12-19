#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <arpa/inet.h>

#include <net/ethernet.h>
#include <net/if_arp.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include <sys/time.h>
#include <sys/stat.h>

#include "openflow/openflow.h"
#include "ofpbuf.h"
#include "config.h"
#include "utils.h"

struct arp_ether_hdr
{
	unsigned short int ar_hrd;          /* Format of hardware address.  */
	unsigned short int ar_pro;          /* Format of protocol address.  */
	unsigned char ar_hln;               /* Length of hardware address.  */
	unsigned char ar_pln;               /* Length of protocol address.  */
	unsigned short int ar_op;           /* ARP opcode (command).  */
	/* Ethernet looks like this : This bit is variable sized
	 *        however...  */
	unsigned char __ar_sha[ETH_ALEN];   /* Sender hardware address.  */
	unsigned char __ar_sip[4];          /* Sender IP address.  */
	unsigned char __ar_tha[ETH_ALEN];   /* Target hardware address.  */
	unsigned char __ar_tip[4];          /* Target IP address.  */
};

// check if we need to rotate every ROTATE_CHECK_FREQ log msgs
#ifndef ROTATE_CHECK_FREQ
#define ROTATE_CHECK_FREQ 	10000
//#define ROTATE_CHECK_FREQ 	10
#endif
// actually DO the rotation if the logfile is above ROTATE_THRESH bytes
#ifndef ROTATE_THRESH
#define ROTATE_THRESH		(100*1024*1024)
//#define ROTATE_THRESH		(10)
#endif
// store the last ROTATE_HISTORY log files
#ifndef ROTATE_HISTORY
#define ROTATE_HISTORY	4
#endif


static int rotate_logs_if_needed();
static int flowvisor_log_thresh = FVISORLOG_DEFAULT_THRESH;
char * flowvisor_log_desc[] = {
	"---BAD---",	// for FVISOR_MIN
	"PKT",
	"DBG",
	"LOG",
	"ERR",
};

/****************************************************************
 * shouldn't this be a in libc?  I mean... come on...
 */

void * _realloc_and_check(void * ptr, size_t bytes, char * file, int lineno)
{
	void * ret = realloc(ptr,bytes);
	if(!ret)
	{
		perror("malloc/realloc: ");
		// use fprintf here in addition to flowvisor_err, incase we can't allocate the err msg buf
		fprintf(stderr, "Malloc/Realloc(%zu bytes) failed at %s:%d\n",bytes,file,lineno);
		flowvisor_err("Malloc/Realloc(%zu bytes) failed at %s:%d\n",bytes,file,lineno);
		abort();
	}
	return ret;
}

/*************************************************************************
 * static struct ofpbuf * make_error_msg(int error_code);
 * 	generate an openflow error message, of the correct type
 */

struct ofpbuf * make_error_msg(uint32_t xid, int error_type, int error_code)
{
	int len;
	struct ofpbuf * neo;
	char * buf = make_error_msg_str(xid,error_type,error_code,&len);

	neo = ofpbuf_new(len);
	ofpbuf_put(neo, buf, len);
	free(buf);
	return neo;
}
char * make_error_msg_str(uint32_t xid, int error_type, int error_code, int * msg_len)
{
	char * neo;
	struct ofp_error_msg err;

	err.type = htons(error_type);
	err.code = htons(error_code);
	// err.type = OFPET_BAD_ACTION;
	// err.code = OFBAC_BAD_OUT_PORT;	// need to think about this!
	err.header.version= OFP_VERSION;
	err.header.type = OFPT_ERROR;
	err.header.length  = htons(sizeof(err));
	err.header.xid = xid;
	neo = malloc_and_check(sizeof(err));
	memcpy(neo,&err,sizeof(err));
	*msg_len=sizeof(err);
	return neo;
}
/***********************************************************************************
 * int _flowvisor_log(char * file, size_t line, char * format, ... );
 * 	uniform logging function
 * 		could eventually put to a file somewhere
 */

int flowvisor_log_set_thresh(int loglevel)
{
	int ret = flowvisor_log_thresh;
	flowvisor_log_thresh=loglevel;
	if((flowvisor_log_thresh < FVISOR_DEBUG) &&	// if we are in ultra debug mode
			FVisorLogfile)
		setvbuf(FVisorLogfile,NULL,_IONBF,0);	// turn off buffering
	return ret;
}
int flowvisor_log_get_thresh(void)
{
	return flowvisor_log_thresh;
}


#ifndef FVISORLOG_BUFLEN
#define FVISORLOG_BUFLEN 	65536
#endif
#ifndef FVISORLOG_PADDING
#define FVISORLOG_PADDING 50
#endif

FILE * FVisorLogfile = NULL;
int FVisorLogPrintPreamble = 1;

int flowvisor_set_print_preamble(int print)
{
	int old = FVisorLogPrintPreamble;
	FVisorLogPrintPreamble = print;
	return old;
}
int flowvisor_set_logfile(FILE * new)
{
	if(FVisorLogfile)
		fclose(FVisorLogfile);
	FVisorLogfile = new;
	return 0;
}

int _flowvisor_log_level(char * file, size_t lineno, int exitval, FILE * out, int level, char * format, ... )
{

	static char flowvisor_buf[FVISORLOG_BUFLEN];
	static char flowvisor_logbuf[FVISORLOG_BUFLEN];
	static int rotate_check=0;
	int count;
	int len;
	va_list ap;
	char * eoln;
	static struct timeval startTime;
	static int needStart=1;
	struct timeval now, diff;

	if(needStart == 1)
	{
		needStart=0;
		gettimeofday(&startTime,NULL);
		if(FVisorLogfile == NULL)
			FVisorLogfile = fopen("flowvisor.log","w+");
		if(flowvisor_log_thresh < FVISOR_DEBUG)	// if we are in ultra debug mode
			setvbuf(FVisorLogfile,NULL,_IONBF,0);	// turn off buffering
		else	// else turn on lots of buffering, for performance
			setvbuf(FVisorLogfile,flowvisor_logbuf,_IOFBF,FVISORLOG_BUFLEN);
		out=FVisorLogfile;	// yuck; but it's a cpp hack
	}
	rotate_check++;
	if((rotate_check % ROTATE_CHECK_FREQ)==0)  // the check freq is just for efficiency
	{
		rotate_logs_if_needed();	// this only rotates log if above ROTATE_THRESH
		rotate_check=0;
	}
	assert(FVisorLogfile);

	if(level < flowvisor_log_thresh)
		return -1;		// too uninteresting
	len = 0;
	assert(level > FVISOR_MIN);
	assert(level < FVISOR_MAX);
	if (FVisorLogPrintPreamble)
	{
		// add file:lineno
		snprintf(&flowvisor_buf[len],FVISORLOG_BUFLEN-len,"%s: %s:%zu",flowvisor_log_desc[level],file,lineno);
		len = strlen(flowvisor_buf);
		// add time
		gettimeofday(&now,NULL);
		timersub(&now,&startTime,&diff);
		snprintf(&flowvisor_buf[len],FVISORLOG_BUFLEN-len," -- %ld.%.6ld",diff.tv_sec,diff.tv_usec);
		len = strlen(flowvisor_buf);
		memset(&flowvisor_buf[len],' ',MAX(FVISORLOG_PADDING-len,0)); 	// fill with spaces
		len=FVISORLOG_PADDING;
		flowvisor_buf[len-3]=' ';
		flowvisor_buf[len-2]=':';
		flowvisor_buf[len-1]=' ';
	}
	va_start(ap,format);
	count = vsnprintf(&flowvisor_buf[len],FVISORLOG_BUFLEN-len,format,ap);
	va_end(ap);
	if(count >= FVISORLOG_BUFLEN)
	{
		flowvisor_err("WARNING: flowvisor_buf too short: recompile with -DFVISORLOG_BUFLEN>%d\n",FVISORLOG_BUFLEN);
	}
	len =strlen(flowvisor_buf);
	if(len>0 && flowvisor_buf[len-1] != '\n')
		eoln="\n";
	else 
		eoln="";
	fprintf(stdout,"%s%s",flowvisor_buf,eoln);
	if( exitval != 0)
	{
		fprintf(stderr,"%s%s",flowvisor_buf,eoln);
		fprintf(stderr,"\nEXITing...\n");
		exit(exitval);
	}
	return count;
}



/*********************************************************************************
 * char * config_next_line(FILE * f, int *lineno, char * line, int maxlen);
 * 	skip ahead in the file until we get a line that doesn't start with
 * 	a '#' or isn't just whitespace
 * 	inc lineno with each step
 */

char * config_next_line(FILE * f, int *lineno, char * line, int maxlen)
{
	while(fgets(line,maxlen,f)!=NULL)
	{
		(*lineno)++;
		if(!config_is_comment_or_blank(line))
			return line;
	}
	return NULL;	// ran out of lines
}

/*******************************************************************************
 * int config_next_token(char * token,int * index, char * line);
 * 	return the next token, using whitespace as token seperators
 * 	update *index to where we should start next parsing in the line
 *
 * 	return 1 if we found something, zero otherwise
 */

int config_next_token(char * token,int * char_index, const char * line)
{
	int start;
	int len = strlen(line);
	// skip whitespace
	while((*char_index)<len)
	{
		if(!config_is_whitespace(line[*char_index]))
			break;
		(*char_index)++;
	}
	if(*char_index>=len)
		return 0;	// found nothing but whitespace
	start=*char_index;
	(*char_index)++;
	// skip non-whitespace
	while((*char_index)<strlen(line))
	{
		if(config_is_whitespace(line[*char_index]))
			break;
		(*char_index)++;
	}
	strncpy(token,&line[start],*char_index - start);
	token[*char_index-start]=0;	// hate strncpy() -- it really should do this for you
	return 1;
}


/***********************************************************************************
 * int config_is_whitespace(char c);
 * 	return 1 if space, tab,newline, CR
 */

int config_is_whitespace(char c)
{
	switch(c)
	{
		case ' ':
		case '\t':
		case '\n':
		case '\r':
			return 1;
		default:
			return 0;
	};
}

/***************************************************************************************
 * int config_is_comment(char *line);
 * 	return 1 if the first non-whitespace char is a '#'
 * 	0 otherwise
 */


int config_is_comment_or_blank(char *line)
{
	int char_index=0;
	int len = strlen(line);
	while(char_index< len)
	{
		if(!config_is_whitespace(line[char_index]))
		{
			if(line[char_index] == '#')
				return 1;
			else
				return 0;
		}
		char_index++;
	}
	return 1;		// got to end of line without finding non-whitespace: blank!
}


/*********************************************************************************************
 * int reverse_strcmp(const char * s1, const char * s2);
 * 	like strcmp, but from the last index to the first, up to the max len of the two args
 */

int reverse_strcmp(const char * s1, const char * s2)
{
	int i1,i2;
	i1=strlen(s1)-1;
	i2=strlen(s2)-1;
	while((i1>=0) && (i2>=0))
	{
		if(s1[i1] != s2[i2])
			return s1[i1] - s2[i2];
		i1--;
		i2--;
	}
	return 0;
}

/******************************************************************************
 * given a file "alice.guest"
 * 	return a newly malloc'd string "alice"
 */
char * name_from_file(char * filename)
{
	char *ptr;
	char * ret;
	ptr = rindex(filename,'/'); //  "/the/leading/path/foo.guest" --> "foo.guest"
	if (ptr == NULL)	
		ptr = filename;
	else 
		ptr++;			// skip the / if we found it
	assert(strlen(ptr)>0);
	ret = strdup(ptr);
	ptr = rindex(ret,'.');		// "foo.guest" --> "foo"
	*ptr=0;
	return ret;
}



/************************************************************************************
 * opfp_type to string
 */


char * ofp_type_to_string(int ofp_type)
{
	switch(ofp_type)
	{
		case OFPT_HELLO:               /* Symmetric message */
			return "ofp_hello";
		case OFPT_ERROR:               /* Symmetric message */
			return "ofp_error";
		case OFPT_ECHO_REQUEST:        /* Symmetric message */
			return "ofp_echo_request";
		case OFPT_ECHO_REPLY:          /* Symmetric message */
			return "ofp_echo_reply";
		case OFPT_VENDOR:              /* Symmetric message */
			return "ofp_vendor";

		/* Switch configuration messages. */
		case OFPT_FEATURES_REQUEST:    /* Controller/switch message */
			return "ofp_features_request";
		case OFPT_FEATURES_REPLY:      /* Controller/switch message */
			return "ofp_features_reply";
		case OFPT_GET_CONFIG_REQUEST:  /* Controller/switch message */
			return "ofp_config_request";
		case OFPT_GET_CONFIG_REPLY:    /* Controller/switch message */
			return "ofp_config_reply";
		case OFPT_SET_CONFIG:          /* Controller/switch message */
			return "ofp_set_config";

		/* Asynchronous messages. */
		case OFPT_PACKET_IN:           /* Async message */
			return "ofp_packet_in";
		case OFPT_FLOW_EXPIRED:        /* Async message */
			return "ofp_flow_expired";
		case OFPT_PORT_STATUS:         /* Async message */
			return "ofp_port_status";

		/* Controller command messages. */
		case OFPT_PACKET_OUT:          /* Controller/switch message */
			return "ofp_packet_out";
		case OFPT_FLOW_MOD:            /* Controller/switch message */
			return "ofp_flow_mod";
		case OFPT_PORT_MOD:            /* Controller/switch message */
			return "ofp_port_mod";

		/* Statistics messages. */
		case OFPT_STATS_REQUEST:       /* Controller/switch message */
			return "ofp_stats_request";
		case OFPT_STATS_REPLY:          /* Controller/switch message */
			return "ofp_stats_reply";
		default:
			flowvisor_err("BAD openflow header type %d\n");
			abort();
	};
}
/**********************************************************************************
 * 	int ip_summary(char * dstbuf,int size, char * arp)
 */

int ip_summary(char * dstbuf,int size, char * ipbuf)
{
	int offset;
	struct ether_header *eth = (struct ether_header * ) ipbuf;
	int count;
	struct iphdr *ip;
	struct icmphdr * icmp;
	struct tcphdr * tcp;

	char srcipbuf[BUFLEN];
	char dstipbuf[BUFLEN];
		
	assert(ntohs(eth->ether_type) == ETHERTYPE_IP);
	offset = sizeof(struct ether_header);
		
		
	ip = (struct iphdr *)&ipbuf[offset];

	inet_ntop(AF_INET,&ip->saddr,srcipbuf,BUFLEN);
	inet_ntop(AF_INET,&ip->daddr,dstipbuf,BUFLEN);

	count = snprintf(dstbuf,size,"_s=%s_d=%s",srcipbuf,dstipbuf);
	size-=count;
	dstbuf+=count;

	offset+=ip->ihl *4;
	switch(ip->protocol)
	{	
		case IPPROTO_ICMP:
			icmp = (struct icmphdr *) &ipbuf[offset];
			return count + snprintf(dstbuf,size,"_ICMP_code=%d_type=%d",
					icmp->code,
					icmp->type);
			break;	// redundant
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) &ipbuf[offset];
			return count + snprintf(dstbuf,size,"_TCP_sport=%d_dport=%d",
					ntohs(tcp->source),
					ntohs(tcp->dest));
		default:
			return count + snprintf(dstbuf,size,"_proto=%d", ip->protocol);
	};
}
/**********************************************************************************
 * 	int arp_summary(char * dstbuf,int size, char * arp)
 */

int arp_summary(char * dstbuf,int size, char * arpbuf)
{
	int offset;
	struct ether_header *eth = (struct ether_header * ) arpbuf;
	struct arp_ether_hdr * ahdr ;
		
	if(ntohs(eth->ether_type) == ETHERTYPE_VLAN)
		offset = 2 + sizeof(struct ether_header);
	else 
		offset = sizeof(struct ether_header);
		
		
	ahdr = (struct arp_ether_hdr *)&arpbuf[offset];
	if(ahdr->ar_hrd !=htons(ARPHRD_ETHER))
		return snprintf(dstbuf,size,"_non_ether_hdr");
	if(ahdr->ar_pro != htons(ETHERTYPE_IP))
		return snprintf(dstbuf,size,"_non_IP_proto");
	return snprintf(dstbuf,size,"_from_addr=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x_ip=%d.%d.%d.%d_"
			"for_addr=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x_ip=%d.%d.%d.%d_",
			ahdr->__ar_sha[0],
			ahdr->__ar_sha[1],
			ahdr->__ar_sha[2],
			ahdr->__ar_sha[3],
			ahdr->__ar_sha[4],
			ahdr->__ar_sha[5],
			ahdr->__ar_sip[0],
			ahdr->__ar_sip[1],
			ahdr->__ar_sip[2],
			ahdr->__ar_sip[3],
			ahdr->__ar_tha[0],
			ahdr->__ar_tha[1],
			ahdr->__ar_tha[2],
			ahdr->__ar_tha[3],
			ahdr->__ar_tha[4],
			ahdr->__ar_tha[5],
			ahdr->__ar_tip[0],
			ahdr->__ar_tip[1],
			ahdr->__ar_tip[2],
			ahdr->__ar_tip[3]);
}
/**********************************************************************************8
 * given an ofpbuf, return "ofptype(xid)+some_extra_info"
 * 	critical -- keep as one string... no whitespace
 *
 * NOT REENTRANT!
 */

char * ofpbuf_msg_summary(struct ofpbuf * msg)
{
	struct ofp_header * ofph;
	ofph = (struct ofp_header *) ofpbuf_at(msg,0,sizeof(struct ofp_header));
	return ofp_msg_summary(ofph);
}
char * ofp_msg_summary(struct ofp_header * ofph)
{
	static char buf[BUFLEN];
	char tmp[BUFLEN];
	int offset;
	struct ether_header * eth;
	struct ofp_packet_out * po;
	int count=0;

	assert(ofph);
	tmp[0]=0;	// no extra msg, by default
	switch(ofph->type)
	{
		struct ofp_packet_in * pi;
		case OFPT_PACKET_IN:
			// check if lldp packet
			pi = (struct ofp_packet_in * ) ofph;
			if(ntohs(ofph->length)>=(sizeof(struct ofp_packet_in)+sizeof(struct ether_header)))
			{
				eth = (struct ether_header *)pi->data;		// advance 1 ofp_packet_in size
				switch(ntohs(eth->ether_type))
				{
					case 0xcc88: 	// LLDP
						count+=snprintf(&tmp[count],BUFLEN-count,"-LLDP");
						break;
					case ETHERTYPE_IP:
						count+=snprintf(&tmp[count],BUFLEN-count,"-IP");
						count+=ip_summary(&tmp[count],BUFLEN-count,(char *)pi->data);
						break;
					case ETHERTYPE_ARP:
						count+=snprintf(&tmp[count],BUFLEN-count,"-ARP");
						count+=arp_summary(&tmp[count],BUFLEN-count,(char *)pi->data);
						break;
					default:
						count+=snprintf(&tmp[count],BUFLEN-count,"-%x",eth->ether_type);
				};
				if(pi->buffer_id != -1)
					count+=snprintf(&tmp[count],BUFLEN-count,"-bufid=%x",ntohl(pi->buffer_id));
			}
			count+=snprintf(&tmp[count],BUFLEN-count,"-from_port_%d",ntohs(pi->in_port));
			break;
		case OFPT_PACKET_OUT:
			po = (struct ofp_packet_out * ) ofph;
			offset = sizeof(struct ofp_packet_out) + ntohs(po->actions_len);
			if(ntohs(ofph->length)>=(offset+sizeof(struct ether_header)))	// is there a valid ethernet header afterwards?
			{
				eth = (struct ether_header *) ((char *)po+ offset);		// advance 1 ofp_packet_out size
				switch(ntohs(eth->ether_type))
				{
					// case 0x88cc: 	// LLDP
					case 0xcc88: 	// LLDP
						count+=snprintf(&tmp[count],BUFLEN-count,"-LLDP");
						break;
					case ETHERTYPE_IP:
						count+=snprintf(&tmp[count],BUFLEN-count,"-IP");
						count+=ip_summary(&tmp[count],BUFLEN-count,(char *)eth);
						break;
					case ETHERTYPE_ARP:
						count+=snprintf(&tmp[count],BUFLEN-count,"-ARP");
						count+=arp_summary(&tmp[count],BUFLEN-count,(char *)eth);
						break;
					default:
						count+=snprintf(&tmp[count],BUFLEN-count,"-%x",eth->ether_type);
				};
			}
			if(po->buffer_id != -1)
				count+=snprintf(&tmp[count],BUFLEN-count,"-bufid=%x",ntohl(po->buffer_id));
			break;
	//	default:

	}
	snprintf(buf,BUFLEN,"%s(xid=%x)%s",ofp_type_to_string(ofph->type),ofph->xid,tmp);
	return buf;
}
/********************************************************************
 * static int rotate_logs_if_needed();
 * 	test if our log file is above a certain size (ROTATE_THRESH), and if yes, rotate it out
 * 	store teh last ROTATE_HISTORY log files
 */


static int rotate_logs_if_needed()
{
	char srcbuf[BUFLEN];
	char dstbuf[BUFLEN];
	int err;
	int i;
	struct stat sbuf;
	err = fstat( fileno(FVisorLogfile) , &sbuf);
	if(err)
	{	
		flowvisor_err("fstat returned: %s", strerror(errno));
		return -1;
	}
	if(sbuf.st_size < ROTATE_THRESH)	// not yet time to rotate
		return 0;
	if(!S_ISREG(sbuf.st_mode))		// don't rotate non-regular files 
		return 0;
	assert(ROTATE_HISTORY>1);		// that would be silly
	for(i=ROTATE_HISTORY;i>0;i--)
	{
		snprintf(srcbuf,BUFLEN,"flowvisor.log-%d",i-1);
		snprintf(dstbuf,BUFLEN,"flowvisor.log-%d",i);
		if(stat(srcbuf,&sbuf) != -1)	 // if exists 
			rename(srcbuf,dstbuf);	 // move log down the line
	}
	snprintf(srcbuf,BUFLEN,"flowvisor.log");
	snprintf(dstbuf,BUFLEN,"flowvisor.log-1");
	rename(srcbuf,dstbuf);	 // always move the current log file out of the way
	
	fclose(FVisorLogfile);
	// open new logfile
	FVisorLogfile = fopen("flowvisor.log","w+");
	return 1;
}
