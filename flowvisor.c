/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/****************************
 * CODE TODO:
 * 	this is the *worst* code I've ever written
 *
 * 	some things are static, some are dynamic
 * 	some parameters take switchId,guestId as param, some take indexes
 * 	variable naming is horribly inconsistent
 * 	the poll() loop, as implemented here, is very inefficient
 * 	- needs a total rewrite
 */

//#include <config.h>
#include <stdio.h> /*keqiang*/
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "/usr/include/pcap.h" // Sourav:
#include <pthread.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <netdb.h>

#include "ofpbuf.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "fault.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "util.h"	// openflow specific
#include "utils.h"	// flowvisor specific
#include "timeval.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"

#include "flowvisor.h"

#include "vlog.h"


#define THIS_MODULE VLM_rconn
#define MAXBYTES2CAPTURE 2048 
/* --max-idle: Maximum idle time, in seconds, before flows expire. */
int max_idle = 60;
pthread_t x;
int NeedConfig=0;
int ShouldStop = 0;
int newswitch = 0;
pthread_mutex_t lock;
/***************************************************
function delclearations 
*/

void parse_options(flowvisor_context * fv_ctx, int argc, char *argv[]);
void usage(void);
struct flowvisor_context * flowvisor_context_malloc();
void init_guest(struct flowvisor_context *fv_ctx);
void handle_usr1_signal(int sig );
void handle_hup_signal(int sig );
struct ofpbuf *new_feature_request();
struct ofpbuf *new_flow_mod_flush();
void new_switch(flowvisor_context *fv_ctx, struct vconn *vconn, const char *name);
int do_new_switches(flowvisor_context *fv_ctx);
void* handle_switches(void * parm);
static int handle_switch(flowvisor_context * fv_ctx, int switchIndex);
static void handle_switch_unidentified(flowvisor_context * fv_ctx, int switchIndex);
static int connect_switch_to_guest(flowvisor_context *fv_ctx, int switchIndex, int guestIndex);
static void handle_switch_identified(flowvisor_context * fv_ctx, int switchIndex);
void * handle_guest(void * parm);
int wait_on_all(flowvisor_context * fv_ctx);
void *listen_raw(void * parms);
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet);
/*******************************struct declearation
*/

struct thread_parm_t{
  struct flowvisor_context * context;
  char  interface[128];
};

/*********************************************
 *      parse options
 ********************************/
void
parse_options(flowvisor_context * fv_ctx, int argc, char *argv[])
{
        int loglevel;
        enum { OPT_MAX_IDLE = UCHAR_MAX + 1 };
        static struct option long_options[] = {
                        {"detach",      no_argument, 0, 'D'},
                        {"pidfile",     optional_argument, 0, 'P'},
                        {"hub",         no_argument, 0, 'H'},
                        {"noflow",      no_argument, 0, 'n'},
                        {"max-idle",    required_argument, 0, OPT_MAX_IDLE},
                        {"verbose",     optional_argument, 0, 'v'},
                        {"help",        no_argument, 0, 'h'},
                        {"version",     no_argument, 0, 'V'},
                        VCONN_SSL_LONG_OPTIONS
                        {0, 0, 0, 0},
        };
        char *short_options = long_options_to_short_options(long_options);

        for (;;) {
                int c;
                int indexptr = 0 ;

                c = getopt_long(argc, argv, short_options, long_options, &indexptr);
                if (c == -1) {
                        break;
                }

                switch (c) {
                case 'D':
                set_detach();
                break;

                case 'P':
                        set_pidfile(optarg);
                        break;

                case OPT_MAX_IDLE:
                        if (!strcmp(optarg, "permanent")) {
                                max_idle = OFP_FLOW_PERMANENT;
                        } else {
                                max_idle = atoi(optarg);
                                if (max_idle < 1 || max_idle > 65535) {
                                        ofp_fatal(0, "--max-idle argument must be between 1 and "
                                                        "65535 or the word 'permanent'");
                                }
                        }
                        break;

                case 'h':
                        usage();
			break;
                case 'V':
                        printf("%s \n", argv[0]);
                        exit(EXIT_SUCCESS);

                case 'v':
                        if(optarg)
                                loglevel=atoi(optarg);
                        else
                                loglevel=FVISOR_DEBUG;
                        if( loglevel < FVISOR_DEBUG)
                                vlog_set_verbosity(NULL);
                        flowvisor_log_set_thresh(loglevel);
                        flowvisor_log("set logging threshold to %d'\n",loglevel);
                        break;

                        VCONN_SSL_OPTION_HANDLERS

                case '?':
                        exit(EXIT_FAILURE);

                default:
                        abort();
                }
        }
        free(short_options);
}
/***************************************************************
 *      usage(void)
 *                      prints usage info
 */

void
usage(void)
{
        printf("%s: OpenFlow flowvisor\n"
                        "usage: %s [OPTIONS] METHOD [METHOD ...] \n"
                        "where METHOD is any OpenFlow connection method.\n",
                        program_name, program_name);
        vconn_usage(true, true,false);
        printf("\nOther options:\n"
                        "  -D, --detach            run in background as daemon\n"
                        "  -P, --pidfile[=FILE]    create pidfile (default: %s/controller.pid)\n"
                        "  -H, --hub               act as hub instead of learning switch\n"
                        "  -n, --noflow            pass traffic, but don't add flows\n"
                        "  --max-idle=SECS         max idle time for new flows\n"
                        "  -v, --verbose=MODULE[:FACILITY[:LEVEL]]  set logging levels\n"
                        "  -v, --verbose           set maximum verbosity level\n"
                        "  -h, --help              display this help message\n"
                        "  -V, --version           display version information\n");
        exit(EXIT_SUCCESS);
}
/*******************************************************************************
 *
 *
 */
struct flowvisor_context * flowvisor_context_malloc()
{
        flowvisor_context * fv_ctx = malloc(sizeof(flowvisor_context));
        if(!fv_ctx)
        {
                perror("malloc:");
                abort();
        }
        memset(fv_ctx,0,sizeof(struct flowvisor_context));
        fv_ctx->EfficiencyLoops = 1;    // down from 50, from original code
        return fv_ctx;
}
void handle_usr1_signal(int sig )
{
        flowvisor_log("Got SIGUSR1");
        ShouldStop=1;
}
void handle_hup_signal(int sig )
{
        flowvisor_log("Got SIGHUP");
        NeedConfig=1;
}

/************************************************************
 * do_new_switches(fv_ctx)
 *      step through each switch listenning connection (typically only one)
 *      and see if any new switches have connected to us
 */
int do_new_switches(flowvisor_context *fv_ctx)
{
        int i;
        for (i = 0; i < fv_ctx->n_listeners && fv_ctx->n_switches < MAX_SWITCHES; ) {
                struct vconn *new_vconn;
                int retval;

                retval = pvconn_accept(fv_ctx->listeners[i], OFP_VERSION,&new_vconn);
                //printf("%d, do_new_switch: %d\n",i, retval);
                //printf("do_new_switch, equal EAGAIN? %d\n", retval==EAGAIN);
                if (!retval || retval == EAGAIN) {
                        if (!retval) {
				printf("%d, do_new_switch: %d\n",i, retval);
                        	printf("do_new_switch, equal EAGAIN? %d\n", retval==EAGAIN);
                                new_switch(fv_ctx, new_vconn, "tcp");
                        }
                        i++;
                } else {
                        pvconn_close(fv_ctx->listeners[i]);
                        fv_ctx->listeners[i] = fv_ctx->listeners[--fv_ctx->n_listeners];
                }
        }
        return 0;
}

/*****************************************************
 *      allocate a new switch
 *              Send out a features request to learn about the switch
 */

void new_switch(flowvisor_context *fv_ctx, struct vconn *vconn,
                const char *name)
{
        struct switch_ * sw;
        static int new_switchID=-1;
        //int test1, test2; /*keqiang*/
        sw = &fv_ctx->switches[fv_ctx->n_switches++];
        printf("new_switch: fc_ctx->n_switches %d\n", fv_ctx->n_switches);
        sw->rc= rconn_new_from_vconn(name, vconn);
        sw->id = new_switchID--;
        flowvisor_log("NEW SWITCH: temp id=%d index=%d rconn_name=%s\n",
                        sw->id, fv_ctx->n_switches-1,rconn_get_name(sw->rc));
        //printf("NEW SWITCH: temp id=%d index=%d rconn_name=%s\n", sw->id, fv_ctx->n_switches-1,rconn_get_name(sw->rc));

	/****update newswitch**********/
	newswitch = 1;
        // flush any existing flows.. should be redundant
        //test1 = rconn_send(sw->rc, new_flow_mod_flush(), NULL);
        // Send a features request to which switch this is
        //test2 = rconn_send(sw->rc, new_feature_request(), NULL);
        //printf("new_switch: teset1 and test2, %d, %d\n", test1, test2);
}

/***************************************************************************
 * new_feature_request()
 *      Create a new feature request packet in an ofpbuf struct
 */

struct ofpbuf *new_feature_request()
{
        struct ofpbuf *buf;
        struct ofp_header *h;

        buf = ofpbuf_new(sizeof(struct ofp_header));
        ofpbuf_put_zeros(buf, sizeof(struct ofp_header));
        h = (struct ofp_header *)buf->data;
        h->version = OFP_VERSION;
        h->type = OFPT_FEATURES_REQUEST;
        h->length = htons(sizeof(struct ofp_header));
        h->xid = 0xdeadbeef;

        return buf;
}
struct ofpbuf *new_flow_mod_flush()
{
        struct ofpbuf *buf;
        struct ofp_flow_mod *fm;
        unsigned int len = sizeof(struct ofp_flow_mod);

        buf = ofpbuf_new(len);
        ofpbuf_put_zeros(buf, len);
        fm = (struct ofp_flow_mod *)buf->data;
        fm->header.version = OFP_VERSION;
        fm->header.type = OFPT_FLOW_MOD;
        fm->header.length = htons(len);
        fm->header.xid = 0xcafebeef;
        fm->buffer_id = -1;
        fm->match.wildcards = htonl(OFPFW_ALL);
        fm->command = htons(OFPFC_DELETE);
        fm->out_port = OFPP_NONE;

        return buf;
}
/*****************************************
 * handle_switches(flowvisor_context *fv_ctx)
 *      foreach switch, check to see if it's sent something
 *      if yes, send it off to individual switch handlers
 */
void* handle_switches(void * parm)
{
	
	struct flowvisor_context *fv_ctx;
	fv_ctx = (struct flowvisor_context *) parm;
        int i,iteration, j = 0;
        // FIXME: This new ordering causes all iterations for a switch/guest
        // to be grouped
	//while (1) {
	//j ++;
	//if (j == 50000) {
	//	printf("DEBUG: handle_switches\n");
	//	j = 0;
	//}
        for (i = 0; i < fv_ctx->n_switches;i++ ) {              // foreach switch
                for (iteration = 0; iteration < fv_ctx->EfficiencyLoops; iteration++) {
                        bool progress = false;
                        int retval = handle_switch(fv_ctx,i);
                        //printf("Bingo, I am IN hand_switches: retval: %d\n", retval);
                        if (!retval || retval == EAGAIN) {
                                if (!retval) {
                                        progress = true;
                                }
                        } else {
				//printf("TODO: destroy switch\n");
                                //switch_destroy(fv_ctx,i);
                                break;          // we just deleted someone
                                // and moved someone else into our slot
                                // we need to let them get a processing changce
                        }
                        if (!progress) {
                                break;
                        }
                }
        }
	//}//while
        return NULL;
}

/**************************************************
 *      given a switch and a policy, see if that switch has
 *      any messages, and if so, which guest to send them to
 **************************/

static int
handle_switch(flowvisor_context * fv_ctx, int switchIndex)
{
        unsigned int packets_sent;
        int retval;
        struct switch_ *sw = &fv_ctx->switches[switchIndex];

        // flowvisor_debug("handle_switch(switchID=%d)\n",sw->id);      // performance hog
        packets_sent = rconn_packets_sent(sw->rc);
        //printf("handle_switch: packets_sent: %d\n", packets_sent);
        // Work out whether we've identified the switch yet
        if (sw->id >= 0)
                handle_switch_identified(fv_ctx, switchIndex);
        else
                handle_switch_unidentified(fv_ctx, switchIndex);

        rconn_run(sw->rc);              // update anything that needs updating

        retval= (!rconn_is_alive(sw->rc) ? EOF          // YUCK! nested ?: stuff...
                        : rconn_packets_sent(sw->rc) != packets_sent ? 0
                                        : EAGAIN);
        if(retval != EAGAIN)    // only print if it died; performance hog
                flowvisor_debug("       return %d\n",retval);
	//printf("in handleswitch endi: retval: %d\n", retval);
        return retval;
}

static void
handle_switch_unidentified(flowvisor_context * fv_ctx, int switchIndex)
{
        struct ofpbuf *msg;
        int i;
        struct switch_ *sw = &fv_ctx->switches[switchIndex];

        flowvisor_debug("handle_switch_unidentified(switchID=%d)\n",sw->id);
        msg = rconn_recv(sw->rc);
        if(msg) {               // if we actually got something from the switch
                flowvisor_debug("GOT MSG from SWITCH, MAN!\n");

                sw->id = 1234; // give it a positive number
                flowvisor_debug("handle_unidentified: sw-id: %d\n", sw->id);
		flowvisor_log("fv_ctx->n_guests:%d\n", fv_ctx->n_guests);
                // Connect to guests if we've identified the switch
                if (sw->id >= 0) {
                        for(i=0;i<fv_ctx->n_guests;i++)
                                connect_switch_to_guest(fv_ctx,switchIndex, i);
                        flowvisor_log("CONNECTED SWITCHid=%d index=%d rconn_name=%s\n",sw->id, fv_ctx->n_switches-1,rconn_get_name(sw->rc));
                }

                // ofpbuf_delete(msg);  NO!  Causes double free()
        }
}

/***********************************************
 * connect_switch_to_guest(htx, switchIndex,guestIndex)
 *      make a new connection to guestID to alert them to
 *      the presence of switchID
 ************/
static int connect_switch_to_guest(flowvisor_context *fv_ctx, int switchIndex, int guestIndex)
{
        struct vconn * neo_v;
        struct rconn * neo_r;
        int retval;
        struct guest * g = &fv_ctx->guests[guestIndex];
        struct switch_ *sw = &fv_ctx->switches[switchIndex];
        struct switch_ *guest_sw;
        // struct _switch * sw;
	flowvisor_log("In connect_switch_to_guest\n");
        if(g->n_switches >= MAX_SWITCHES)
        {
                flowvisor_err("%s: too many switches: increase buffer or make it dynamic", g->vconn_name);
                return -1;
        }
	//g->vconn name should be initialized..
        // create a connection to the guest's controller
        retval = vconn_open(g->vconn_name,OFP_VERSION, &neo_v);
        flowvisor_debug("connecting to the guest cotroller...OFP_version:%d,%d\n", OFP_VERSION, retval);
        if (retval) {
                flowvisor_err("%s: connect: %s", g->vconn_name, strerror(retval));
                return -1;
        }
        printf("%s,%d  \n", "i am in connect_switch_to_huest", retval);
        printf("connect_switch_to_guest: g->vconn_name: %s  \n", g->vconn_name);
        // convert it to a reliable connection
        neo_r = rconn_new_from_vconn( g->vconn_name, neo_v);
        // update struct
        guest_sw = &g->guest_switches[g->n_switches];
        guest_sw->rc= neo_r;
        guest_sw->id= sw->id;
        g->n_switches++;
        return 0;
}

static void
handle_switch_identified(flowvisor_context * fv_ctx, int switchIndex)
{
        struct ofpbuf *msg;
        struct switch_ * guest_sw;
        int guest_index = 0; //there is only one guest in our case
	struct guest * g = &fv_ctx->guests[guest_index];
        struct switch_ *sw = &fv_ctx->switches[switchIndex];
	guest_sw = &g->guest_switches[switchIndex];
        msg = rconn_recv(sw->rc);
        if(msg) {               // if we actually got something from the switch
		pthread_mutex_lock(&lock);
		rconn_send(guest_sw->rc,ofpbuf_clone(msg),NULL);
		pthread_mutex_unlock(&lock);
		//flowvisor_log("SEND MSG to GUEST\n");
	}
}

void init_guest(struct flowvisor_context *fv_ctx)
{
	struct guest g;
	const char* name = "tcp:127.0.0.1";
	fv_ctx->n_guests = 0;
	fv_ctx->n_switches = 0;
	fv_ctx->n_listeners = 0;

	g.magic = FV_GUEST_MAGIC;
	g.n_switches = 0;
	flowvisor_log("Initialize the GUEST\n");
	strncpy(g.vconn_name,name,MAX_VCONN_NAME_LEN);	
	fv_ctx->guests[fv_ctx->n_guests++] = g;
	flowvisor_log("Initialize the GUEST STATUS:%d\n", fv_ctx->n_guests);
}

/******************************************************
 * static int handle_guest(struct guest *g, const policy *, int n_switches, struct switch_ switches[]);
 *              given a guest and a policy, see if that guest has
 *              anything to say, and if it should be allowed; send it if allowed, else send error
 */
void* handle_guest(void * parm)
{
        unsigned int packets_sent;
        struct ofpbuf *msg;
        int i, j=0;
	struct ofp_header *oh;
	
	struct flowvisor_context *fv_ctx;
        fv_ctx = (struct flowvisor_context *) parm;

        struct guest * g = &fv_ctx->guests[0];
	struct rconn * this;
	struct switch_ *dst_sw;
	//while (1) {
	//j ++ ;
	//if (j == 50000){
	
	//	printf("DEBUG: in handle_guest, g->n_switches %d\n", g->n_switches);
	//	j = 0;
	//}
	for(i=0; i< g->n_switches; i++) // foreach guest controller connection, 1 per switch
        {
		//printf("DEGUB IN handle_guest thread\n");
                this= g->guest_switches[i].rc;	
		dst_sw = &fv_ctx->switches[i]; 

		//packets_sent = rconn_packets_sent(this);
		//flowvisor_log("HANDLE_GUEST, packets_sent: %d\n", packets_sent);
                msg = rconn_recv(this);
		if(msg){
			oh = msg->data;
			if (oh->type != OFPT_PACKET_OUT && oh->type != OFPT_FLOW_MOD){
			rconn_send(dst_sw->rc,msg,NULL);
			flowvisor_log("HANDLE_GUEST, SEND MSG to SWITCH\n");
			}
			
		}
	}
	//}//while
	return NULL;
}

/********************************************************
 * wait_on_all()
 *      set all of the vcons and rcons to the wait state
 *      in prepartion for a poll_block()
*/ 
int wait_on_all(flowvisor_context * fv_ctx)
{
        int i,j;
        if (fv_ctx->n_switches < MAX_SWITCHES) {        // IF we still have room for more switches
                for (i = 0; i < fv_ctx->n_listeners; i++) {
                        pvconn_wait(fv_ctx->listeners[i]);
                }
        }
        for (i = 0; i < fv_ctx->n_switches; i++) {
                struct switch_ *sw = &fv_ctx->switches[i];
                rconn_run_wait(sw->rc);
                rconn_recv_wait(sw->rc);
        }
        for (i = 0; i < fv_ctx->n_guests; i++) {
                struct guest *g= &fv_ctx->guests[i];
                for(j = 0; j < g->n_switches; j++) {
                        rconn_run_wait(g->guest_switches[j].rc);
                        rconn_recv_wait(g->guest_switches[j].rc);
                }
        }
	return 0;
}

/* listenraw: Opens network interface and calls pcap_loop() */

void *listen_raw(void* parms){

	struct thread_parm_t * parameters;
	parameters = (struct thread_parm_t *) parms;
	struct flowvisor_context *fv_cur_ctx = parameters->context;
	char * interface = parameters->interface;
	pcap_t *descr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device=NULL;
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
 
	struct bpf_program fp; //the complied filter
	char filter_exp[] = "udp";//filter expression
	bpf_u_int32 mask; //Our net mask
	bpf_u_int32 net; //our IP

	device = interface;

	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Can't get netmask for device %s\n", device);
		 net = 0;
		 mask = 0;
	}
	/*
	if ( (device = pcap_lookupdev(errbuf)) == NULL){
        	fprintf(stderr, "ERROR: %s\n", errbuf);
        	exit(1);
	}
 	*/
	flowvisor_log("Opening device %s\n", device);
	//Open device in promiscuous mode
        if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
                fprintf(stderr, "ERROR: %s\n", errbuf);
                exit(1);
        }

	// Compile and apply the filter
	if (pcap_compile(descr, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
		exit(1);
	}
	if (pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
		exit(1);
 	}

	//Loop forever & call processPacket() for every received packet
	if ( pcap_loop(descr, -1, processPacket, (u_char *)fv_cur_ctx) == -1){
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}
	return NULL;
}


/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */


void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){

 	//int i=0;
	//struct timeval cur_time;
	struct flowvisor_context *myctx = (struct flowvisor_context *)arg;
	struct guest *g= &myctx->guests[0]; //there is only one guest
	
	//printf("Packet Count: %d\n", ++(*counter));
	//flowvisor_log("processPacket, Received Packet Size: %d\n", pkthdr->len);
	//printf("Payload:\n");

	if (pkthdr->len <=128)	{	
	/*try to generate packet_in message to guest
	*/
	unsigned int pkt_len = pkthdr->len;
	struct ofpbuf *buf;
        struct ofp_packet_in *opi;
        unsigned int len = offsetof(struct ofp_packet_in, data) + pkt_len;

        buf = ofpbuf_new(len);
        ofpbuf_put_zeros(buf, len);
        opi = (struct ofp_packet_in *)buf->data;
        opi->header.version = OFP_VERSION;
        opi->header.type = OFPT_PACKET_IN;
        opi->header.length = htons(len);
        opi->header.xid = 0xcafebeef;
        opi->buffer_id = -1; //not buffered in switch
        opi->total_len = htons(pkt_len); // ether frame length
        opi->in_port = htons(OFPP_NONE); //FIXME: assume that it is from port None
        opi->reason = OFPR_NO_MATCH;
        //opi->data = packet;// the pointer
        memcpy(opi->data, packet, pkt_len);
	pthread_mutex_lock(&lock);
        rconn_send(g->guest_switches[0].rc, buf, NULL);	//there is only in switch and on eguest
	pthread_mutex_unlock(&lock);
	//gettimeofday(&cur_time, NULL);
	//printf("Sent Packet_In Message (Raw) to GUEST: %ld.%ld\n", cur_time.tv_sec, cur_time.tv_usec);
	}
 	/*
	for (i=0; i<pkthdr->len; i++){

   		if ( isprint(packet[i]) ) // If it is a printable character, print it
        	printf("%c ", packet[i]);
    		else
        	printf(". ");

     		if( (i%16 == 0 && i!=0) || i==pkthdr->len-1 )
        		printf("\n");
  	}
	*/
 	return;
}


/**************************************************************************
*****main
****
*/

int main(int argc, char *argv[])
{
	int retval;
	int i, rc, round = 0;
	struct flowvisor_context *fv_ctx = flowvisor_context_malloc();
	struct thread_parm_t         *parm=NULL;

	struct timeval last_stats_dump;
	//struct timeval s1,s2,s3;
	parse_options(fv_ctx,argc, argv);
	// create stats file
	gettimeofday(&last_stats_dump,NULL);
	// openflow/controller leftovers
	set_program_name(argv[0]);
	register_fault_handlers();
	signal(SIGUSR1,handle_usr1_signal);
	signal(SIGHUP,handle_hup_signal);
	time_init();
	vlog_init();
	init_guest(fv_ctx);

        /***********threads********************
	*/
	/* this variable is our reference to the second thread */
	pthread_t listen_raw_thread;
	pthread_t handle_switches_thread;
	pthread_t handle_guest_thread;
	/*************paramterns*************
	*/
	if (argc - optind < 1) {
		ofp_fatal(0, "at least one vconn argument required; use --help for usage");
	}

	retval = vlog_server_listen(NULL, NULL);
	if (retval) {
		ofp_fatal(retval, "Could not listen for vlog connections");
	}
	/****
	 * Step through each cmdline arg and add a passive or active connection
	 * for each argument until we have parsed all args or have run out of room
	 *****/
	for (i = optind; i < argc; i++) {
		const char *name = argv[i];
		struct vconn *vconn;

		printf("%s  \n", argv[i]);
		retval = vconn_open(name, OFP_VERSION, &vconn);
		if (retval == EAFNOSUPPORT) {	// really?  copied from OF/controller/controller.c
			struct pvconn * pvconn;
			printf("activeL %d, %s  \n", retval, argv[i]);
			retval = pvconn_open(name, &pvconn);
			printf("passive: %d, %s  \n", retval, argv[i]);
			if(retval) {
				flowvisor_err("%s: connect: %s", name, strerror(retval));
				continue;
			}
			if (fv_ctx->n_listeners >= MAX_LISTENERS) {
				ofp_fatal(0, "max %d passive connections", fv_ctx->n_listeners);
			}
			printf("listener: %d\n", fv_ctx->n_listeners);
			fv_ctx->listeners[fv_ctx->n_listeners++] = pvconn;
			printf("listener: %d\n", fv_ctx->n_listeners);
		} else if( retval == 0) {
			if (fv_ctx->n_switches >= MAX_SWITCHES) {
				ofp_fatal(0, "max %d switch connections", fv_ctx->n_switches);
			}
			new_switch(fv_ctx, vconn, name);
		} else {
			flowvisor_err("%s: connect: %s", name, strerror(retval));
		}
	}
	printf("switches: %d\n", fv_ctx->n_switches);
	if (fv_ctx->n_switches == 0 && fv_ctx->n_listeners == 0) {
		flowvisor_err(0, "no active or passive switch connections");
	}
	daemonize();

	/*main loop
	*/
	while (!newswitch) {
		do_new_switches(fv_ctx);
	}
	flowvisor_log("accept new switch success\n");
	do_new_switches(fv_ctx);
	while (ShouldStop==0){
		//if (round == 2){
		  //     	rc = pthread_create(&handle_switches_thread, NULL, handle_switches, (void *)fv_ctx);
                    //    printf("creating thread for handle_switches, status: %d\n", rc);
		//}
		//if (round == 3) {
		//	rc = pthread_create(&handle_guest_thread, NULL, handle_guest, (void *)fv_ctx);
                //        printf("creating thread for handle_guest, status: %d\n", rc);
		//}
		handle_switches(fv_ctx);
		handle_guest(fv_ctx);
		if(round == 4){
			parm = malloc(sizeof( struct thread_parm_t));
			parm->context = fv_ctx;
			strcpy(parm->interface, "lo");
			rc = pthread_create(&listen_raw_thread, NULL, listen_raw, (void *)parm);
			printf("creating thread for packet capture, status: %d\n", rc);
		}
		wait_on_all(fv_ctx);
		poll_block();
		round ++;
		//if (round > 10) {
		//	sleep(10);
		//}
	}	
	pthread_mutex_destroy(&lock);
	return 0;

}

