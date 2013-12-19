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
#ifndef FLOWVISOR_H
#define FLOWVISOR_H

struct flowvisor_context;
#include "rconn.h"
//#include "statistics.h"
//#include "policy.h"

#define MAX_SWITCHES 		64
#define MAX_LISTENERS 		16
#define MAX_GUESTS 		64		// max number of guest virtual controllers
#define MAX_GUEST_LISTENERS 	16		// max number of sockets to listen for new guests
#define MAX_VCONN_NAME_LEN	128
#define MAX_MSGS_FROM_POLICY	65536		// max number of expansions HACK!
#define BUFLEN 			4096
#define MAX_CONNECT_STR_LEN	128

#define FV_GUEST_MAGIC 0x01234567


#include <openflow/openflow.h>
// FIXME: find a cleaner way to updated this when openflow.h changes

#define STATISTICS_N_COUNTERS (OFPT_STATS_REPLY+1)      // the last enum + 1

typedef struct switch_stats
{
        int ofp_counters[STATISTICS_N_COUNTERS];        // one counter for each type of message
} switch_stats;


struct switch_ {
	struct rconn * rc;      // this connects one switch to a guest with queuing and reliability
	struct switch_stats ss;
	int id;
};

struct guest {
	int magic;		// used to sanity check guest structures to prevent mem corruption
	struct switch_ guest_switches[MAX_SWITCHES];	// one connection per controller
	int n_switches;
	char vconn_name[MAX_VCONN_NAME_LEN];
	int id;
};

typedef struct flowvisor_context {
	struct switch_ switches[MAX_SWITCHES];
	struct guest guests[MAX_GUESTS];
	struct pvconn *listeners[MAX_LISTENERS];
	int n_switches, n_guests, n_listeners;
	int EfficiencyLoops;	
} flowvisor_context;

#define DEFAULT_POLICY POLICY_NAME_PARTITION



#endif
