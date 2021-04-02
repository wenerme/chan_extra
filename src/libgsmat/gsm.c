/*
 * libgsmat: An implementation of OpenVox G400P GSM/CDMA cards
 *
 * Parts taken from libpri
 * Written by mark.liu <mark.liu@openvox.cn>
 *
 * Copyright (C) 2005-2013 OpenVox Communication Co. Ltd,
 * All rights reserved.
 *
 * $Id: gsm.c 356 2011-06-15 02:56:27Z wuyiping $
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2 as published by the
 * Free Software Foundation. See the LICENSE file included with
 * this program for more details.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <stdarg.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>

#include "gsm_timers.h"
#include "libgsmat.h"
#include "gsm_internal.h"
#include "gsm_module.h"
#include "gsm_config.h"

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct msgtype causes[] = {
	{ GSM_CAUSE_UNALLOCATED,				"Unallocated (unassigned) number" },
	{ GSM_CAUSE_NO_ROUTE_TRANSIT_NET,		"No route to specified transmit network" },
	{ GSM_CAUSE_NO_ROUTE_DESTINATION,		"No route to destination" },
	{ GSM_CAUSE_CHANNEL_UNACCEPTABLE,		"Channel unacceptable" },
	{ GSM_CAUSE_CALL_AWARDED_DELIVERED,		"Call awarded and being delivered in an established channel" },
	{ GSM_CAUSE_NORMAL_CLEARING,			"Normal Clearing" },
	{ GSM_CAUSE_USER_BUSY,					"User busy" },
	{ GSM_CAUSE_NO_USER_RESPONSE,			"No user responding" },
	{ GSM_CAUSE_NO_ANSWER,					"User alerting, no answer" },
	{ GSM_CAUSE_CALL_REJECTED,				"Call Rejected" },
	{ GSM_CAUSE_NUMBER_CHANGED,				"Number changed" },
	{ GSM_CAUSE_DESTINATION_OUT_OF_ORDER,	"Destination out of order" },
	{ GSM_CAUSE_INVALID_NUMBER_FORMAT,		"Invalid number format" },
	{ GSM_CAUSE_FACILITY_REJECTED,			"Facility rejected" },
	{ GSM_CAUSE_RESPONSE_TO_STATUS_ENQUIRY,	"Response to STATus ENQuiry" },
	{ GSM_CAUSE_NORMAL_UNSPECIFIED,			"Normal, unspecified" },
	{ GSM_CAUSE_NORMAL_CIRCUIT_CONGESTION,	"Circuit/channel congestion" },
	{ GSM_CAUSE_NETWORK_OUT_OF_ORDER,		"Network out of order" },
	{ GSM_CAUSE_NORMAL_TEMPORARY_FAILURE,	"Temporary failure" },
	{ GSM_CAUSE_SWITCH_CONGESTION,			"Switching equipment congestion" },
	{ GSM_CAUSE_ACCESS_INFO_DISCARDED,		"Access information discarded" },
	{ GSM_CAUSE_REQUESTED_CHAN_UNAVAIL,		"Requested channel not available" },
	{ GSM_CAUSE_PRE_EMPTED,					"Pre-empted" },
	{ GSM_CAUSE_FACILITY_NOT_SUBSCRIBED,	"Facility not subscribed" },
	{ GSM_CAUSE_OUTGOING_CALL_BARRED,		"Outgoing call barred" },
	{ GSM_CAUSE_INCOMING_CALL_BARRED,		"Incoming call barred" },
	{ GSM_CAUSE_BEARERCAPABILITY_NOTAUTH,	"Bearer capability not authorized" },
	{ GSM_CAUSE_BEARERCAPABILITY_NOTAVAIL,	"Bearer capability not available" },
	{ GSM_CAUSE_BEARERCAPABILITY_NOTIMPL,	"Bearer capability not implemented" },
	{ GSM_CAUSE_SERVICEOROPTION_NOTAVAIL,	"Service or option not available, unspecified" },
	{ GSM_CAUSE_CHAN_NOT_IMPLEMENTED,		"Channel not implemented" },
	{ GSM_CAUSE_FACILITY_NOT_IMPLEMENTED,	"Facility not implemented" },
	{ GSM_CAUSE_INVALID_CALL_REFERENCE,		"Invalid call reference value" },
	{ GSM_CAUSE_IDENTIFIED_CHANNEL_NOTEXIST,"Identified channel does not exist" },
	{ GSM_CAUSE_INCOMPATIBLE_DESTINATION,	"Incompatible destination" },
	{ GSM_CAUSE_INVALID_MSG_UNSPECIFIED,	"Invalid message unspecified" },
	{ GSM_CAUSE_MANDATORY_IE_MISSING,		"Mandatory information element is missing" },
	{ GSM_CAUSE_MESSAGE_TYPE_NONEXIST,		"Message type nonexist." },
	{ GSM_CAUSE_WRONG_MESSAGE,				"Wrong message" },
	{ GSM_CAUSE_IE_NONEXIST,				"Info. element nonexist or not implemented" },
	{ GSM_CAUSE_INVALID_IE_CONTENTS,		"Invalid information element contents" },
	{ GSM_CAUSE_WRONG_CALL_STATE,			"Message not compatible with call state" },
	{ GSM_CAUSE_RECOVERY_ON_TIMER_EXPIRE,	"Recover on timer expiry" },
	{ GSM_CAUSE_MANDATORY_IE_LENGTH_ERROR,	"Mandatory IE length error" },
	{ GSM_CAUSE_PROTOCOL_ERROR,				"Protocol error, unspecified" },
	{ GSM_CAUSE_INTERWORKING,				"Interworking, unspecified" },
};

static char *code2str(int code, struct msgtype *codes, int max)
{
	int x;
	
	for (x = 0; x < max; x++) {
		if (codes[x].msgnum == code) {
			return codes[x].name;
		}
	}

	return "Unknown";
}

static char* trim_CRLF( char *String )
{
#define ISCRLF(x) ((x)=='\n'||(x)=='\r'||(x)==' ')

	char *Tail, *Head;
	for ( Tail = String + strlen( String ) - 1; Tail >= String; Tail-- ) {
		if (!ISCRLF( *Tail ))
			break;
	}
	Tail[1] = 0;

	for ( Head = String; Head <= Tail; Head ++ ) {
		if ( !ISCRLF( *Head ) )
			break;
	}

	if ( Head != String )
		memcpy( String, Head, ( Tail - Head + 2 ) * sizeof(char) );

	return String;
}

static char* convert2visible(char* buf)
{
	char* newbuf;
	char* pnewbuf;
	char* p;
	int size;
	int newbuflen;
	newbuflen = strlen(buf)*9;
	newbuf = malloc(newbuflen);
	pnewbuf = newbuf;
	for(p=buf; *p!='\0'; p++) {
		if(((int)*p<=31 || (int)*p>=127) && (*p != 0x0d) && (*p != 0x0a)) {
			size = snprintf(pnewbuf, newbuflen-(pnewbuf-newbuf)," 0x%02X ",*p);
		} else {
			size = snprintf(pnewbuf,newbuflen-(pnewbuf-newbuf),"%c",*p);
		}
		pnewbuf += size;
	}
	*pnewbuf = 0;

	return newbuf;
}


static int convert_str(const char* ori, int orilen, char *buf, int len, int tx)
{
	char tbuf[1024];
	char* newbuf;
	int retlen;

	if(len < sizeof(tbuf)) return 0;
	if(orilen > sizeof(tbuf) || orilen <=0) return 0;

	memcpy(tbuf,ori,orilen);
	tbuf[orilen] = '\0';

	trim_CRLF(tbuf);

	//Freedom Modify 2013-07-10 17:10
	//if(tbuf[0] == 0x1A && tbuf[1] == '\0') {  //Send Message end flag
	//	strcpy(tbuf,"Ctrl+Z");
	//}
	if(tx) {
		int buflen = strlen(tbuf);
		if(buflen > 0) {
			if(tbuf[buflen-1] == 0x1A) {
				tbuf[buflen-1] = '\0';
				strncat(tbuf," Ctrl+Z",sizeof(tbuf)-strlen(tbuf)-1);
			}
		}
	}

	newbuf = convert2visible(tbuf);
	if(tx) {
		retlen = snprintf(buf,len,"TX:[%s]\n",newbuf);
	} else {
		retlen = snprintf(buf,len,"%s\n",newbuf);
	}
	free(newbuf);

	return retlen;
}

/* 
 Initialize setting debug at commands to file /var/log/asterisk/at/span_num 
*/
static int __gsm_init_set_debugat(struct gsm_modul *gsm)
{
	if(gsm->debug_at_fd <= 0)
	{
		char debug_at_file[256];
		char *debug_at_dir = "/var/log/asterisk/at";
		if(access(debug_at_dir, R_OK)) {
			mkdir(debug_at_dir,0774);
		}
		snprintf(debug_at_file,256,"%s/%d",debug_at_dir,gsm->span);
		if(access(debug_at_file, R_OK)) {
			gsm->debug_at_fd = open(debug_at_file,O_WRONLY|O_TRUNC|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
		} else {
			gsm->debug_at_fd = open(debug_at_file,O_WRONLY|O_TRUNC|O_CREAT|O_APPEND);
			if(gsm->debug_at_fd > 0) {
				lseek(gsm->debug_at_fd, 0, SEEK_END);
			}
		}
	}

	return gsm->debug_at_fd > 0 ? 1 : 0;
}

/* 
 Clear setting debug at commands to file
*/
static void __gsm_deinit_set_debugat(struct gsm_modul *gsm)
{
	if(gsm->debug_at_fd > 0) {
		close(gsm->debug_at_fd);
		gsm->debug_at_fd = 0;
	}
}

static void write_time(int fd) 
{ 
   char buf[64]; 
   int size; 
   time_t now; 
   struct tm *timenow; 
   time(&now); 
   timenow = localtime(&now); 
   size = snprintf(buf,sizeof(buf),"%04d-%02d-%02d %02d:%02d:%02d   ",timenow->tm_year+1900,timenow->tm_mon+1,timenow->tm_mday,timenow->tm_hour,timenow->tm_min,timenow->tm_sec); 
   write(fd,buf,size); 
}


/******************************************************************************
 * Read AT Command or AT Command feedback info
 * If buflen is zero, __gsm_read() returns zero and has no other results
 * param:
 *		gsm: struct gsm_modul
 *		buf: save the received info
 *		buflen: receive up to buflen bytes from D-channel
 * return:
 *		The number of bytes read is returned; this may be less than buflen
 *		-1 : error, and errno is set appropriately
 ******************************************************************************/
static int __gsm_read(struct gsm_modul *gsm, void *buf, int buflen)
{
	int res = read(gsm->fd, buf, buflen);
	if (res < 0) {
		if (errno != EAGAIN) {
			gsm_error(gsm, "Read on %d failed: %s\n", gsm->fd, strerror(errno));
		}
		return 0;
	}

	if((gsm->debug_at_fd > 0) && (gsm->debug_at_flag)){

		char wbuf[1024];
		int wlen;
		wlen = convert_str((const char *)buf,res,wbuf,sizeof(wbuf),0);
		if(wlen > 0) {
			write_time(gsm->debug_at_fd);
			write(gsm->debug_at_fd,wbuf,wlen);
		}
		/*write_time(gsm->debug_at_fd);
		write(gsm->debug_at_fd,buf,res);*/
	}
	
	return res;
}


/******************************************************************************
 * Write AT Command
 * param:
 *		gsm: struct gsm_modul
 *		buf: AT Command
 *		buflen: AT Command Length
 * return:
 *		The number of bytes sent; this may be less than buflen
 ******************************************************************************/
static int __gsm_write(struct gsm_modul *gsm, const void *buf, int buflen)
{
	int res = write(gsm->fd, buf, buflen);
	if (res < 0) {
		if (errno != EAGAIN) {
			gsm_error(gsm, "Write to %d failed: %s\n", gsm->fd, strerror(errno));
		}
		return 0;
	}

	if((gsm->debug_at_fd > 0) && (gsm->debug_at_flag)) {
		char wbuf[1024];
		int wlen;
		wlen = convert_str((const char *)buf,res,wbuf,sizeof(wbuf),1);
		if(wlen > 0) {
			write_time(gsm->debug_at_fd);
			write(gsm->debug_at_fd,wbuf,wlen);
		}
	}
	
	return res;
}

static int gsm_call_proceeding(struct gsm_modul *gsm, struct at_call *c, int channel, int info)
{
	if (channel) { 
		channel &= 0xff;
		c->channelno = channel;		
	}

	/* Set channel flag */
	c->chanflags &= ~FLAG_PREFERRED;
	c->chanflags |= FLAG_EXCLUSIVE;

	/* Set our call state */
	UPDATE_OURCALLSTATE(gsm, c, AT_CALL_STATE_INCOMING_CALL_PROCEEDING);

	/* Set peer call state */
	c->peercallstate = AT_CALL_STATE_OUTGOING_CALL_PROCEEDING;
	
	if (info) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;			/* Set Progress location */
		c->progcode = CODE_CCITT;						/* Set Progress coding */
		c->progressmask = GSM_PROG_INBAND_AVAILABLE;	/* Set progress indicator */
	} else {
		c->progressmask = 0; /* Set progress indicator */
	}

	/* We've sent a call proceeding / alerting */
	c->proc = 1;

	/* Call is alive */
	c->alive = 1;
	
	return 0;
}


static int gsm_call_disconnect(struct gsm_modul *gsm, struct at_call *c, int cause)
{
	/* Set our call state */
	UPDATE_OURCALLSTATE(gsm, c, AT_CALL_STATE_DISCONNECT_REQUEST);

	/* Set peer call state */	
	c->peercallstate = AT_CALL_STATE_DISCONNECT_INDICATION;

	/* Set call dead */
	if (c->alive) {
		c->alive			= 0;	/* call is not alive */
		c->cause			= cause;	/* Set event cause */
		c->causecode		= CODE_CCITT;	/* Set cause coding */
		c->causeloc			= LOC_PRIV_NET_LOCAL_USER; /* Set cause progress location */
		c->sendhangupack	= 1; 	/* Sending a hangup ack */
		/* Delete schedule */
		if (gsm->retranstimer) {
			gsm_schedule_del(gsm, gsm->retranstimer);
		}
		//c->retranstimer = gsm_schedule_event(gsm, gsm->timers[GSM_TIMER_T305], gsm_disconnect_timeout, c);
		return 0;
	} else {
		return 0;
	}
}

static void gsm_call_destroy(struct gsm_modul *gsm, int cr, struct at_call *call)
{
	struct at_call *cur, *prev;

	prev = NULL;
	cur = *gsm->callpool;
	while(cur) {
		if ((call && (cur == call)) || (!call && (cur->cr == cr))) {
			if (prev) {
				prev->next = cur->next;
			} else {
				*gsm->callpool = cur->next;
			}

			if (gsm->debug & GSM_DEBUG_AT_STATE) {
				gsm_message(gsm, "NEW_HANGUP DEBUG: Destroying the call, ourstate %s, peerstate %s\n",callstate2str(cur->ourcallstate),callstate2str(cur->peercallstate));
			}

			/* Delete schedule */
			if (gsm->retranstimer) {
				gsm_schedule_del(gsm, gsm->retranstimer);
			}

			/* free at_call */
			free(cur);
			
			return;
		}
		prev = cur;
		cur = cur->next;
	}

	//Freedom Modify 2011-12-07 18:03
	if( NULL != call && 0 == cr ) {
		gsm_message(gsm, "Can't destroy call %d!\n", cr);
	}
	//gsm_message(gsm, "Can't destroy call %d!\n", cr);
}


static void gsm_default_timers(struct gsm_modul *gsm)
{
	static const int defaulttimers[GSM_MAX_TIMERS] = GSM_TIMERS_DEFAULT;
	int x;

	if (!gsm) {
		return;
	}

	for (x = 0; x < GSM_MAX_TIMERS; x++) {
		gsm->timers[x] = defaulttimers[x];
	}
}


static void gsm_reset_timeout(void *data)
{
	struct at_call *c = data;
	struct gsm_modul *gsm = c->gsm;
	
	if (gsm->debug & GSM_DEBUG_AT_STATE) {
		gsm_message(gsm, "Timed out resetting span. Starting Reset again\n");
	}
	
	gsm->retranstimer = gsm_schedule_event(gsm, gsm->timers[GSM_TIMER_T316], gsm_reset_timeout, c);
	module_restart(gsm);
}


/******************************************************************************
 * Initialize gsm_sr
 * param:
 *		req: struct gsm_sr
 * return:
 *		void
 ******************************************************************************/
static void gsm_sr_init(struct gsm_sr *req)
{
	memset(req, 0, sizeof(struct gsm_sr));
}


/******************************************************************************
 * Get Network status info
 * param:
 *		id: gsm->network
 *			GSM_NET_UNREGISTERED 	Unregistered
 *			GSM_NET_HOME 			home Registered
 *			GSM_NET_ROAMING 		roaming
 *			other					Unknown Network Status
 * return:
 *		network status string info
 ******************************************************************************/
static char *gsm_network2str(int id)
{
	switch(id) {
		case GSM_NET_UNREGISTERED:
			return "Not registered";
		case GSM_NET_HOME:
			return "Registered (Home network)";
		case GSM_NET_SEARCHING:
			return "Searching";
		case GSM_NET_DENIED:
			return "Registration denied";
		case GSM_NET_UNKNOWN:
			return "Unknown";
		case GSM_NET_ROAMING:
			return "Registered (Roaming)";
		case GSM_NET_REGISTERED:
			return "Registered";
		default:
			return "Unknown Network Status";
	}
}


/******************************************************************************
 * Get call state message
 * param:
 *		call state id
 * return:
 *		call state message
 ******************************************************************************/
char *callstate2str(int callstate)
{
	static struct msgtype callstates[] = {
		{  0, "Null" },
		{  1, "Call Initiated" },
		{  2, "Overlap sending" },
		{  3, "Outgoing call  Proceeding" },
		{  4, "Call Delivered" },
		{  6, "Call Present" },
		{  7, "Call Received" },
		{  8, "Connect Request" },
		{  9, "Incoming Call Proceeding" },
		{ 10, "Active" },
		{ 11, "Disconnect Request" },
		{ 12, "Disconnect Indication" },
		{ 15, "Suspend Request" },
		{ 17, "Resume Request" },
		{ 19, "Release Request" },
		{ 22, "Call Abort" },
		{ 25, "Overlap Receiving" },
		{ 61, "Restart Request" },
		{ 62, "Restart" },
	};
	return code2str(callstate, callstates, sizeof(callstates) / sizeof(callstates[0]));
}


/******************************************************************************
 * Create a new gsm_modul
 * param:
 *		fd: FD's for D-channel
 *		nodetype:
 *		switchtype:
 * return:
 *		A new gsm_modul structure
 * e.g.
 *		__gsm_new_tei(fd, nodetype, switchtype, __gsm_read, __gsm_write, NULL);
 ******************************************************************************/
/*Freedom Modify 2011-10-10 10:11*/
//struct gsm_modul *__gsm_new_tei(int fd, int nodetype, int switchtype, int span, gsm_rio_cb rd, gsm_wio_cb wr, void *userdata)
struct gsm_modul *__gsm_new_tei(int fd, int nodetype, int switchtype, int span, gsm_rio_cb rd, gsm_wio_cb wr, void *userdata,int at_debug)
{
	struct gsm_modul *gsm;
	/* malloc gsm_modul */
	if (!(gsm = calloc(1, sizeof(*gsm)))) {
		return NULL;
	}

	gsm->fd			= fd;
	gsm->read_func	= rd;
	gsm->write_func	= wr;
	gsm->userdata	= userdata;
	gsm->localtype	= nodetype;
	gsm->switchtype	= switchtype;
	gsm->cref		= 1; /* Next call reference value */
	gsm->callpool	= &gsm->localpool;
	gsm->span		= span;
	gsm->sms_mod_flag = SMS_UNKNOWN;
	gsm->debug_at_fd = 0;
	gsm->debug_at_flag = at_debug;

	memset(gsm->rec_at, 0, sizeof(gsm->rec_at));
	gsm->syncat_stat = 0;

	//Freedom Add for if GSM module can't timely start. power restart modules. 2013-05-14 09:08
	gsm->start_time = sys_uptime();
	
	/*Freedom Modify 2011-10-10 10:11*/
	/* Set default timer by switchtype */
//	gsm_default_timers(gsm, switchtype);
	gsm_default_timers(gsm);
		
	/* set network status */
	gsm->network = GSM_NET_UNREGISTERED;

	/* Set network coverage */
	gsm->coverage = -1;

	/*Set default ber*/
	gsm->ber = -1;
	
	gsm->send_at = 0;

#ifdef CONFIG_CHECK_PHONE
	/*Makes modify 2012-04-10 17:03*/
	gsm->check_mode = 0;
	gsm->phone_stat = -1;
	gsm->auto_hangup_flag = 0;
#endif

#ifdef GSM0710_MODE
	gsm->already_set_mux_mode = 0;
#endif //GSM0710_MODE

#ifdef TX_QUEUE
	init_tx_queue(gsm);
#endif //TX_QUEUE

	if(gsm->debug_at_flag) {
		__gsm_init_set_debugat(gsm);
	} else {
		gsm->debug_at_fd = -1;
	}

	/* set timer by switchtype and start gsm module */
	if (gsm) {
		gsm_set_timer(gsm, GSM_TIMER_T316, 5000);
		module_start(gsm);
	}

	return gsm;
}


/******************************************************************************
 * Free gsm_modul
 * param:
 *		gsm: gsm_modul
 * return:
 *		void
 ******************************************************************************/
void __gsm_free_tei(struct gsm_modul *gsm)
{
	if (gsm) {
		__gsm_deinit_set_debugat(gsm);
		gsm->debug_at_flag = 0;
		free (gsm);
	}
}

void gsm_set_debugat(struct gsm_modul *gsm,int mode)
{
	if(mode > 0) {
		gsm->debug_at_flag = 1;
		__gsm_init_set_debugat(gsm);
	} else {
		gsm->debug_at_flag = 0;
		__gsm_deinit_set_debugat(gsm);
	}
}



/******************************************************************************
 * Make a config error event
 * param:
 *		gsm: gsm_modul
 *		errstr: config error message
 * return:
 *		gsm_event
 ******************************************************************************/
gsm_event *gsm_mkerror(struct gsm_modul *gsm, char *errstr)
{
	/* Return a configuration error */
	gsm->ev.err.e = GSM_EVENT_CONFIG_ERR;
	strncpy(gsm->ev.err.err, errstr, sizeof(gsm->ev.err.err));
	return &gsm->ev;
}


/******************************************************************************
 * Dump AT Command Message
 * param:
 *		gsm: gsm module
 *		h  : AT Command
 *		len: AT Command Length
 *      txrx:
 *			1: Show sended message
 *			0: Show received message
 * return:
 * 			void
 * e.g.
 *		gsm_dump(gsm, "AT+CREG?\r\n", 10, 1);
 ******************************************************************************/
void gsm_dump(struct gsm_modul *gsm, const char *at, int len, int txrx)
{
	if ( NULL == gsm || NULL == at || len <= 0 ) {
		return;
	}
	
    int i=0;
    int j=0;
	char *dbuf;
	
	dbuf = (char*)malloc(len*sizeof(char)*2);
	
    for (i = 0; i < len; i++) {
        if (at[i] == '\r') {
            dbuf[j++] = '\\';
			dbuf[j++] = 'r';
        } else if (at[i] == '\n') {
        	dbuf[j++] = '\\';
			dbuf[j++] = 'n';
        } else {
        	dbuf[j++] = at[i];
        }
    }
    dbuf[j] = '\0';

	gsm_message(gsm, "%d:%s %s\n", gsm->span,(txrx) ? ">>" : "<<", dbuf);
	
	free(dbuf);
}


/******************************************************************************
 * Transmit AT Command
 * param:
 *		gsm: gsm module
 *		at  : AT Command
 * return:
 *	   	0: trasmit ok
 *		-1: error
 * e.g.
 *		gsm_transmit(gsm, "AT+CREG?\r\n");
 ******************************************************************************/
int gsm_send_at(struct gsm_modul *gsm, const char *at) 
{
	if ( NULL == gsm || NULL == at ) {
		return -1;
	}
	
	int res, len;
	char *dbuf;

	/* get AT Command length */
	len = strlen(at);
	
	dbuf = (char*)malloc(len*sizeof(char)+2+1);

	/* Just send it raw */
	/* Dump AT Message*/
	if (gsm->debug & (GSM_DEBUG_AT_DUMP)) {
		gsm_dump(gsm, at, len, 1);
	}
	
	strcpy(dbuf, at);

	dbuf[len++]	= '\r';
	dbuf[len++]	= '\n';
	dbuf[len] = '\0';
	

	//Freedom Add for send AT commmands according to simple queue. 2013-07-09 14:13
#ifdef TX_QUEUE
	res = add_tx_queue(gsm, (char*)dbuf, len);
#else
	/* Write an extra two bytes for the FCS */
	res = gsm->write_func ? gsm->write_func(gsm, dbuf, len + 2) : 0;
	if (res != (len + 2)) {
		gsm_error(gsm, "Short write: %d/%d (%s)\n", res, len + 2, strerror(errno));
		
		free(dbuf);
		return -1;
	}
	/* Last sent command to dchan */
	strncpy(gsm->at_last_sent, dbuf, sizeof(gsm->at_last_sent));

	/* at_lastsent length */
	gsm->at_last_sent_idx = len;
#endif
	
	free(dbuf);
	return 0;
}

/******************************************************************************
 * Transmit AT Command
 * param:
 *		gsm: gsm module
 *		at  : AT Command
 * return:
 *	   	0: trasmit ok
 *		-1: error
 * e.g.
 *		gsm_transmit(gsm, "AT+CREG?\r\n");
 ******************************************************************************/
int gsm_transmit(struct gsm_modul *gsm, const char *at) 
{
	if ( NULL == gsm || NULL == at ) {
		return -1;
	}
	
	int res, len;

	/* get AT Command length */
	len = strlen(at);

	/* Just send it raw */
	/* Dump AT Message*/
	if (gsm->debug & (GSM_DEBUG_AT_DUMP)) {
		gsm_dump(gsm, at, len, 1);
	}
	
	//Freedom Add for send AT commmands according to simple queue. 2013-07-09 14:13
#ifdef TX_QUEUE
	res = add_tx_queue(gsm, (char*)at, len);
#else
	/* Write an extra two bytes for the FCS */
	res = gsm->write_func ? gsm->write_func(gsm, at, len + 2) : 0;
	if (res != (len + 2)) {
		gsm_error(gsm, "Short write: %d/%d (%s)\n", res, len + 2, strerror(errno));
		return -1;
	}

	/* Last sent command to dchan */
	strncpy(gsm->at_last_sent, at, sizeof(gsm->at_last_sent));

	/* at_lastsent length */
	gsm->at_last_sent_idx = len;
#endif
		
	return 0;
}

int gsm_test_atcommand(struct gsm_modul *gsm, char *at) 
{
	if ( NULL == gsm || NULL == at /*|| GSM_STATE_READY != gsm->state*/ ) {
		return -1;
	}
	
	int res, len;
	int i;
	char *dbuf;

	/* get AT Command length */
	len = strlen(at);
	
	dbuf = (char*)malloc(len*sizeof(char)+2+1);
	
	/* Just send it raw */
	/* Dump AT Message*/
	if (gsm->debug & (GSM_DEBUG_AT_DUMP)) {
		gsm_dump(gsm, at, len, 1);
	}

	strcpy(dbuf, at);
	
	for(i=0; i<len; i++) {
		if( '@' == dbuf[i] ) {
			dbuf[i] = '?';
		}
	}

	dbuf[len++]	= '\r';
	dbuf[len++]	= '\n';		
	dbuf[len] = '\0';
						
//Freedom Add for send AT commmands according to simple queue. 2013-07-09 14:13
#ifdef TX_QUEUE
	res = add_tx_queue(gsm, (char*)dbuf, len);
#else
	/* Write an extra two bytes for the FCS */
	res = gsm->write_func ? gsm->write_func(gsm, dbuf, len + 2) : 0;
	if (res != (len + 2)) {
		gsm_error(gsm, "Short write: %d/%d (%s)\n", res, len + 2, strerror(errno));
		free(dbuf);
		return -2;
	}

	/* Last sent command to dchan */
	strncpy(gsm->at_last_sent, dbuf, sizeof(gsm->at_last_sent));

	/* at_lastsent length */
	gsm->at_last_sent_idx = len;
#endif
		
	gsm->send_at = 1;
	
	free(dbuf);
	
	return 0;
}


/******************************************************************************
 * Get a call
 * param:
 *		gsm: struct gsm_modul
 *		cr: Call Reference in at_call
 *		outboundnew: not used
 * return:
 *	   	at_call
 ******************************************************************************/
struct at_call *gsm_getcall(struct gsm_modul *gsm, int cr, int outboundnew)
{
	struct at_call *cur, *prev;
	struct gsm_modul *master;

	master = gsm;

	/* Get at_call */
	cur = *master->callpool;
	prev = NULL;
	while(cur) {
		if (cur->cr == cr) {
			return cur;
		}
		prev = cur;
		cur = cur->next;
	}
	
	/* No call exists, make a new one */
	if (gsm->debug & GSM_DEBUG_AT_STATE) {
		gsm_message(gsm, "-- Making new call for cr %d\n", cr);
	}

	/* calloc a new call */
	if (!(cur = calloc(1, sizeof(*cur)))) {
		return NULL;
	}

	/* Initialize the new call */
	cur->cr = cr;		/* Set Call reference */
	cur->gsm = gsm;
	cur->channelno		= -1;
	cur->newcall		= 1;
	cur->ourcallstate	= AT_CALL_STATE_NULL;
	cur->peercallstate	= AT_CALL_STATE_NULL;
	cur->next 			= NULL;

	/* Append to end of list */
	if (prev) {
		prev->next = cur;
	} else {
		*master->callpool = cur;
	}

	/* return the new call f*/
	return cur;
}


/******************************************************************************
 * String Comparation
 * param:
 *		str_at: source string
 *		str_cmp: destination string
 * return:
 *		1: equal
 *		0: not equal
 * e.g.
 *		gsm_compare("abc", "abc")			=> 1
 *		gsm_compare("ab", "abcd")			=> 0 
 *		gsm_compare("abcd", "ab")			=> 1 
 *		gsm_compare("ab\r\ncd", "ab")		=> 1 
 *		gsm_compare("ab\r\ncd", "abcd")		=> 0
 *		gsm_compare("\r\nab\r\ncd", "ab")	=> 1
 ******************************************************************************/
int gsm_compare(const char *str_at, const char *str_cmp) 
{
#if 0
	int res;
	int i;
	int j =0;
	char buf[1024];
	int k = strlen(str_at);

	if ((NULL == str_at) || (NULL == str_cmp)) {
		return 0;
	}
	
	res = strncmp(str_at, str_cmp, strlen(str_cmp));
	if (!res) {
		return 1;
	}

	for (i=0; i < k ;i++) {
		/* skip \r or \n */
		if ((str_at[i] != '\r') && (str_at[i] != '\n') ) {
			buf[j++] = str_at[i];
		}
		/*  */
		if (('\n' == str_at[i])) {
			buf[j] = '\0';
			if (j > 0) {
				res = strncmp(buf, str_cmp, strlen(str_cmp));
				if (!res) {
					return 1;
				}
			}
			j=0;
		}
	}

	res = strncmp(buf, str_cmp, strlen(str_cmp));
	if (!res) {
		return 1;
	}

	return 0;
#else
	return NULL == strstr(str_at,str_cmp) ? 0 : 1;
#endif
}


/******************************************************************************
 * Strip \r\n
 * param:
 *		in: source string
 *		out: destination string
 * return:
 *		string without \r\n
 * e.g.
 *		gsm_trim() 				=>
 *		gsm_trim("abc") 		=>
 *		gsm_trim("abc") 		=> abc
 *		gsm_trim("\r\nabc") 	=> abc
 *		gsm_trim("abc\r\n") 	=> abc
 *		gsm_trim("\r\nabc\r\n") => abc
 ******************************************************************************/
int gsm_trim(const char *in, int in_len, char *out, int out_len) 
{
    int i=0;
    int j=0;

    for (i = 0; i < in_len && j < (out_len-1); i++) {
        if ((in[i] != '\r') && (in[i] != '\n') ) {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
	
    return j;
}

void gsm_get_manufacturer(struct gsm_modul *gsm, char *h) 
{
	char buf[sizeof(gsm->manufacturer)];
	gsm_trim(h, strlen(h), buf, sizeof(buf));
	strncpy(gsm->manufacturer, buf, sizeof(gsm->manufacturer));
	
	return;
}

void gsm_get_smsc(struct gsm_modul *gsm, char *h) 
{
	char buf[sizeof(gsm->sim_smsc)];

	gsm_trim(h, strlen(h), buf, sizeof(buf));

	char *ps, *pe;
	ps = strchr(buf,'"');
	pe = strrchr(buf,'"');

	if(pe == 0 || ps == 0) {
		gsm->sim_smsc[0]='\0';
		return;
	}
	
	if( (pe-ps) < sizeof(gsm->sim_smsc) && (pe-ps) > 0) {
		if((pe-ps-1)>=sizeof(gsm->sim_smsc))
			gsm->sim_smsc[0]='\0';
		else
			strncpy(gsm->sim_smsc, ps+1, pe-ps-1);
	} else {
		gsm->sim_smsc[0]='\0';
	}
	
	return;
}

void gsm_get_model_name(struct gsm_modul *gsm, char *h) 
{
	char buf[sizeof(gsm->model_name)];
	gsm_trim(h, strlen(h), buf, sizeof(buf));
	strncpy(gsm->model_name, buf, sizeof(gsm->model_name));
	
	return;
}

void gsm_get_model_version(struct gsm_modul *gsm, char *h) 
{
	char buf[sizeof(gsm->revision)];
	gsm_trim(h, strlen(h), buf, sizeof(buf));
	strncpy(gsm->revision, buf, sizeof(gsm->revision));
	return;
}

void gsm_get_imsi(struct gsm_modul *gsm, char *h) 
{
	char buf[sizeof(gsm->imsi)];
	gsm_trim(h, strlen(h), buf, sizeof(buf));
	strncpy(gsm->imsi, buf, sizeof(gsm->imsi));
	return;
}

void gsm_get_imei(struct gsm_modul *gsm,char *h) 
{
	char buf[sizeof(gsm->imei)];
	gsm_trim(h, strlen(h), buf, sizeof(buf));
	strncpy(gsm->imei, buf, sizeof(gsm->imei));
}

void gsm_get_operator(struct gsm_modul *gsm, char *buf) 
{
	char* key ="\"";
	char* start;
	char* end;

	if (!gsm) {
		return;
	}

	gsm->net_name[0] = '\0';

	start = strstr(buf, key);
	if (0 == start) {
		return;
	}
	start += strlen(key);
	end = strstr(start, key);

	if((end-start) < sizeof(gsm->net_name)) {
		strncpy(gsm->net_name, start, (end - start));
	}
}

int gsm_switch_state(struct gsm_modul *gsm, int state, const char *next_command)
{
	gsm->oldstate = gsm->state;
    gsm->state = state;
    if (next_command) {
		//Freedom Modify 2011-10-10 15:58
		//gsm_transmit(gsm, next_command);
		fsync(gsm->fd);
		gsm_send_at(gsm,next_command);
    }
    return 0;
}

int gsm_switch_sim_state(struct gsm_modul *gsm, int state, char *next_command)
{
    gsm->sim_state = state;
    if (next_command) {
        //Freedom Modify 2011-10-10 15:58
		//gsm_transmit(gsm, next_command);
		gsm_send_at(gsm,next_command);
    }

    return 0;
}

static void (*__gsm_error)(struct gsm_modul *gsm, char *stuff);
static void (*__gsm_message)(struct gsm_modul *gsm, char *stuff);

/******************************************************************************
 * General message reporting function
 * param:
 *		gsm: gsm module
 *		fmt: format string
 * return:
 *		void
 * e.g.
 *		gsm_message(gsm, "Timed out resetting span. Starting Reset again\n");
 ******************************************************************************/
void gsm_message(struct gsm_modul *gsm, char *fmt, ...)
{
	char tmp[1024];

	if (!gsm) {
		return;
	}

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	
	if (__gsm_message) {
		__gsm_message(gsm, tmp);
	} else {
		fputs(tmp, stdout);
	}
}


/******************************************************************************
 * General error reporting function
 * param:
 *		gsm: gsm module
 *		fmt: format string
 * return:
 *		void
 * e.g.
 *		gsm_error(gsm, "Short write: %d/%d (%s)\n", res, len + 2, strerror(errno));
 ******************************************************************************/
void gsm_error(struct gsm_modul *gsm, char *fmt, ...)
{
	char tmp[1024];

	if (!gsm) {
		return;
	}

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (__gsm_error) {
		__gsm_error(gsm, tmp);
	} else {
		fputs(tmp, stderr);
	}
}

/*============================================================================
 *
 * Called by chan_extra.so
 *
 * ===========================================================================*/

/******************************************************************************
 * Set message reporting function
 * param:
 *		a function pointer
 * return:
 *		void
 * e.g.
 *		used in chan_extra.so
 *		gsm_set_message(extra_extend_message);
 ******************************************************************************/
void gsm_set_message(void (*func)(struct gsm_modul *gsm, char *stuff))
{
	__gsm_message = func;
}


/******************************************************************************
 * Set error reporting function
 * param:
 *		a function pointer
 * return:
 *		void
 * e.g.
 *		used in chan_extra.so
 *		gsm_set_error(extra_extend_error);
 ******************************************************************************/
void gsm_set_error(void (*func)(struct gsm_modul *gsm, char *stuff))
{
	__gsm_error = func;
}

/******************************************************************************
 * Set debug level
 * param:
 *		gsm: struct gsm_modul
 *		debug: debug level
 * return:
 *		void
 * e.g.
 *		used in chan_extra.so
 ******************************************************************************/
void gsm_set_debug(struct gsm_modul *gsm, int debug)
{
	if (!gsm) {
		return;
	}
	
	gsm->debug = debug;
}


/******************************************************************************
 * Get debug level
 * param:
 *		gsm: struct gsm_modul
 * return:
 *		void
 * e.g.
 *		used in chan_extra.so
 ******************************************************************************/
int gsm_get_debug(struct gsm_modul *gsm)
{
	if (!gsm) {
		return -1;
	}
	return gsm->debug;
}

char *gsm_cause2str(int cause)
{
	return code2str(cause, causes, sizeof(causes) / sizeof(causes[0]));
}

char *gsm_event2str(int id)
{
	switch(id) {
		case GSM_EVENT_DCHAN_UP:
			return "D-Channel Up";
		case GSM_EVENT_DETECT_MODULE_OK:
			return "Detect module OK";
		case GSM_EVENT_DCHAN_DOWN:
			return "D-channel Down";
		case GSM_EVENT_RESTART:
			return "Restart channel";

		case GSM_EVENT_RING:
			return "Ring";
		case GSM_EVENT_HANGUP:
			return "Hangup";
		case GSM_EVENT_RINGING:
			return "Ringing";
		case GSM_EVENT_ANSWER:
			return "Answer";
		case GSM_EVENT_HANGUP_ACK:
			return "Hangup ACK";
		case GSM_EVENT_RESTART_ACK:
			return "Restart ACK";
		case GSM_EVENT_FACNAME:
			return "FacName";
		case GSM_EVENT_INFO_RECEIVED:
			return "Info Received";
		case GSM_EVENT_PROCEEDING:
			return "Proceeding";
		case GSM_EVENT_SETUP_ACK:
			return "Setup ACK";
		case GSM_EVENT_HANGUP_REQ:
			return "Hangup request";
		case GSM_EVENT_NOTIFY:
			return "Notify";
		case GSM_EVENT_PROGRESS:
			return "Progress";
		case GSM_EVENT_KEYPAD_DIGIT:
			return "Keypad digit";
		case GSM_EVENT_SMS_RECEIVED:
			return "SMS received";
		case GSM_EVENT_SIM_FAILED:
			return "SIM failed";
		case GSM_EVENT_PIN_REQUIRED:
			return "PIN required";
		case GSM_EVENT_PIN_ERROR:
			return "PIN error";
#ifdef AUTO_SIM_CHECK
		case GSM_EVENT_SIM_NOT_INSERTED:
			return "SIM not insert";
		case GSM_EVENT_SIM_INSERTED:
			return "SIM insert";
#endif //AUTO_SIM_CHECK
		case GSM_EVENT_SMS_SEND_OK:
			return "SMS send OK";	
		case GSM_EVENT_SMS_SEND_FAILED:	
			return "SMS send failed";
		case GSM_EVENT_USSD_RECEIVED:
			return "USSD received";
		case GSM_EVENT_USSD_SEND_FAILED:
			return "USSD send failed";
		case GSM_EVENT_NO_SIGNAL:
			return "No signal";

#ifdef CONFIG_CHECK_PHONE
		case GSM_EVENT_CHECK_PHONE:
			return "Check phone";
#endif //CONFIG_CHECK_PHONE

#ifdef GSM0710_MODE
		case GSM_EVENT_INIT_MUX:
			return "Init Multiplexer";
#endif //GSM0710_MODE

		//Freedom Add for if GSM module can't timely start. power restart modules. 2013-05-14 09:08
		case GSM_EVENT_POWER_RESTART:
			return "Power restart";

		default:
			return "Unknown Event";
	}
}

int gsm_keypad_facility(struct gsm_modul *gsm, struct at_call *call, char *digits)
{
	if (!gsm || !call || !digits || !digits[0]) {
		return -1;
	}

	strncpy(call->keypad_digits, digits, sizeof(call->keypad_digits));
	return 0;
}


/******************************************************************************
 * Get D-Channel Fileno
 * param:
 *		gsm: gsm module
 * return:
 *		-1: error
 *      other: gsm->fd
 ******************************************************************************/
int gsm_fd(struct gsm_modul *gsm)
{
	if (!gsm) {
		return -1;
	}

	return gsm->fd;
}

int gsm_call(struct gsm_modul *gsm, struct at_call *c, int transmode, int channel, int exclusive, 
					int nonisdn, char *caller, int callerplan, char *callername, int callerpres, char *called,
					int calledplan,int ulayer1)
{
	struct gsm_sr req;

	if (!gsm || !c) {
		return -1;
	}

	gsm_sr_init(&req);
	req.transmode = transmode;
	req.channel = channel;
	req.exclusive = exclusive;
	req.nonisdn =  nonisdn;
	req.caller = caller;
	req.callername = callername;
	req.called = called;
	req.userl1 = ulayer1;
	return gsm_setup(gsm, c, &req);
}	

char *gsm_node2str(int node)
{
	switch(node) {
	case GSM_NETWORK:
		return "Network";
	case GSM_CPE:
		return "CPE";
	default:
		return "Invalid value";
	}
}

//Freedom del 2012-09-13
#if 0
char *gsm_switch2str(int sw)
{
	switch(sw) {
	case GSM_SWITCH_E169:
		return "Huawei E169/K3520";
	case GSM_SWITCH_SIMCOM:
		return "SimCom 100/300";
	case GSM_SWITCH_SIM900:
		return "SimCom 900";
	case GSM_SWITCH_M20:
		return "Quectel M20";
	case GSM_SWITCH_EM200:
		return "Huawei EM200 CDMA 1X 800M";
	default:
		return "Unknown switchtype";
	}
}
#endif


/******************************************************************************
 * Set timer
 * param:
 *		gsm: struct gsm_modul
 *		timer: timer type
 *		value: ms
 * return:
 *		-1: error
 *		 0: ok
 ******************************************************************************/
int gsm_set_timer(struct gsm_modul *gsm, int timer, int value)
{
	if (timer < 0 || timer > GSM_MAX_TIMERS || value < 0) {
		return -1;
	}
	
	gsm->timers[timer] = value;
	return 0;
}


/******************************************************************************
 * Get timer
 * param:
 *		gsm: struct gsm_modul
 *		timer: timer type
 * return:
 *		 -1: error
 *		> 0: timer value
 ******************************************************************************/
int gsm_get_timer(struct gsm_modul *gsm, int timer)
{
	if (timer < 0 || timer > GSM_MAX_TIMERS) {
		return -1;
	}
	return gsm->timers[timer];
}


/******************************************************************************
 * Create a new gsm_modul
 * param:
 *		fd: FD's for D-channel
 *		nodetype:
 *		switchtype:
 * return:
 *		A new gsm_modul structure
 * e.g.
 *		used in chan_extra.so
 *		extend->dchan = gsm_new(extend->fd, extend->nodetype, extend->switchtype);
 ******************************************************************************/

struct gsm_modul *gsm_new(int fd, int nodetype, int switchtype, int span, int at_debug)
{
	return __gsm_new_tei(fd, nodetype, switchtype, span, __gsm_read, __gsm_write, NULL, at_debug);
}

int gsm_restart(struct gsm_modul *gsm)
{	
	if (gsm) {
		gsm->network = GSM_NET_UNREGISTERED;
		gsm->imei[0] = 0x0;
		gsm->imsi[0] = 0x0;
		gsm->net_name[0] = 0x0;
		gsm->coverage = -1;
		gsm->ber = -1;


		
		module_start(gsm);

		return 0;
	}
	
	return -1;
}

int gsm_reset(struct gsm_modul *gsm, int channel)
{
	struct at_call *c;

	if (!gsm) {
		return -1;
	}

	/* Get at_call */
	c = gsm_getcall(gsm, 0, 1);
	if (!c) {
		return -1;
	}

	/* check channel */
	if (!channel) {
		return -1;
	}
	channel &= 0xff;
	
	c->channelno = channel;		
	c->chanflags &= ~FLAG_PREFERRED;
	c->chanflags |= FLAG_EXCLUSIVE;

	/* Set our call state */
	UPDATE_OURCALLSTATE(gsm, c, AT_CALL_STATE_RESTART);
	
	/* Set peer call state */	
	c->peercallstate = AT_CALL_STATE_RESTART_REQUEST;

	/* restart gsm module */
	gsm->retranstimer = gsm_schedule_event(gsm, gsm->timers[GSM_TIMER_T316], gsm_reset_timeout, c);
	module_restart(gsm);

	return 0;
}

void gsm_module_start(struct gsm_modul *gsm)
{
	//Freedom Add for if GSM module can't timely start. power restart modules. 2013-05-14 09:08
	gsm->start_time = sys_uptime();

	gsm_switch_state(gsm, GSM_STATE_INIT, AT(AT_CHECK));
}


/******************************************************************************
 * Handle received AT feedback from GSM D-channel
 * param:
 *		gsm: struct gsm_modul
 * return:
 *		gsm_event
 ******************************************************************************/
gsm_event *gsm_check_event(struct gsm_modul *gsm)
{
	char buf[1024];
	int res = 0;
	int i = 0;
	gsm_event *e = NULL;

	// Read from GSM D-channel
	res = gsm->read_func ? gsm->read_func(gsm, buf, sizeof(buf)) : 0;
	if (!res) {
		return NULL;
	}
	
	//Freedom Modify fix up data overflow 2013-07-03 22:51
#if 0
	//Save Receive AT Commands
	for (i = 0; i < res && gsm->at_last_recv_idx < sizeof(gsm->at_last_recv); i++) {
		gsm->at_last_recv[gsm->at_last_recv_idx] = buf[i];
		gsm->at_last_recv_idx++;
	}
#endif
		
	//Save Receive AT Commands
	for (i = 0; i < res && gsm->at_last_recv_idx < sizeof(gsm->at_last_recv) - 1; i++) {
		gsm->at_last_recv[gsm->at_last_recv_idx] = buf[i];
		gsm->at_last_recv_idx++;
	}

	gsm->at_last_recv[gsm->at_last_recv_idx] = '\0';

	memset(gsm->at_pre_recv,0,sizeof(gsm->at_pre_recv));
	strncpy(gsm->at_pre_recv, gsm->at_last_recv, sizeof(gsm->at_pre_recv));

	//Use '\r' or '\n' split AT Commands.
	if (((gsm->at_last_recv[gsm->at_last_recv_idx-1]=='\r')||(gsm->at_last_recv[gsm->at_last_recv_idx-1]=='\n'))||
			((gsm->state==GSM_STATE_SMS_SENDING)&&(gsm->at_last_recv[gsm->at_last_recv_idx-2]=='>'))) {

		if (gsm->debug & GSM_DEBUG_AT_DUMP) {
			gsm_dump(gsm, gsm->at_last_recv, gsm->at_last_recv_idx, 0);
		}

		//Freedom del 2013-07-12 11:57
		/*
		if(strcmp(gsm->at_last_recv,"\r\nSM BL Ready\r\n")==0){
			strcpy(gsm->at_last_recv,"OK\r\n");
			gsm->at_last_recv_idx=4;
		}*/

		//For "gsm send syncat"
		//if(gsm->syncat_stat) {
		//	strncat(gsm->rec_at,gsm->at_last_recv,sizeof(gsm->rec_at)-strlen(gsm->rec_at)-1);
		//}

		gsm->at_leak[0] = '\0';

		e = module_receive(gsm, gsm->at_last_recv, gsm->at_last_recv_idx);

		//Reset receive AT commands container.
		gsm->at_last_recv_idx	= 0;
		memset(gsm->at_last_recv,0,sizeof(gsm->at_last_recv));

		//Pick up no process AT commands.
		if( strlen(gsm->at_leak) > 0 ) {
			strncpy(gsm->at_last_recv, gsm->at_leak, sizeof(gsm->at_last_recv));
		}
		gsm->at_leak[0] = '\0';
	}
	
	return e;
}


int gsm_acknowledge(struct gsm_modul *gsm, struct at_call *c, int channel, int info)
{
	if (!gsm || !c) {
		return -1;
	}
	
	if (!c->proc) {
		gsm_call_proceeding(gsm, c, channel, 0);
	}
	if (info) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask = GSM_PROG_INBAND_AVAILABLE;
	} else {
		c->progressmask = 0;
	}
	UPDATE_OURCALLSTATE(gsm, c, AT_CALL_STATE_CALL_RECEIVED);
	c->peercallstate = AT_CALL_STATE_CALL_DELIVERED;
	c->alive = 1;
	
	return 0;
}

int gsm_proceeding(struct gsm_modul *gsm, struct at_call *call, int channel, int info)
{
	if (!gsm || !call) {
		return -1;
	}
	
	return gsm_call_proceeding(gsm, call, channel, info);
}

int gsm_progress(struct gsm_modul *gsm, struct at_call *c, int channel, int info)
{
	if (!gsm || !c) {
		return -1;
	}

	if (channel) { 
		channel &= 0xff;
		c->channelno = channel;		
	}

	if (info) {
		c->progloc = LOC_PRIV_NET_LOCAL_USER;
		c->progcode = CODE_CCITT;
		c->progressmask = GSM_PROG_INBAND_AVAILABLE;
	} else {
		/* PI is mandatory IE for PROGRESS message - Q.931 3.1.8 */
		gsm_error(gsm, "XXX Progress message requested but no information is provided\n");
		c->progressmask = 0;
	}

	c->alive = 1;
	return 0;
}


int gsm_information(struct gsm_modul *gsm, struct at_call *call, char digit)
{
	if (!gsm || !call) {
		return -1;
	}
	call->callednum[0] = digit;
	call->callednum[1] = '\0';
	return 0;
}


int gsm_need_more_info(struct gsm_modul *gsm, struct at_call *c, int channel)
{
	if (!gsm || !c) {
		return -1;
	}
	if (channel) { 
		channel &= 0xff;
		c->channelno = channel;		
	}
	c->chanflags &= ~FLAG_PREFERRED;
	c->chanflags |= FLAG_EXCLUSIVE;
	c->progressmask = 0;
	UPDATE_OURCALLSTATE(gsm, c, AT_CALL_STATE_OVERLAP_RECEIVING);
	c->peercallstate = AT_CALL_STATE_OVERLAP_SENDING;
	c->alive = 1;
	return 0;
}

int gsm_senddtmf(struct gsm_modul *gsm, char digit)
{
	return module_senddtmf(gsm,digit);
}

int gsm_answer(struct gsm_modul *gsm, struct at_call *c, int channel)
{
	if (!gsm || !c) {
		return -1;
	}
	if (channel) { 
		channel &= 0xff;
		c->channelno = channel;
	}
	c->chanflags &= ~FLAG_PREFERRED;
	c->chanflags |= FLAG_EXCLUSIVE;
	c->progressmask = 0;
	UPDATE_OURCALLSTATE(gsm, c, AT_CALL_STATE_CONNECT_REQUEST);
	c->peercallstate = AT_CALL_STATE_ACTIVE;
	c->alive = 1;
	/* Connect request timer */
	if (gsm->retranstimer) {
		gsm_schedule_del(gsm, gsm->retranstimer);
	}
	gsm->retranstimer = 0;

	module_answer(gsm);

	return 0;
}


int gsm_setup(struct gsm_modul *gsm, struct at_call *c, struct gsm_sr *req)
{
	if (!gsm || !c) {
		return -1;
	}

	/* get law */
	if (!req->userl1) {
		req->userl1 = GSM_LAYER_1_ULAW;
	}
	c->userl1 = req->userl1;
	c->userl2 = -1;
	c->userl3 = -1;

	/* get D-channel number*/
	req->channel &= 0xff;
	c->channelno = req->channel;
	
	c->newcall = 0;
	c->complete = req->numcomplete; 

	/* get channel flag */
	if (req->exclusive) {
		c->chanflags = FLAG_EXCLUSIVE;
	} else if (c->channelno) {
		c->chanflags = FLAG_PREFERRED;
	}

	/* get caller and callername */
	if (req->caller) {
		strncpy(c->callernum, req->caller, sizeof(c->callernum));
		if (req->callername) {
			strncpy(c->callername, req->callername, sizeof(c->callername));
		} else {
			c->callername[0] = '\0';
		}
	} else {
		c->callernum[0] = '\0';
		c->callername[0] = '\0';
	}

	/* get callednum */
	if (req->called) {
		strncpy(c->callednum, req->called, sizeof(c->callednum));
	} else {
		return -1;
	}

	c->progressmask = 0;
	
	module_dial(gsm, c);
	
	c->alive = 1;
	/* make sure we call GSM_EVENT_HANGUP_ACK once we send/receive RELEASE_COMPLETE */
	c->sendhangupack = 1;
	UPDATE_OURCALLSTATE(gsm, c, AT_CALL_STATE_CALL_INITIATED);
	c->peercallstate = AT_CALL_STATE_OVERLAP_SENDING;	
	
	return 0;
}


void gsm_destroycall(struct gsm_modul *gsm, struct at_call *call)
{
	if (gsm && call) {
		gsm_call_destroy(gsm, 0, call);
	}
	return;
}


int gsm_hangup(struct gsm_modul *gsm, struct at_call *c, int cause)
{
/*	int disconnect = 1;
	int release_compl = 0;
*/
	if (!gsm || !c) {
		return -1;
	}

	if (cause == -1) {
		/* normal clear cause */
		cause = 16;
	}
	if (gsm->debug & GSM_DEBUG_AT_STATE) {
		gsm_message(gsm, "NEW_HANGUP DEBUG: Calling at_hangup, ourstate %s, peerstate %s\n",callstate2str(c->ourcallstate),callstate2str(c->peercallstate));
	}

	/* If mandatory IE was missing, insist upon that cause code */
	if (c->cause == GSM_CAUSE_MANDATORY_IE_MISSING) {
		cause = c->cause;
	}
#if 0
	if (cause == 34 || cause == 44 || cause == 82 || cause == 1 || cause == 81) {
		/* We'll send RELEASE_COMPLETE with these causes */
		disconnect = 0;
		release_compl = 1;
	}
	if (cause == 6 || cause == 7 || cause == 26) {
		/* We'll send RELEASE with these causes */
		disconnect = 0;
	}
#endif
	
	/* All other causes we send with DISCONNECT */
	switch(c->ourcallstate) {
		case AT_CALL_STATE_NULL:
			if (c->peercallstate == AT_CALL_STATE_NULL) {
				/* free the resources if we receive or send REL_COMPL */
				gsm_call_destroy(gsm, c->cr, NULL);
			} else if (c->peercallstate == AT_CALL_STATE_RELEASE_REQUEST) {
				gsm_call_destroy(gsm, c->cr, NULL);
			}
			break;
		case AT_CALL_STATE_CALL_INITIATED:
			/* we sent SETUP */
		case AT_CALL_STATE_OVERLAP_SENDING:
			/* received SETUP_ACKNOWLEDGE */
		case AT_CALL_STATE_OUTGOING_CALL_PROCEEDING:
			/* received CALL_PROCEEDING */
		case AT_CALL_STATE_CALL_DELIVERED:
			/* received ALERTING */
		case AT_CALL_STATE_CALL_PRESENT:
			/* received SETUP */
		case AT_CALL_STATE_CALL_RECEIVED:
			/* sent ALERTING */
		case AT_CALL_STATE_CONNECT_REQUEST:
			/* sent CONNECT */
		case AT_CALL_STATE_INCOMING_CALL_PROCEEDING:
			/* we sent CALL_PROCEEDING */
		case AT_CALL_STATE_OVERLAP_RECEIVING:
			/* received SETUP_ACKNOWLEDGE */
			/* send DISCONNECT in general */
			gsm_call_disconnect(gsm,c,cause);	
			//gsm_call_destroy(gsm, c->cr, NULL);
			break;
		case AT_CALL_STATE_ACTIVE:
			/* received CONNECT */
			
			gsm_call_disconnect(gsm,c,cause);
				//gsm_call_destroy(gsm, c->cr, NULL);

			break;
		case AT_CALL_STATE_DISCONNECT_REQUEST:
			/* sent DISCONNECT */
			gsm_call_destroy(gsm, c->cr, NULL);

			break;
		case AT_CALL_STATE_DISCONNECT_INDICATION:
			/* received DISCONNECT */
			gsm_call_destroy(gsm, c->cr, NULL);
			break;
		case AT_CALL_STATE_RELEASE_REQUEST:
			/* sent RELEASE */
			/* don't do anything, waiting for RELEASE_COMPLETE */
			gsm_call_destroy(gsm, c->cr, NULL);

			break;
		case AT_CALL_STATE_RESTART:
		case AT_CALL_STATE_RESTART_REQUEST:
			/* sent RESTART */
			gsm_error(gsm, "at_hangup shouldn't be called in this state, ourstate %s, peerstate %s\n",callstate2str(c->ourcallstate),callstate2str(c->peercallstate));
			break;
		default:
			gsm_message(gsm, "We're not yet handling hanging up when our state is %d, ourstate %s, peerstate %s\n",
				  c->ourcallstate,
				  callstate2str(c->ourcallstate),
				  callstate2str(c->peercallstate));
			return -1;
	}
	
	if (c->ourcallstate != AT_CALL_STATE_NULL) {
		module_hangup(gsm);
	}
	
	/* we did handle hangup properly at this point */
	return 0;
}


/******************************************************************************
 * Create a call
 * param:
 *		gsm: struct gsm_modul
 * return:
 *	   	struct at_call
 ******************************************************************************/
struct at_call *gsm_new_call(struct gsm_modul *gsm)
{
	struct at_call *cur;
	
	if (!gsm) {
		return NULL;
	}

	gsm->cref++;
	if (gsm->cref > 32767) {
		gsm->cref = 1;
	}


	cur = gsm_getcall(gsm, gsm->cref, 1);
	return cur;
}


/******************************************************************************
 * Dump gsm event message
 * param:
 *		gsm: struct gsm_modul
 *		e: gsm_event
 * return:
 *	   	void
 ******************************************************************************/
void gsm_dump_event(struct gsm_modul *gsm, gsm_event *e)
{
	if (!gsm || !e) {
		return;
	}
	
	gsm_message(gsm, "Event type: %s (%d)\n", gsm_event2str(e->gen.e), e->gen.e);
	switch(e->gen.e) {
		case GSM_EVENT_DCHAN_UP:
		case GSM_EVENT_DCHAN_DOWN:
			break;
		case GSM_EVENT_CONFIG_ERR:
			gsm_message(gsm, "Error: %s", e->err.err);
			break;
		case GSM_EVENT_RESTART:
			gsm_message(gsm, "Restart on channel %d\n", e->restart.channel);
		case GSM_EVENT_RING:
			gsm_message(gsm, "Calling number: %s \n", e->ring.callingnum);
			gsm_message(gsm, "Called number: %s \n", e->ring.callednum);
			gsm_message(gsm, "Channel: %d (%s) Reference number: %d\n", e->ring.channel, e->ring.flexible ? "Flexible" : "Not Flexible", e->ring.cref);
			break;
		case GSM_EVENT_HANGUP:
			gsm_message(gsm, "Hangup, reference number: %d, reason: %s\n", e->hangup.cref, gsm_cause2str(e->hangup.cause));
			break;
		default:
			gsm_message(gsm, "Don't know how to dump events of type %d\n", e->gen.e);
	}
}

/******************************************************************************
 * Dump GSM sys info
 *			Show Switchtype
 *			Show Type
 *			Show Network Status
 *			Show Net Coverage
 *			Show SIM IMSI
 *			Show Card IMEI
 * param:
 *		gsm: struct gsm_modul
 * return:
 *		gsm module sys info
 * e.g.
 *		used in chan_extra.so
 *		gsm show span 1
			D-channel: 2
			Status: Provisioned, Down, Active
			Switchtype: SimCom 100/300
			Type: CPE
			Network Status: Unregistered
			Network Name:
			Signal Quality (0,31): -1
			SIM IMSI:
			Card IMEI:
 ******************************************************************************/
char *gsm_dump_info_str(struct gsm_modul *gsm)
{
	char buf[4096];
	int len = 0;
	
	if (!gsm) {
		return NULL;
	}

	/* Might be nice to format these a little better */
	len += snprintf(buf + len, sizeof(buf)-len, "Type: %s\n", gsm_node2str(gsm->localtype));
//	len += snprintf(buf + len, sizeof(buf)-len, "Switchtype: %s\n", gsm_switch2str(gsm->switchtype));
	len += snprintf(buf + len, sizeof(buf)-len, "Manufacturer: %s\n", gsm->manufacturer);
	len += snprintf(buf + len, sizeof(buf)-len, "Model Name: %s\n", gsm->model_name);
	len += snprintf(buf + len, sizeof(buf)-len, "Model IMEI: %s\n", gsm->imei);
	len += snprintf(buf + len, sizeof(buf)-len, "Revision: %s\n", gsm->revision);
	len += snprintf(buf + len, sizeof(buf)-len, "Network Name: %s\n", gsm->net_name);
	len += snprintf(buf + len, sizeof(buf)-len, "Network Status: %s\n", gsm_network2str(gsm->network));
	len += snprintf(buf + len, sizeof(buf)-len, "Signal Quality (0,31): %d\n", gsm->coverage);
	len += snprintf(buf + len, sizeof(buf)-len, "BER value (0,7): %d\n", gsm->ber);
//Freedom del 2011-10-10 10:11
//	len += snprintf(buf + len, sizeof(buf)-len, (gsm->switchtype == GSM_SWITCH_EM200) ? "Card GSN: %s\n" : "Card IMEI: %s\n", gsm->imei);
	len += snprintf(buf + len, sizeof(buf)-len, "SIM IMSI: %s\n", gsm->imsi);
	len += snprintf(buf + len, sizeof(buf)-len, "SIM SMS Center Number: %s\n",gsm->sim_smsc);

	return strdup(buf);
}

struct gsm_sr *gsm_sr_new(void)
{
	struct gsm_sr *req;
	req = malloc(sizeof(*req));
	if (req) {
		gsm_sr_init(req);
	}
	
	return req;
}

void gsm_sr_free(struct gsm_sr *sr)
{
	if (sr) {
		free(sr);
	}
}

int gsm_sr_set_channel(struct gsm_sr *sr, int channel, int exclusive, int nonisdn)
{
	sr->channel = channel;
	sr->exclusive = exclusive;
	sr->nonisdn = nonisdn;
	return 0;
}

int gsm_sr_set_called(struct gsm_sr *sr, char *called, int numcomplete)
{
	sr->called = called;
	sr->numcomplete = numcomplete;
	return 0;
}

int gsm_sr_set_caller(struct gsm_sr *sr, char *caller, char *callername, int callerpres)
{
	sr->caller = caller;
	sr->callername = callername;
	return 0;
}

static int __gsm_send_text(struct gsm_modul *gsm, char *destination, char *message)
{
	return module_send_text(gsm, destination, message);
}
 
static void gsm_resend_sms_txt(void *info)
{
	sms_info_u *sms_info = info;
	struct gsm_modul *gsm	= sms_info->txt_info.gsm;
	char *destination		= sms_info->txt_info.destination;
	char *message			= sms_info->txt_info.message;

	if (gsm->state != GSM_STATE_READY) {
		int resendsmsidx = gsm_schedule_event(gsm, 2000, gsm_resend_sms_txt, info);
		sms_info->txt_info.resendsmsidx = resendsmsidx;
		//Freedom Add 2011-10-27 16:41 Release memory
		if (resendsmsidx < 0 && sms_info) {
			gsm_error(gsm, "Can't schedule sending sms!\n");
			free(sms_info);
			sms_info = NULL;
		}
	} else {
		gsm->sms_info = sms_info;
		__gsm_send_text(gsm, destination, message);
	}
}

/*
static void gsm_resend_ussd(void *info)
{
	ussd_info_t *ussd_info = info;
	struct gsm_modul *gsm	= ussd_info->gsm;
	char *message			= ussd_info->message;

	if (gsm->state != GSM_STATE_READY) {
		int resendsmsidx = gsm_schedule_event(gsm, 2000, gsm_resend_ussd, info);
		ussd_info->resendsmsidx = resendsmsidx;
		if (resendsmsidx < 0 && ussd_info) {
			gsm_error(gsm, "Can't schedule sending sms!\n");
			free(ussd_info);
			ussd_info = NULL;
		}
	} else {
		gsm->ussd_info = ussd_info;
		module_send_ussd(gsm, message);
	}
} 
*/ 

int gsm_send_ussd(struct gsm_modul *gsm, const char *message) 
{
	int res = -1;
	ussd_info_t *ussd_info;
	if (!gsm)
	{
		return res;
	}	
	
	ussd_info = malloc(sizeof(ussd_info_t));
	if (!ussd_info) {
		gsm_error(gsm, "unable to malloc!\n");
		return res;
	}
	ussd_info->gsm = gsm;
	strncpy(ussd_info->message, message, sizeof(ussd_info->message));
	
	gsm->ussd_info = ussd_info;
	module_send_ussd(gsm, ussd_info->message);
	res = 0;


	return res;
}

/******************************************************************************
 * send sms
 * param:
 *		gsm: gsm module
 *		destination: called number
 *		message: sms body
 * return:
 *		0: send sms ok
 *		-1: can not send sms
 * e.g.
 *		gsm_send_sms(gsm, "1000", "Hello World")
 ******************************************************************************/
int gsm_send_text(struct gsm_modul *gsm, const char *destination, const char *message, const char *id) 
{
	int res = -1;
	sms_info_u *sms_info = NULL;	
	
	if (!gsm) {
		return res;
	}
	
	sms_info = malloc(sizeof(sms_txt_info_t));
	if (!sms_info) {
		gsm_error(gsm, "unable to malloc!\n");
		return res;
	}

	//id
	if(id) {
		strncpy(sms_info->pdu_info.id,id,sizeof(sms_info->pdu_info.id));
	} else {
		sms_info->pdu_info.id[0] = '\0';
	}
	
	sms_info->txt_info.gsm = gsm;
	strncpy(sms_info->txt_info.destination, destination, sizeof(sms_info->txt_info.destination));
	strncpy(sms_info->txt_info.message, message, sizeof(sms_info->txt_info.message));		
	
	if (GSM_STATE_READY != gsm->state) {
		if (gsm_schedule_check(gsm) < 0) {
			gsm_error(gsm, "No enough space for sending sms!\n");
			return -1;
		}
		int resendsmsidx = gsm_schedule_event(gsm, 2000, gsm_resend_sms_txt, (void *)sms_info);
		sms_info->txt_info.resendsmsidx = resendsmsidx;
		if (resendsmsidx < 0 && sms_info) {
			gsm_error(gsm, "Can't schedule sending sms!\n");
			free(sms_info);
			sms_info = NULL;
			return -1;
		}
		res = 0;
	}  else {	
		gsm->sms_info = sms_info;
		__gsm_send_text(gsm, sms_info->txt_info.destination, sms_info->txt_info.message);
		res = 0;
	}

	return res;
}

static int __gsm_send_pdu(struct gsm_modul *gsm, char *message)
{
	return module_send_pdu(gsm, message);
}

static void gsm_resend_sms_pdu(void *info)
{
	sms_info_u *sms_info = info;
	struct gsm_modul *gsm	= sms_info->pdu_info.gsm;

	if (gsm->state != GSM_STATE_READY) {
		int resendsmsidx = gsm_schedule_event(gsm, 2000, gsm_resend_sms_pdu, info);
		sms_info->pdu_info.resendsmsidx = resendsmsidx;
		//Freedom Add 2011-10-27 16:41 Release memory
		if (resendsmsidx < 0 && sms_info) {
			gsm_error(gsm, "Can't schedule sending sms!\n");
			free(sms_info);
			sms_info = NULL;
		}
	} else {
		gsm->sms_info = sms_info;
		__gsm_send_pdu(gsm, sms_info->pdu_info.message);
	}
}

/******************************************************************************
 * send pdu
 * param:
 *		gsm: gsm module
 *  	message: pdu body
 * return:
 *		0: send pdu ok
 *		-1: can not send pdu
 * e.g.
 *		gsm_send_pdu(gsm, "0891683110808805F0040BA13140432789F300F1010112316435230BE8F71D14969741F9771D")
 ******************************************************************************/
int gsm_send_pdu(struct gsm_modul *gsm, const char *message, const char *text, const char* id) 
{
	int res = -1;
	sms_info_u *sms_info = NULL;	
	char smsc[3];
	int smsc_len;
	int len = 0;
	if (!gsm) {
		return res;
	}	
	
	sms_info = malloc(sizeof(sms_pdu_info_t));
	if (!sms_info) {
		gsm_error(gsm, "unable to malloc!\n");
		return res;
	}

	//id
	if(id) {
		strncpy(sms_info->pdu_info.id,id,sizeof(sms_info->pdu_info.id));
	} else {
		sms_info->pdu_info.id[0] = '\0';
	}

	//text
	if(text) {
		strncpy(sms_info->pdu_info.text,text,sizeof(sms_info->pdu_info.text));
	} else {
		sms_info->pdu_info.text[0] = '\0';
	}
	
	// gsm
	sms_info->pdu_info.gsm = gsm;

	// pdu body
	strncpy(sms_info->pdu_info.message, message, 1024);	

	// Destination
	pdu_get_send_number(message, sms_info->pdu_info.destination, sizeof(sms_info->pdu_info.destination));

	// SMSC information length
	len = strlen(message);
	strncpy(smsc, message, sizeof(smsc) - 1);
	smsc[2] = '\0';
	smsc_len = gsm_hex2int(smsc, 2);
	len = (len / 2) - 1 - smsc_len;
	sms_info->pdu_info.len = len;
	
	if (GSM_STATE_READY != gsm->state) {
		if (gsm_schedule_check(gsm) < 0) {
			gsm_error(gsm, "No enough space for sending sms!\n");
			return -1;
		}
		// schedule index
		int resendsmsidx = gsm_schedule_event(gsm, 2000, gsm_resend_sms_pdu, (void *)sms_info);
		sms_info->pdu_info.resendsmsidx = resendsmsidx;
		if (resendsmsidx < 0 && sms_info) {
			gsm_error(gsm, "Can't schedule sending sms!\n");
			free(sms_info);
			sms_info = NULL;
			return -1;
		}
		res = 0;
	} else {
		gsm->sms_info = sms_info;
		__gsm_send_pdu(gsm, sms_info->pdu_info.message);
		res = 0;
	}

	return res;
}


/******************************************************************************
 * send pin
 * param:
 *		gsm: gsm module
 *
 * return:
 *
 * e.g.
 *		gsm_send_pin(gsm, "1234")
 ******************************************************************************/
int gsm_send_pin(struct gsm_modul *gsm, const char *pin)
{	
	if (!gsm) {
		return -1;
	}

	return module_send_pin(gsm, pin);
}

int gsm_san(struct gsm_modul *gsm, char *in, char *out, int len) 
{
	int i = 0;
	int skip = 0;
	char *tmp = NULL;

	if (len <= 0) {
		return 0;
	}

	//Freedom Add 2013-05-23 15:59
	//Fix Up if get USSD code:
	//+CUSD: 2, "MSISDN: \r\n8801552932082", 15
	//Change middle '\r' to ' ';
	////////////////////////////////////////////////////////////////////////////////
	char * p = in;
	int start = 0;
	while ((*p == '\r') || (*p == '\n')) {
		p++;
	}
	if(AT(AT_CHECK_USSD)) {
		if(strncmp(p,AT(AT_CHECK_USSD),strlen(AT(AT_CHECK_USSD))) == 0) {
			for(; p<in+len; p++) {
				if(start == 0) {
					if(*p == '"') {
						start = 1;
					}
				} else {
					if(*p == '\r') {
						*p = ' ';
					} else if(*p == '"') {
						start = 0;
					}
				}
			}
		}
	}
	////////////////////////////////////////////////////////////////////////////////

	if ((len > 0) && ((gsm->sanidx + len < sizeof(gsm->sanbuf)))) {
		memcpy(gsm->sanbuf + gsm->sanidx, in, len);
		gsm->sanidx += len;
		gsm->sanbuf[gsm->sanidx] = '\0';
	}

	i = 0;
	while ((gsm->sanbuf[i] == '\r') || (gsm->sanbuf[i] == '\n')) {
		i++;
	}
	skip = i;
	gsm->sanskip = skip;
	tmp = (char *)memchr(gsm->sanbuf + skip, '\r', gsm->sanidx - skip);
	
	if (tmp){
		i = tmp - (gsm->sanbuf + skip);
		memcpy(out, (gsm->sanbuf + skip), i);
		out[i] = 0x0;
		memmove(&gsm->sanbuf[0], &gsm->sanbuf[skip+i], sizeof(gsm->sanbuf) - i - skip);
		gsm->sanidx -= i + skip;

		return i;
	} else {
		if ((gsm->sanidx - skip == 2) && (gsm->sanbuf[gsm->sanidx - 2] == '>') && (gsm->sanbuf[gsm->sanidx - 1] == ' ')) {
			/* for sim340dz and m20 */
			out[0] = '>';
			out[1] = ' ';
			out[2] = 0x0;
			gsm->sanidx = 0;
			return 2;
		} else if ((gsm->sanidx - skip == 1) && (gsm->sanbuf[gsm->sanidx - 1] == '>')) {
			/* for em200 */
			out[0] = '>';
			out[1] = 0x0;
			gsm->sanidx = 0;
			return 1;
		} else if (0x0 == gsm->sanbuf[skip]) {
			/* gsm->sanbuf = "\r\n" */
			if (gsm->sanskip == 4 && gsm_compare(gsm->at_last_recv, "+CMT: \""))
			{
				out[0] = '\0';
				return -3;
			}
			gsm->sanskip = 0;
			return 0;
		} else {
			i = gsm->sanidx - skip;
			memcpy(out, (gsm->sanbuf + skip), i);
			out[i] = 0x0;
			return -1;
		}
	}

	return 0;
}

/*Makes Add 2012-4-9 14:01*/

#ifdef CONFIG_CHECK_PHONE

void gsm_hangup_phone(struct gsm_modul *gsm)
{
	module_hangup_phone(gsm);
}
void gsm_set_check_phone_mode(struct gsm_modul *gsm,int mode)
{
	gsm->check_mode=mode;
}

int gsm_check_phone_stat(struct gsm_modul *gsm, const char *phone_number,int hangup_flag,unsigned int timeout)
{
	return module_check_phone_stat(gsm, phone_number,hangup_flag,timeout);
}
#endif //CONFIG_CHECK_PHONE

#ifdef GSM0710_MODE
int gsm_get_mux_command(struct gsm_modul *gsm,char *command)
{
	int ret=0;
	const char *string = AT(AT_CMUX);
	if(string) {
		strcpy(command,string);
	}
	else
		ret=-1;
	return ret;
}

int gsm_mux_end(struct gsm_modul *gsm, int restart_at_flow)
{
	return module_mux_end(gsm,restart_at_flow);
}
#endif //GSM0710_MODE

int is_call_state(int state)
{
	switch(state) {
		case GSM_STATE_CALL_INIT:
		case GSM_STATE_CALL_MADE:
		case GSM_STATE_CALL_PRESENT:
		case GSM_STATE_CALL_PROCEEDING:
		case GSM_STATE_CALL_PROGRESS:
		case GSM_STATE_PRE_ANSWER:
		case GSM_STATE_CALL_ACTIVE_REQ:
		case GSM_STATE_CALL_ACTIVE:
		case GSM_STATE_RING:
		case GSM_STATE_RINGING:
		return 1;
	}

	return 0;
}

char *gsm_state2str(int state)
{
	switch(state) {
		case GSM_STATE_DOWN:
			return "DOWN";
			break;
		case GSM_STATE_INIT:
			return "INIT";
			break;
		case GSM_STATE_UP:
			return "UP";
			break;
		case GSM_STATE_SEND_HANGUP:
			return "SEND HANGUP";
			break;
		case GSM_STATE_SET_ECHO:
			return "SET ECHO";
			break;
		case GSM_STATE_SET_REPORT_ERROR:
			return "SET REPORT ERROR";
			break;
		case GSM_STATE_MODEL_NAME_REQ:
			return "MODEL NAME REQ";
			break;
		case GSM_STATE_MANUFACTURER_REQ:
			return "MANUFACTURER REQ";
			break;
		case GSM_STATE_GET_SMSC_REQ:
			return "GET SMSC REQ";
			break;
		case GSM_STATE_VERSION_REQ:
			return "VERSION REQ";
			break;
		case GSM_STATE_GSN_REQ:
			return "GSN REQ";
			break;
		case GSM_STATE_IMEI_REQ:
			return "IMEI REQ";
			break;
		case GSM_STATE_IMSI_REQ:
			return "IMSI REQ";
			break;
		case GSM_STATE_INIT_0:
			return "INIT 0";
			break;
		case GSM_STATE_INIT_1:
			return "INIT 1";
			break;
		case GSM_STATE_INIT_2:
			return "INIT 2";
			break;
		case GSM_STATE_INIT_3:
			return "INIT 3";
			break;
		case GSM_STATE_INIT_4:
			return "INIT 4";
			break;
		case GSM_STATE_INIT_5:
			return "INIT 5";
			break;
		case GSM_STATE_SIM_READY_REQ:
			return "SIM READY REQ";
			break;
		case GSM_STATE_SIM_PIN_REQ:
			return "SIM PIN REQ";
			break;
		case GSM_STATE_SIM_PUK_REQ:
			return "SIM PUK REQ";
			break;
		case GSM_STATE_SIM_READY:
			return "SIM READY";
			break;
		case GSM_STATE_UIM_READY_REQ:
			return "UIM READY REQ";
			break;
		case GSM_STATE_UIM_PIN_REQ:
			return "UIM PIN REQ";
			break;
		case GSM_STATE_UIM_PUK_REQ:
			return "UIM PUK REQ";
			break;
		case GSM_STATE_UIM_READY:
			return "UIM READY";
			break;
#ifdef GSM0710_MODE
		case GSM_INIT_MUX:
			return "INIT MUX";
			break;
#endif //GSM0710_MODE
		case GSM_STATE_MOC_STATE_ENABLED:
			return "MOC STATE ENABLED";
			break;
		case GSM_STATE_SET_SIDE_TONE:
			return "SET SIDE TONE";
			break;
		case GSM_STATE_CLIP_ENABLED:
			return "CLIP ENABLED";
			break;
		case GSM_STATE_BAND_BINDING:
			return "BAND BINDING";
			break;
		case GSM_STATE_RSSI_ENABLED:
			return "RSSI ENABLED";
			break;
		case GSM_STATE_SET_NET_URC:
			return "SET NET URC";
			break;
		case GSM_STATE_NET_REQ:
			return "NET REQ";
			break;
		case GSM_STATE_NET_OK:
			return "NET OK";
			break;

		case GSM_AT_MODE:
			return "AT MODE";
			break;
		case GSM_STATE_NET_NAME_REQ:
			return "NET NAME REQ";
			break;
		case GSM_STATE_READY:
			return "READY";
			break;
		case GSM_STATE_CALL_INIT:
			return "CALL INIT";
			break;
		case GSM_STATE_CALL_MADE:
			return "CALL MADE";
			break;
		case GSM_STATE_CALL_PRESENT:
			return "CALL PRESENT";
			break;
		case GSM_STATE_CALL_PROCEEDING:
			return "CALL PROCEEDING";
			break;
		case GSM_STATE_CALL_PROGRESS:
			return "CALL PROGRESS";
			break;
		case GSM_STATE_PRE_ANSWER:
			return "PRE ANSWER";
			break;
		case GSM_STATE_CALL_ACTIVE_REQ:
			return "CALL ACTIVE REQ";
			break;
		case GSM_STATE_CALL_ACTIVE:
			return "CALL ACTIVE";
			break;
		case GSM_STATE_RING:
			return "RING";
			break;
		case GSM_STATE_RINGING:
			return "RINGING";
			break;
		case GSM_STATE_HANGUP_REQ:
			return "HANGUP REQ";
			break;
		case GSM_STATE_HANGUP_ACQ:
			return "HANGUP ACQ";
			break;
		case GSM_STATE_HANGUP:
			return "HANGUP";
			break;

		case GSM_STATE_SMS_SET_CHARSET:
			return "SMS SET CHARSET";
			break;
		case GSM_STATE_SMS_SET_INDICATION:
			return "SMS SET INDICATION";
			break;
		case GSM_STATE_SET_SPEAK_VOL:
			return "SET SPEAK VOL";
			break;
		case GSM_STATE_SET_MIC_VOL:
			return "SET MIC VOL";
			break;
		case GSM_STATE_SMS_SET_UNICODE:
			return "SMS SET UNICODE";
			break;
		case GSM_STATE_SMS_SENDING:
			return "SMS SENDING";
			break;
		case GSM_STATE_SMS_SENT:
			return "SMS SENT";
			break;
		case GSM_STATE_SMS_SENT_END:
			return "SMS SENT END";
			break;
		case GSM_STATE_SMS_RECEIVED:
			return "SMS RECEIVED";
			break;
		case GSM_STATE_USSD_SENDING:
			return "USSD SENDING";
			break;
		case GSM_STATE_SIM_CFUN_FULL:
			return "CFUN FULL";
			break;
		case GSM_STATE_SIM_CFUN_MINI:
			return "CFUN MINI";
			break;
#ifdef CONFIG_CHECK_PHONE
		case GSM_STATE_PHONE_CHECK:
			return "PHONE CHECK";
			break;
#endif
		//Freedom Add for if GSM module can't timely start. power restart modules. 2013-05-14 09:08
		case GSM_STATE_POWER_RESTART:
			//return "POWER RESTART";
			return "WAIT READY";
			break;
	}
	return "UNKNOW";
}

long sys_uptime(void)
{
	struct sysinfo si;
	if(0 == sysinfo(&si)) {
		return si.uptime;
	}
	
	return 0;
}


//Freedom Add for send AT commmands according to simple queue. 2013-07-09 14:13
#ifdef TX_QUEUE
static void (*txq_lock_func)(int span);
static void (*txq_unlock_func)(int span);

void set_txq_lock_func(void (*lock_func)(int),void (*unlock_func)(int))
{
	txq_lock_func = lock_func;
	txq_unlock_func = unlock_func;
}

void init_tx_queue(struct gsm_modul* gsm)
{
	memset(gsm->txq, 0, sizeof(gsm->txq));
	gsm->txqi_a = 0;
	gsm->txqi_b = 0;
	gsm->have_report = 1;
	gsm->wait_report = 0;
	gsm->tq_sendcount = 0;
}

int add_tx_queue(struct gsm_modul* gsm, char* buf, int len)
{
	txq_lock_func(gsm->span);
	gsm->txq[gsm->txqi_a] = malloc(sizeof(gsm->txq[0]));
	gsm->txq[gsm->txqi_a]->tx_buf = malloc(len+1);
	gsm->txq[gsm->txqi_a]->tx_buf[len] = '\0';
	strncpy(gsm->txq[gsm->txqi_a]->tx_buf, buf, len);
	gsm->txqi_a++;
	gsm->txqi_a %= sizeof(gsm->txq)/sizeof(gsm->txq[0]);
	txq_unlock_func(gsm->span);

	return len;
}

int exec_tx_queue(struct gsm_modul* gsm)
{
	txq_lock_func(gsm->span);

	if( gsm->have_report && (gsm->txqi_a != gsm->txqi_b) ) {//Send next AT commands before have GSM module report.
		int buflen;
		char* buf;
		int res;

		if( gsm->txq[gsm->txqi_b] == NULL || gsm->txq[gsm->txqi_b]->tx_buf == NULL ) {	//That impossibility, error!!!
			gsm->txqi_b++ ;
			txq_unlock_func(gsm->span);
			gsm_error(gsm, "That impossibility, error!!! %s:%d\n", __FILE__, __LINE__);
			return 0;
		}

		buflen = strlen(gsm->txq[gsm->txqi_b]->tx_buf);
		buf = malloc(buflen+2);
		memset(buf, 0, buflen+2);
		memcpy(buf, gsm->txq[gsm->txqi_b]->tx_buf, buflen);

		gsm->have_report = 0;
		gsm->wait_report = 1;
		gsm->tq_sendtime = time(NULL);
		gsm->tq_sendcount++;

#if 0
		{
			int i;
			if(gsm->span == 1) {
				printf("send:");
				for(i=0;i<buflen+2;i++) {
					printf("%d,",buf[i]);
				}
				printf("\n");
			}
		}
#endif

		res = write(gsm->fd, buf, buflen+2);

		if (res < 0) {
			if (errno != EAGAIN) {
				gsm_error(gsm, "Write to %d failed: %s\n", gsm->fd, strerror(errno));
			}
			free(buf);
			txq_unlock_func(gsm->span);
			return 0;
		}

		if((gsm->debug_at_fd > 0) && (gsm->debug_at_flag)) {
			char wbuf[1024];
			int wlen;
			wlen = convert_str((const char *)buf,res,wbuf,sizeof(wbuf),1);
			if(wlen > 0) {
				write_time(gsm->debug_at_fd);
				write(gsm->debug_at_fd,wbuf,wlen);
			}
		}

		/* Last sent command to dchan */
		strncpy(gsm->at_last_sent, buf, sizeof(gsm->at_last_sent));

		/* at_lastsent length */
		gsm->at_last_sent_idx = buflen;


		free(buf);
		txq_unlock_func(gsm->span);
		return res;
	}
	txq_unlock_func(gsm->span);

	return 0;
}

void set_report(struct gsm_modul* gsm)
{
	txq_lock_func(gsm->span);
	gsm->have_report = 1;
	txq_unlock_func(gsm->span);
}

static void free_tx_queue(struct gsm_modul* gsm)
{
	int i;
	i = gsm->txqi_b;
	while(i < gsm->txqi_a) {
		if(gsm->txq[i]) {
			if(gsm->txq[i]->tx_buf) {
				free(gsm->txq[i]->tx_buf);
			}
			free(gsm->txq[i]);
			gsm->txq[i] = NULL;
		}
		i++;
		i %= sizeof(gsm->txq)/sizeof(gsm->txq[0]);
	}
	gsm->txqi_b = gsm->txqi_a;
}

gsm_event* process_report(struct gsm_modul* gsm)
{
	txq_lock_func(gsm->span);

	if( gsm->wait_report && (gsm->txqi_a != gsm->txqi_b) ) {
		if( 0 == gsm->have_report ) {		//No has GSM Module report. maybe Send failed or maybe GSM module die. 
			if(time(NULL) - gsm->tq_sendtime > 10) {  //Time out, Send AT commmand again
				gsm->have_report = 1;
			} else if(gsm->tq_sendcount >= 3) { //power restart GSM module.
				free_tx_queue(gsm);
				gsm->ev.e = GSM_EVENT_POWER_RESTART;
				txq_unlock_func(gsm->span);
				return &gsm->ev;
			}
		} else {	//Has GSM module report. Maybe send next AT Command. Free last AT command bufffer.
			gsm->wait_report = 0;
			gsm->tq_sendcount = 0;
			if(gsm->txq[gsm->txqi_b]) {
				if(gsm->txq[gsm->txqi_b]->tx_buf) {
					free(gsm->txq[gsm->txqi_b]->tx_buf);
				}
				free(gsm->txq[gsm->txqi_b]);
				gsm->txq[gsm->txqi_b] = NULL;
			}
			gsm->txqi_b++;
			gsm->txqi_b %= sizeof(gsm->txq)/sizeof(gsm->txq[0]);
		}
	}
	txq_unlock_func(gsm->span);

	return NULL;
}

unsigned char is_normal_reply(struct gsm_modul* gsm)
{
	int len;
	int i;
	char buf[1024];

	len = strlen(gsm->at_pre_recv);
	strncpy(buf,gsm->at_pre_recv,sizeof(buf));
	txq_lock_func(gsm->span);

	for(i=0;i<len;i++) {
		if(buf[i] == '\r' || buf[i] == '\n' || buf[i] == '>') {
			goto return_true;
		}
	}

	txq_unlock_func(gsm->span);
	return 0;

return_true:
	txq_unlock_func(gsm->span);
	return 1;
}

//Freedom Add for ignore some AT commmands. irrelevant answer 2013-08-01 17:20
unsigned char is_active_report(struct gsm_modul* gsm)
{
	char buf[1024];

	gsm_trim(gsm->at_pre_recv, strlen(gsm->at_pre_recv), buf, sizeof(buf));

	txq_lock_func(gsm->span);
	if(0 == strcmp(buf, AT(AT_CREG1))) {
		goto return_true;
	}

	if(0 == strcmp(buf, AT(AT_CREG2))) {
		goto return_true;
	}

	if(0 == strcmp(buf, AT(AT_CREG3))) {
		goto return_true;
	}

	if(0 == strcmp(buf, AT(AT_CREG4))) {
		goto return_true;
	}

	if(0 == strcmp(buf, AT(AT_CREG5))) {
		goto return_true;
	}

	if(0 == strcmp(buf, "SM BL Ready")) {
		goto return_true;
	}

	if(0 == strcmp(buf, "Call Ready")) {
		goto return_true;
	}

	if(0 == strcmp(buf, "NORMAL POWER DOWN")) {
		goto return_true;
	}

	if(0 == strncmp(buf,"+CSQN:",sizeof("+CSQN:")-1)) {
		if(strlen(buf) <= sizeof("+CSQN: 31,0")) {
			goto return_true;
		}
	}

	txq_unlock_func(gsm->span);
	return 0;

return_true:
	txq_unlock_func(gsm->span);
	return 1;
}
#endif //TX_QUEUE

