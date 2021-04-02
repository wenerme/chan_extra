/*
 * libgsmat: An implementation of OpenVox G400P GSM/CDMA cards
 *
 * Written by mark.liu <mark.liu@openvox.cn>
 * 
 * Modified by freedom.huang <freedom.huang@openvox.cn>
 * 
 * Copyright (C) 2005-2013 OpenVox Communication Co. Ltd,
 * All rights reserved.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2 as published by the
 * Free Software Foundation. See the LICENSE file included with
 * this program for more details.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <time.h>

#include "libgsmat.h"
#include "gsm_internal.h"
#include "gsm_module.h"
#include "gsm_config.h"


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

static void module_get_coverage(struct gsm_modul *gsm, char *h)
{
	int coverage = -1;
	int ber = -1;
	int both = -1;
	
	if (gsm_compare(h,AT(AT_CHECK_SIGNAL1))) {
		both = get_coverage1(gsm->switchtype,h);
	} else if (gsm_compare(h,AT(AT_CHECK_SIGNAL2))) {
		both = get_coverage2(gsm->switchtype,h);
	}

	if(both == -1) {
		gsm->coverage = -1;
		gsm->ber = -1;
		return;
	}

	coverage = both & 0xFF;
	ber = (both >> 8) & 0xFF;

	if ((coverage >= 0) && (coverage <= 31)) {
		gsm->coverage = coverage;
	} else {
		gsm->coverage = -1;
	}

	if ((ber >= 0) && (ber <= 7)) {
		gsm->ber = ber;
	} else {
		gsm->ber = -1;
	}
}

int module_start(struct gsm_modul *gsm) 
{
	gsm->resetting = 0;
	gsm_switch_state(gsm, GSM_STATE_INIT, get_at(gsm->switchtype,AT_CHECK));
	//gsm_switch_state(gsm, GSM_STATE_UP, get_at(gsm->switchtype,AT_ATZ));
	return 0;
}

int module_restart(struct gsm_modul *gsm) 
{
	gsm->resetting = 1;
	gsm_switch_state(gsm, GSM_STATE_UP, get_at(gsm->switchtype,AT_ATZ));
	return 0;
}

int module_dial(struct gsm_modul *gsm, struct at_call *call) 
{
	char buf[128];
	char callednum[128];
	char tmp[128];

	memset(buf, 0x0, sizeof(buf));
	memset(callednum,0,sizeof(callednum));
	memset(tmp,0,sizeof(tmp));

	strncpy(callednum,call->callednum,sizeof(callednum));

	//Jason Add dial prefix 2013-5-9
	if(strlen(gsm->dialprefix)>0){
		snprintf(tmp,sizeof(tmp),"%s%s",gsm->dialprefix,callednum);
		strncpy(callednum,tmp,sizeof(callednum));
	}

	//Freedom Add for anonymous call 2013-08-15 09:37
	if(gsm->anonymouscall){
		snprintf(tmp,sizeof(tmp),"#31#%s",callednum);
		strncpy(callednum,tmp,sizeof(callednum));
	}
	
	get_dial_str(gsm->switchtype, callednum, buf, sizeof(buf));

	//Simulate Dial successful ... Freedom add 2013-05-28 11:18
#ifdef SIMULATE_DIAL
	if(gsm->simulatedial) {
		strcpy(buf,"AT\r\n");
	}
#endif

	gsm_switch_state(gsm, GSM_STATE_CALL_INIT, buf);

	return 0;
}

int module_answer(struct gsm_modul *gsm) 
{
	gsm_switch_state(gsm, GSM_STATE_PRE_ANSWER, AT(AT_ANSWER));
	
	return 0;
}

int module_senddtmf(struct gsm_modul *gsm, char digit)
{
	char buf[128];
	memset(buf, 0x0, sizeof(buf));
	get_dtmf_str(gsm->switchtype, digit, buf, sizeof(buf));

	return gsm_send_at(gsm, buf);
}

int module_hangup(struct gsm_modul *gsm) 
{
#ifdef SIMULATE_DIAL
	if(gsm->simulatedial) {
		gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, "AT");
		return 0;
	}
#endif

	gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
	
	return 0;
}

static char* get_cur_time(char* buf, int size)
{
	time_t  t;
	struct tm *ptm;
	int len = 0;

	time(&t);

	ptm = localtime(&t);
	//len =  strftime(buf,size, "%Y-%m-%d %H:%M:%S", ptm);
	len =  strftime(buf,size, "%H:%M:%S", ptm);
	buf[len] = '\0';

	return buf;
}

int module_send_ussd(struct gsm_modul *gsm, const char *message) 
{	
	//Freedom Modify 2013-05-13 14:51 for simple show USSD response.
#if 0
	if (gsm->state == GSM_STATE_READY) {
//		char time_buf[20];
		char buf[1024];
/*		get_cur_time(time_buf,20);
		gsm_message(gsm, "Send USSD on span %d at %s\n",gsm->span,time_buf);*/
		snprintf(gsm->ussd_sent_buffer, sizeof(gsm->ussd_sent_buffer) - 1, "%s", message);
		get_ussd_str(gsm->switchtype, message, buf, sizeof(buf));
		gsm_switch_state(gsm, GSM_STATE_USSD_SENDING, buf);
		return 0;
	}
	
	if (gsm->debug & GSM_DEBUG_AT_RECEIVED) {
		gsm_message(gsm, "Cannot send USSD when not ready, waiting...\n");
	}
#else
	char buf[1024];
	snprintf(gsm->ussd_sent_buffer, sizeof(gsm->ussd_sent_buffer) - 1, "%s", message);
	get_ussd_str(gsm->switchtype, message, buf, sizeof(buf));
	gsm_send_at(gsm,buf);
	return 0;
#endif

	return -1;
}

int module_send_text(struct gsm_modul *gsm, const char *destination, const char *message) 
{	
	if (gsm->state == GSM_STATE_READY) {
		char time_buf[20];
		get_cur_time(time_buf,20);
		gsm_message(gsm, "Send SMS to %s on span %d at %s\n",gsm->sms_info->txt_info.destination,gsm->span,time_buf);
		snprintf(gsm->sms_sent_buffer, sizeof(gsm->sms_sent_buffer) - 1, "%s", message);
		gsm_switch_state(gsm, GSM_STATE_SMS_SENDING, AT( AT_SEND_SMS_TEXT_MODE));
		return 0;
	}
	
	if (gsm->debug & GSM_DEBUG_AT_RECEIVED) {
		gsm_message(gsm, "Cannot send SMS when not ready, waiting...\n");
	}
	
	return -1;
}

int module_send_pdu( struct gsm_modul *gsm, const char *pdu)
{	
	if (gsm->state == GSM_STATE_READY) {
		char time_buf[20];
		get_cur_time(time_buf,20);
		gsm_message(gsm, "Send SMS to %s on span %d at %s\n",gsm->sms_info->txt_info.destination,gsm->span,time_buf);
		snprintf(gsm->sms_sent_buffer, sizeof(gsm->sms_sent_buffer) - 1, "%s", pdu);
		gsm_switch_state(gsm, GSM_STATE_SMS_SENDING, AT( AT_SEND_SMS_PDU_MODE));
		return 0;
	} 
	
	if (gsm->debug & GSM_DEBUG_AT_RECEIVED) {
		gsm_message(gsm, "Cannot send PDU when not ready, waiting...\n");
	}
	
	return -1;
}


int module_send_pin(struct gsm_modul *gsm, const char *pin)
{
	char buf[256];
	/* If the SIM PIN is blocked */
	if (gsm->state == GSM_STATE_SIM_PIN_REQ) {
		
		memset(buf, 0x0, sizeof(buf));
		get_pin_str(gsm->switchtype, pin, buf, sizeof(buf));
		gsm_send_at(gsm, buf);
	}

	return 0;
}

static int parse_ussd_code(struct gsm_modul *gsm,const char* ori_ussd_code)
{
	//Format:
	//+CUSD: 1, "xxxx",15
	//or
	//+CUSD: 1,"xxxx",15
	//
	// 1: response type
	// "xxxx": USSD string
	// 15: coding

	char buf[1024];
	char encode[1024];
	char *pt1, *pt2;
	int response_type = -1;

	//Get response_type
	//////////////////////////////////////////////
	pt1 = strchr(ori_ussd_code,':');
	if(!pt1) return -1;

	pt2 = strchr(ori_ussd_code,',');
	if(!pt2) return -1;

	if(pt2-pt1-1 <= 0) return -1;
	
	memset(buf,0,sizeof(buf));
	memcpy(buf, pt1+1, pt2-pt1-1);

	//printf("response_type = [%s],%d\n",buf,atoi(buf));
	response_type = atoi(buf);
	gsm->ev.ussd_received.ussd_stat = response_type;
	//////////////////////////////////////////////

	//Get USSD String
	//////////////////////////////////////////////
	pt1 = strchr(ori_ussd_code,'"');
	if(!pt1) return -1;

	pt2 = strrchr(ori_ussd_code,'"');
	if(!pt2) return -1;

	if(pt2-pt1-1 <= 0) return -1;
	
	memset(buf,0,sizeof(buf));
	memcpy(buf, pt1+1, pt2-pt1-1);

	//printf("USSD String = [%s]\n",buf);

	if(-1 != decode_ussd(buf,strlen(buf),encode,sizeof(encode))) { //Decode USSD, If need.
		strncpy(gsm->ev.ussd_received.text, encode, sizeof(gsm->ev.ussd_received.text));
		gsm->ev.ussd_received.len = strlen(encode);
	} else {
		strncpy(gsm->ev.ussd_received.text, buf, sizeof(gsm->ev.ussd_received.text));
		gsm->ev.ussd_received.len = strlen(buf);
	}
	//////////////////////////////////////////////
	
	//Get USSD Code
	//////////////////////////////////////////////
	pt1 = strrchr(ori_ussd_code,',');
	if(!pt1) return -1;

	if(ori_ussd_code + strlen(ori_ussd_code) - pt1 -1 <= 0) return -1;
	
	memset(buf,0,sizeof(buf));
	memcpy(buf, pt1+1, ori_ussd_code + strlen(ori_ussd_code) - pt1 -1);
	//printf("Coding = [%s],%d\n",buf,atoi(buf));
	gsm->ev.ussd_received.ussd_coding = atoi(buf);
	//////////////////////////////////////////////
	
	return response_type;
}


static gsm_event *module_check_ussd(struct gsm_modul *gsm, char *buf, int i)
{
	int response_type;

	//Freedom Del 2013-05-13 14:51 for simple show USSD response.
	//if(gsm->state != GSM_STATE_USSD_SENDING)
	//	return NULL;

	if(gsm_compare(buf, AT(AT_CHECK_USSD))) {
		char *error_msg = NULL;
		response_type = parse_ussd_code(gsm,buf);
		//Freedom Modify 2012-10-11 13:42
#if 0
		switch(response_type) {
		case 1:		//Successful;
			break;
		case -1:
			error_msg = "USSD parse failed\n";
		case 0:
			error_msg = "USSD response type: No further action required 0\n";
			break;
		case 2:
			error_msg = "USSD response type: USSD terminated by network 2\n";
			break;
		case 3:
			error_msg = "USSD response type: Other local client has responded 3\n";
			break;
		case 4:
			error_msg = "USSD response type: Operation not supported 4\n";
			break;
		case 5:
			error_msg = "USSD response type: Network timeout 5\n";
			break;
		default:
			error_msg = "CUSD message has unknown response type \n";
			break;
		}
#else
		if( -1 == response_type ) {
			error_msg = "USSD parse failed\n";
		}
#endif

		if(error_msg) {
			gsm->at_last_recv[0] = '\0';
			gsm->at_pre_recv[0] = '\0';
			if (gsm->ussd_info) {
				free(gsm->ussd_info);
				gsm->ussd_info = NULL;
			}
			//Freedom Del 2013-05-13 14:51 for simple show USSD response.
			//gsm_switch_state(gsm, GSM_STATE_READY,NULL);
			gsm->ev.e = GSM_EVENT_USSD_SEND_FAILED;
			return &gsm->ev;
		} else { //Successful
			gsm->ev.e = GSM_EVENT_USSD_RECEIVED;
			gsm->at_last_recv[0] = '\0';
			gsm->at_pre_recv[0] = '\0';
			
			if (gsm->ussd_info) {
				free(gsm->ussd_info);
				gsm->ussd_info = NULL;
			}
			//Freedom Del 2013-05-13 14:51 for simple show USSD response.
			//gsm_switch_state(gsm, GSM_STATE_READY,NULL);
			return &gsm->ev;
		}		
	} else if ( gsm_compare(buf, AT(AT_CMS_ERROR)) ||
				//Freedom Del 2013-05-13 14:51 for simple show USSD response.
//				gsm_compare(buf, AT(AT_NO_CARRIER)) ||
				gsm_compare(buf, AT(AT_CME_ERROR))) {
		gsm_error(gsm, "Error sending USSD (%s) on span %d.\n", buf, gsm->span);
		if (gsm->ussd_info) {
			free(gsm->ussd_info);
			gsm->ussd_info = NULL;
		}
		//Freedom Del 2013-05-13 14:51 for simple show USSD response.
		//gsm_switch_state(gsm, GSM_STATE_READY,NULL);
		gsm->ev.e = GSM_EVENT_USSD_SEND_FAILED;
		return &gsm->ev;
	}

	return NULL;
}


static gsm_event *module_check_sms(struct gsm_modul *gsm, char *buf, int i)
{
	int res;
	int compare1;
	int compare2;
	char sms_buf[1024];
		
	compare1 = gsm_compare(gsm->at_last_recv, AT(AT_CHECK_SMS));
	compare2 = gsm_compare(gsm->at_pre_recv, AT(AT_CHECK_SMS));

	if (((2 == i) && compare1) || ((1 == i) && compare2)) {
		enum sms_mode mode;
		if (2 == i) {
			mode = gsm_check_sms_mode(gsm, gsm->at_last_recv);
		} else if (1 == i) {
			mode = gsm_check_sms_mode(gsm, gsm->at_pre_recv);		
		}
		
		if (SMS_TEXT == mode) {
		    memcpy(gsm->sms_recv_buffer, gsm->at_last_recv, gsm->at_last_recv_idx);
		
			res = (2 == i) ? gsm_text2sm_event2(gsm, gsm->at_last_recv, gsm->sms_recv_buffer) : \
			                 gsm_text2sm_event2(gsm, gsm->at_pre_recv, gsm->sms_recv_buffer);
			if (!res) {
				gsm->ev.e = GSM_EVENT_SMS_RECEIVED;
				gsm->at_last_recv[0] = '\0';
				return &gsm->ev;
			} else {
				return NULL;
			}
		} else if (SMS_PDU == mode) {
			if (((2 == i) && compare1) || ((1 == i) && compare2)) {
				char *temp_buffer = NULL;
				temp_buffer = strchr(gsm->at_last_recv,',');
				if(temp_buffer) {
					temp_buffer = strstr(temp_buffer,"\r\n");
					if(temp_buffer)
						temp_buffer += 2;
					else
 						temp_buffer = gsm->sms_recv_buffer;
				} else {
					temp_buffer=gsm->sms_recv_buffer;
				}

				int len = strlen(temp_buffer);
				if((temp_buffer[len-2]=='\r')||(temp_buffer[len-2]=='\n')) {
					temp_buffer[len-2]='\0';
				} else if((temp_buffer[len-1]=='\r')||(temp_buffer[len-1]=='\n')) {
					temp_buffer[len-1]='\0';
				}

				strncpy(gsm->sms_recv_buffer, temp_buffer, sizeof(gsm->sms_recv_buffer));
				if (!gsm_pdu2sm_event(gsm, gsm->sms_recv_buffer)) {
					gsm->ev.e = GSM_EVENT_SMS_RECEIVED;
					gsm->at_last_recv[0] = '\0';
					gsm->at_pre_recv[0] = '\0';
					gsm->sms_recv_buffer[0] = '\0';
					return &gsm->ev;
				} else {
					gsm->at_pre_recv[0] = '\0';
					gsm->sms_recv_buffer[0] = '\0';
					return NULL;
				}
			}
		}
	}

	switch(gsm->state) {
		case GSM_STATE_READY:
			if (gsm_compare(buf, AT(AT_OK))) {
				if (gsm_compare(gsm->at_last_sent, AT(AT_SEND_SMS_PDU_MODE))) {
	                gsm_send_at(gsm, AT(AT_UCS2)); /* text to pdu mode */
					gsm->sms_mod_flag = SMS_PDU;
				} else if (gsm_compare(gsm->at_last_sent, AT(AT_UCS2))) {
					gsm->sms_mod_flag = SMS_PDU;
				}
			}
			break;
		case GSM_STATE_SMS_SENDING:
			if (gsm_compare(buf, AT(AT_OK))) {
				if (gsm_compare(gsm->at_last_sent, AT(AT_SEND_SMS_PDU_MODE))) {
					gsm_send_at(gsm, AT(AT_UCS2));
				} else if (gsm_compare(gsm->at_last_sent, AT(AT_SEND_SMS_TEXT_MODE))) {
					gsm_send_at(gsm, AT(AT_GSM));
				} else if (gsm_compare(gsm->at_last_sent, AT(AT_UCS2))) {
					gsm->sms_mod_flag = SMS_PDU;
					memset(sms_buf, 0x0, sizeof(sms_buf));
					if (gsm->sms_info) {
						get_sms_len(gsm->switchtype, gsm->sms_info->pdu_info.len, sms_buf, sizeof(sms_buf));
					}
					gsm_send_at(gsm, sms_buf);
				} else if (gsm_compare(gsm->at_last_sent, AT(AT_GSM))) {
					gsm->sms_mod_flag = SMS_TEXT;
					memset(sms_buf, 0x0, sizeof(sms_buf));
					if (gsm->sms_info) {
						get_sms_des(gsm->switchtype, gsm->sms_info->txt_info.destination, sms_buf, sizeof(sms_buf));	
					}
					gsm_send_at(gsm, sms_buf);
				} else {
					//Freedom del 2012-06-05 15:50
					//gsm_error(gsm, DEBUGFMT "!%s!,last at tx:[%s]\n", DEBUGARGS, buf,gsm->at_last_sent);				
				}
			} else if (gsm_compare(buf, "> ") || gsm_compare(gsm->sanbuf, "> ")) {
				//Freedom Modify 2013-07-10 17:10
				//gsm_transmit(gsm, gsm->sms_sent_buffer);
				//memset(gsm->sms_sent_buffer, 0x0, sizeof(gsm->sms_sent_buffer));
				//snprintf(gsm->sms_sent_buffer, sizeof(gsm->sms_sent_buffer) - 1, "%c", 0x1A);

				//Freedom Modify 2013-11-13 09:49
				//Can't call snprintf like this.It's a big bug.
				//snprintf(gsm->sms_sent_buffer, sizeof(gsm->sms_sent_buffer) - 1, "%s%c", gsm->sms_sent_buffer, 0x1A);
				char ends[] = {0x1A,0};
				strncat(gsm->sms_sent_buffer,ends,sizeof(gsm->sms_sent_buffer)-strlen(gsm->sms_sent_buffer)-1);
				gsm_switch_state(gsm, GSM_STATE_SMS_SENT, gsm->sms_sent_buffer);
			} else if (gsm_compare(buf, AT(AT_CMS_ERROR)) || 
					   gsm_compare(buf, AT(AT_CME_ERROR))) {
				gsm_error(gsm, "Error sending SMS (%s) on span %d.\n", buf, gsm->span);
				if (gsm->sms_info) {
					free(gsm->sms_info);
					gsm->sms_info = NULL;
				}
				gsm_switch_state(gsm,GSM_STATE_READY,NULL);
	           } else {
//                gsm_error(gsm, DEBUGFMT "!%s!,last at tx:[%s]\n", DEBUGARGS, buf,gsm->at_last_sent);
            }
			break;
		case GSM_STATE_SMS_SENT:
			if (gsm_compare(buf, AT(AT_SEND_SMS_SUCCESS))) {
				//gsm_switch_state(gsm, GSM_STATE_SMS_SENT_END,NULL);
				if(gsm->sms_mod_flag == SMS_PDU) {
					gsm_switch_state(gsm, GSM_STATE_READY,NULL);
					gsm->ev.e = GSM_EVENT_SMS_SEND_OK;
					return &gsm->ev;
				} else {
					gsm_switch_state(gsm, GSM_STATE_SMS_SENT_END,AT(AT_SEND_SMS_PDU_MODE));
				}
			} else if (gsm_compare(buf, AT(AT_CMS_ERROR))) {
				gsm_switch_state(gsm, GSM_STATE_READY,NULL);
				gsm->ev.e = GSM_EVENT_SMS_SEND_FAILED;
				return &gsm->ev;
			}
			break;
		case GSM_STATE_SMS_SENT_END:
			if (gsm_compare(buf, AT(AT_OK))) {
				gsm_switch_state(gsm, GSM_STATE_READY,NULL);
				gsm->ev.e = GSM_EVENT_SMS_SEND_OK;
				return &gsm->ev;
			} else {
				gsm_switch_state(gsm, GSM_STATE_READY,NULL);
				gsm->ev.e = GSM_EVENT_SMS_SEND_FAILED;
				return &gsm->ev;
			}
			break;
		default:
			break;
	}

	return NULL;
}


static void module_check_coverage(struct gsm_modul *gsm, char *buf)
{
#ifdef SIMULATE_DIAL
	if(gsm->simulatedial) {
		return;
	}
#endif //SIMULATE_DIAL

	if ( gsm_compare(buf, AT(AT_CHECK_SIGNAL1)) || gsm_compare(buf, AT(AT_CHECK_SIGNAL2)) ) {
		module_get_coverage(gsm, buf);
	}
}


static gsm_event * module_check_network(struct gsm_modul *gsm, struct at_call *call, char *buf, int i)
{
#ifdef SIMULATE_DIAL
	if(gsm->simulatedial) {
		return NULL;
	}
#endif //SIMULATE_DIAL

	if (gsm_compare(buf, AT(AT_CREG))) {
		/*
			0 not registered, ME is not currently searching a new operator to register to
			1 registered, home network
			2 not registered, but ME is currently searching a new operator to register to
			3 registration denied
			4 unknown
			5 registered, roaming
		*/
		trim_CRLF(buf);
		if ( 0 == strcmp(buf, AT(AT_CREG0)) ) {
#if 1
			gsm->network = GSM_NET_UNREGISTERED;
			gsm->ev.gen.e = GSM_EVENT_DCHAN_DOWN;
			gsm_switch_state(gsm, GSM_STATE_NET_REQ, AT(AT_ASK_NET));
			gsm->start_time = sys_uptime();
			return &gsm->ev;
#endif
		} else if ( 0 == strcmp(buf, AT(AT_CREG1)) ) {
			gsm->network = GSM_NET_HOME;
			gsm->ev.gen.e = GSM_EVENT_DCHAN_UP;
			return &gsm->ev;

		} else if ( 0 == strcmp(buf, AT(AT_CREG2)) ) {
#if 1
			gsm->network = GSM_NET_SEARCHING;
			gsm->ev.gen.e = GSM_EVENT_DCHAN_DOWN;
			gsm_switch_state(gsm, GSM_STATE_NET_REQ, AT(AT_ASK_NET));
			gsm->start_time = sys_uptime();
			return &gsm->ev;
#endif
		} else if ( 0 == strcmp(buf, AT(AT_CREG3)) ) {
#if 1
			gsm->network = GSM_NET_DENIED;
			gsm->ev.gen.e = GSM_EVENT_DCHAN_DOWN;
			gsm_switch_state(gsm, GSM_STATE_NET_REQ, AT(AT_ASK_NET));
			gsm->start_time = sys_uptime();
			return &gsm->ev;
#endif
		} else if ( 0 == strcmp(buf, AT(AT_CREG4)) ) {
			gsm->network = GSM_NET_UNKNOWN;
			gsm->ev.gen.e = GSM_EVENT_DCHAN_DOWN;
			gsm_switch_state(gsm, GSM_STATE_NET_REQ, AT(AT_ASK_NET));
			gsm->start_time = sys_uptime();
			return &gsm->ev;
		} else if ( 0 == strcmp(buf, AT(AT_CREG5)) ) {
			gsm->network = GSM_NET_ROAMING;
			gsm->ev.gen.e = GSM_EVENT_DCHAN_UP;
			return &gsm->ev;
		}
	} else if (gsm_compare(buf, AT(AT_OK))) {
		if (((2 == i) && (gsm_compare(gsm->at_last_recv, AT(AT_CHECK_SIGNAL1))))
			  || ((1 == i) && (gsm_compare(gsm->at_pre_recv, AT(AT_CHECK_SIGNAL1))))) {
			if (gsm->coverage < 1) {
				gsm->ev.gen.e = GSM_EVENT_DCHAN_DOWN;
			} else {
				gsm->ev.gen.e = GSM_EVENT_DCHAN_UP;	
			}
			return &gsm->ev;
		}
	} 

	return NULL;
}

#ifdef GSM0710_MODE
int module_mux_end(struct gsm_modul *gsm, int restart_at_flow)
{
	if(restart_at_flow) {
		//Restart AT command flow again, Because after execute "AT+CMUX=0" or clear MUX mode, something need reinitialize.
		gsm->already_set_mux_mode = 1;
		return gsm_switch_state(gsm, GSM_STATE_UP, AT(AT_ATZ));
	} else {
		return gsm_switch_state(gsm, GSM_STATE_READY, AT(AT_NET_NAME));
	}
}
#endif //GSM0710_MODE

#ifdef AUTO_SIM_CHECK
int module_cfun_mini(struct gsm_modul *gsm)
{
	return gsm_switch_state(gsm, GSM_STATE_SIM_CFUN_MINI, AT(AT_SIM_CFUN_MINI));
}
#endif //AUTO_SIM_CHECK

//Freedom Add for if GSM module can't timely start. power restart modules. 2013-05-14 09:08
int gsm_start_progress_timeout(struct gsm_modul *gsm)
{
	//60 Second need.
	if( (sys_uptime()-gsm->start_time) > 100 ) {
		gsm->start_time = sys_uptime();
		return 1;
	}

	return 0;
}


//Freedom Add 2013-05-24 16:52 for call progress failed
///////////////////////////////////////////////////////////////////////////////////////////
static gsm_event *module_dial_failed(struct gsm_modul *gsm, struct at_call* call)
{
	gsm_switch_state(gsm,GSM_STATE_READY,NULL);
	UPDATE_OURCALLSTATE(gsm, call, AT_CALL_STATE_NULL);
	call->peercallstate = AT_CALL_STATE_NULL;
	call->alive = 0;
	call->sendhangupack = 0;
	gsm->ev.e = GSM_EVENT_HANGUP;
	gsm->ev.hangup.cause = GSM_CAUSE_CALL_REJECTED;
	gsm->ev.hangup.cref = call->cr;
	gsm->ev.hangup.call = call;
	gsm->ev.hangup.channel	= 1;
	gsm_hangup(gsm, call, GSM_CAUSE_CALL_REJECTED);
	return &gsm->ev;
}
///////////////////////////////////////////////////////////////////////////////////////////

static int ignore_ats(struct gsm_modul *gsm, char* buf)
{
	if(gsm_compare(buf, AT(AT_CHECK_SMS))) {
		return 1;
	}

	if(gsm_compare(buf, AT(AT_CHECK_SIGNAL2))) {
		return 1;
	}

	if(gsm_compare(buf, AT(AT_CHECK_SIGNAL2))) {
		return 1;
	}

	if(gsm_compare(buf, AT(AT_CHECK_USSD))) {
		return 1;
	}

	if(0 == strcmp(buf, AT(AT_CREG1))) {
		return 1;
	}

	if(0 == strcmp(buf, AT(AT_CREG2))) {
		return 1;
	}

	if(0 == strcmp(buf, AT(AT_CREG3))) {
		return 1;
	}

	if(0 == strcmp(buf, AT(AT_CREG4))) {
		return 1;
	}

	if(0 == strcmp(buf, AT(AT_CREG5))) {
		return 1;
	}

	if(gsm_compare(buf, "SM BL Ready")) {
		return 1;
	}

	if(gsm_compare(buf, "Call Ready")) {
		return 1;
	}

	if(gsm_compare(buf, "NORMAL POWER DOWN")) {
		return 1;
	}

	if(gsm_compare(buf,AT(AT_RING))) { //Ignore RING Freedom 2013-07-15 11:38
		return 1;
	}

	if(gsm_compare(buf,AT(AT_INCOMING_CALL))) { //Ignore +CLIP: Freedom 2013-07-15 11:38
		return 1;
	}

	return 0;
}

static void process_at_leak(struct gsm_modul *gsm, char * leak_at)
{
	strncpy(gsm->at_leak, leak_at, sizeof(gsm->at_leak));
}


static gsm_event* event_ring(struct gsm_modul *gsm, struct at_call *call)
{
	call->alive = 1;
	gsm->ev.gen.e = GSM_EVENT_MO_RINGING;
	gsm->ev.answer.progress = 0;
	gsm->ev.answer.channel = call->channelno;
	gsm->ev.answer.cref = call->cr;
	gsm->ev.answer.call = call;
	return &gsm->ev;
}

static gsm_event* event_connect(struct gsm_modul *gsm, struct at_call *call)
{
	gsm_switch_state(gsm,GSM_STATE_CALL_ACTIVE,NULL);
	call->alive = 1;
	gsm->ev.gen.e = GSM_EVENT_ANSWER;
	gsm->ev.answer.progress = 0;
	gsm->ev.answer.channel = call->channelno;
	gsm->ev.answer.cref = call->cr;
	gsm->ev.answer.call = call;
	return &gsm->ev;
}

static gsm_event* event_hangup(struct gsm_modul *gsm, struct at_call *call, int cause, int asknetname)
{
	if(asknetname) {
		gsm_switch_state(gsm, GSM_STATE_READY, AT(AT_NET_NAME));
	} else {
		gsm_switch_state(gsm, GSM_STATE_READY, NULL);
	}
	UPDATE_OURCALLSTATE(gsm, call, AT_CALL_STATE_NULL);
	call->peercallstate = AT_CALL_STATE_NULL;
	gsm->ev.e = GSM_EVENT_HANGUP;
	gsm->ev.hangup.channel = call->channelno;
	gsm->ev.hangup.cause = cause;
	gsm->ev.hangup.cref = call->cr;
	gsm->ev.hangup.call = call;
	call->alive = 0;
	call->sendhangupack = 0;
	//gsm_hangup(gsm, call, GSM_CAUSE_NORMAL_CLEARING);
	gsm_destroycall(gsm, call);
	return &gsm->ev;
}

gsm_event *module_receive(struct gsm_modul *gsm, char *data, int len)
{
	struct at_call *call;
	char buf[1024];
	char receivebuf[1024];
	char *p = NULL;
	gsm_event* res_event = NULL;
	int i;

	//Freedom Add 2012-02-07 15:24
	/////////////////////////////////////////////////////////
#if SIMCOM900D_NO_ANSWER_BUG
	static int first = 1;
	static struct timeval start_time,end_time;
#endif //SIMCOM900D_NO_ANSWER_BUG
	//////////////////////////////////////////////////////////
	
	/* get ast_call */
	call = gsm_getcall(gsm, gsm->cref, 0);
	if (!call) {
		gsm_error(gsm, "Unable to locate call %d\n", gsm->cref);
		return NULL;
	}

	strncpy(receivebuf, data, sizeof(receivebuf));
	p = receivebuf;
	i = 0;

	while (1) {	
		len = gsm_san(gsm, p, buf, len);
		if (0 == len || -1 == len) {
			return NULL;
		}
		
		//Freedom Modify 2011-09-14 16:45
		if (gsm->debug & GSM_DEBUG_AT_RECEIVED) {
			char tmp[1024];
			gsm_trim(gsm->at_last_sent, strlen(gsm->at_last_sent), tmp, sizeof(tmp));
			if (-3 == len) {
				gsm_message(gsm, "\t\t%d:<<< %d %s -- %s , NULL\n", gsm->span, i, tmp, buf);		
			}
			gsm_message(gsm, "\t\t%d:<<< %d %s -- %s , %d\n", gsm->span, i, tmp, buf, len);
		}

		strncpy(p, gsm->sanbuf, sizeof(receivebuf));
		len = (-3 == len) ? 0: gsm->sanidx;
		gsm->sanidx = 0;

#ifdef AUTO_SIM_CHECK
		if (gsm_compare(buf,AT(AT_SIM_INSERT))) {
			gsm->ev.e = GSM_EVENT_SIM_INSERTED;
			res_event = &gsm->ev;
			goto out;
		} else if (gsm_compare(buf,AT(AT_SIM_REMOVE))) {
			memset(gsm->imsi,0,sizeof(gsm->imsi));
			memset(gsm->sim_smsc,0,sizeof(gsm->sim_smsc));
			memset(gsm->net_name,0,sizeof(gsm->net_name));
			gsm->network = GSM_NET_UNREGISTERED;
			gsm_switch_state(gsm, GSM_STATE_SIM_NOT_INSERT, NULL);
			gsm->ev.e = GSM_EVENT_SIM_NOT_INSERTED;
			res_event = &gsm->ev;
			goto out;
		}
#endif //AUTO_SIM_CHECK


		switch (gsm->state) {
			case GSM_STATE_INIT:

				//Simulate Dial successful ... Freedom add 2013-05-28 11:18
				///////////////////////////////////////////////////////////
#ifdef SIMULATE_DIAL
				if(gsm->simulatedial) {
					gsm_switch_state(gsm, GSM_STATE_READY, NULL);
					gsm->network = GSM_NET_HOME;
					gsm->ev.gen.e = GSM_EVENT_DCHAN_UP;
					gsm->resetting = 0;
					gsm->retranstimer = 0;
					gsm->coverage = 28;
					gsm->ber = 0;
					strncpy(gsm->net_name,"OPENVOX",sizeof(gsm->net_name));
					return &gsm->ev;
				}
#endif //SIMULATE_DIAL
				///////////////////////////////////////////////////////////


				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_CHECK))) {
#ifdef GSM0710_MODE
						gsm->already_set_mux_mode = 0;
#endif //GSM0710_MODE
						gsm_switch_state(gsm, GSM_STATE_UP, AT(AT_ATZ));
						gsm->ev.gen.e = GSM_EVENT_DETECT_MODULE_OK;
						return &gsm->ev; 
					}
				} else if(gsm_compare(buf, AT(AT_CHECK))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_CHECK));	//Resend AT Again.
				}
				break;


			case GSM_STATE_UP:
			
				/* Drops the current call, and resets the values to default configuration. */
				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_ATZ))) {
						sleep(gsm->atz_timeout); /* To show the network status */
						gsm_switch_state(gsm, GSM_STATE_SEND_HANGUP, AT(AT_HANGUP));
					}
				} else if(gsm_compare(buf, AT(AT_ATZ))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_ATZ));	//Resend AT Again.
				}
				break;
			

			case GSM_STATE_SEND_HANGUP:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_HANGUP))) {
						gsm_switch_state(gsm, GSM_STATE_SET_ECHO, AT(AT_SET_ECHO_MODE));
						if (gsm->resetting) {
							/* Destory call and hangup all channels */
							UPDATE_OURCALLSTATE(gsm, call, AT_CALL_STATE_NULL);
							call->peercallstate = AT_CALL_STATE_NULL;
							gsm->ev.gen.e = GSM_EVENT_RESTART;
							return &gsm->ev;
						}
					}
				} else if(gsm_compare(buf, AT(AT_HANGUP))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_HANGUP));	//Resend AT Again.
				}
				break;


			case GSM_STATE_SET_ECHO:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_SET_ECHO_MODE))) {
						gsm_switch_state(gsm, GSM_STATE_SET_REPORT_ERROR, AT(AT_SET_CMEE));
					}
				} else if(gsm_compare(buf, AT(AT_SET_ECHO_MODE))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_SET_ECHO_MODE));	//Resend AT Again.
				}
				break;
	
						
			case GSM_STATE_SET_REPORT_ERROR:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_SET_CMEE))) {
						gsm_switch_state(gsm, GSM_STATE_MODEL_NAME_REQ, AT(AT_GET_CGMM));
					}
				} else if(gsm_compare(buf, AT(AT_SET_CMEE))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_SET_CMEE));	//Resend AT Again.
				}
				break;


			case GSM_STATE_MODEL_NAME_REQ:

				if(gsm_compare(buf, AT(AT_GET_CGMM))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else if(gsm_compare(buf, AT(AT_ERROR))) {	//AT error.
					gsm_send_at(gsm,AT(AT_GET_CGMM));	//Resend AT Again.
				} else if(gsm_compare(buf, AT(AT_OK))) {	//Receive OK.
					if(strlen(gsm->model_name) > 0) {
						gsm_switch_state(gsm, GSM_STATE_MANUFACTURER_REQ, AT(AT_GET_CGMI));
					} else {
						gsm_send_at(gsm,AT(AT_GET_CGMM));	//Resend AT Again.
					}
				} else {
					if (gsm_compare(gsm->at_last_sent, AT(AT_GET_CGMM))) {
						if(strlen(gsm->model_name) <= 0) {
							gsm_get_model_name(gsm, buf);
							gsm_set_module_id(&(gsm->switchtype),gsm->model_name);
						}
					}
				}
				break;


			case GSM_STATE_MANUFACTURER_REQ:

				if(gsm_compare(buf, AT(AT_GET_CGMI))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else if(gsm_compare(buf, AT(AT_ERROR))) {	//AT error.
					gsm_send_at(gsm,AT(AT_GET_CGMI));	//Resend AT Again.
				} else if(gsm_compare(buf, AT(AT_OK))) {	//Receive OK.
					if(strlen(gsm->manufacturer) > 0) {
						gsm_switch_state(gsm, GSM_STATE_VERSION_REQ, AT(AT_GET_VERSION));
					} else {
						gsm_send_at(gsm,AT(AT_GET_CGMI));	//Resend AT Again.
					}
				} else {
					if (gsm_compare(gsm->at_last_sent, AT(AT_GET_CGMI))) {
						gsm_get_manufacturer(gsm, buf);
					}
				}
				break;

			
			case GSM_STATE_VERSION_REQ:

				if(gsm_compare(buf, AT(AT_GET_VERSION))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else if(gsm_compare(buf, AT(AT_ERROR))) {	//AT error.
					gsm_send_at(gsm,AT(AT_GET_VERSION));	//Resend AT Again.
				} else if(gsm_compare(buf, AT(AT_OK))) {	//Receive OK.
					if(strlen(gsm->revision) > 0) {
						gsm_switch_state(gsm, GSM_STATE_IMEI_REQ, AT(AT_GET_IMEI));
					} else {
						gsm_send_at(gsm,AT(AT_GET_VERSION));	//Resend AT Again.
					}
				} else {
					if (gsm_compare(gsm->at_last_sent, AT(AT_GET_VERSION))) {
						gsm_get_model_version(gsm, buf);
					}
				}
				break;


			case GSM_STATE_IMEI_REQ:

				if(gsm_compare(buf, AT(AT_GET_IMEI))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else if(gsm_compare(buf, AT(AT_ERROR))) {	//AT error.
					gsm_send_at(gsm,AT(AT_GET_IMEI));	//Resend AT Again.
				} else if(gsm_compare(buf, AT(AT_OK))) {	//Receive OK.
					if(strlen(gsm->imei) > 0) {
#ifdef AUTO_SIM_CHECK
						if(strlen(AT(AT_SIM_DECTECT)) > 0) {
							gsm_switch_state(gsm, GSM_ENABLE_SIM_DETECT, AT(AT_SIM_DECTECT));
						} else {
							gsm_switch_state(gsm, GSM_STATE_SIM_READY_REQ, AT(AT_ASK_PIN));
						}
#else
						gsm_switch_state(gsm, GSM_STATE_SIM_READY_REQ, AT(AT_ASK_PIN));
#endif
					} else {
						gsm_send_at(gsm,AT(AT_GET_IMEI));	//Resend AT Again.
					}
				} else {
					if (gsm_compare(gsm->at_last_sent, AT(AT_GET_IMEI))) {
						gsm_get_imei(gsm, buf);
					}
				}
				break;


#ifdef AUTO_SIM_CHECK
			case GSM_ENABLE_SIM_DETECT:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_SIM_DECTECT))) {
						gsm_switch_state(gsm, GSM_STATE_SIM_READY_REQ, AT(AT_ASK_PIN));
					}
				} else if(gsm_compare(buf, AT(AT_SIM_DECTECT))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_SIM_DECTECT));	//Resend AT Again.
				}
				break;
#endif //AUTO_SIM_CHECK


			case GSM_STATE_SIM_READY_REQ:

				if (gsm_compare(buf, AT(AT_PIN_READY))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_ASK_PIN))) {
						gsm_switch_sim_state(gsm, GSM_STATE_SIM_READY, NULL);
						break;
					}
				} else if (gsm_compare(buf, AT(AT_PIN_SIM))) { /* waiting for SIM PIN */
					gsm_switch_sim_state(gsm, GSM_STATE_SIM_PIN_REQ, NULL);
					break;
				} else if (gsm_compare(buf, AT(AT_OK))) {
					switch(gsm->sim_state) {
						case GSM_STATE_SIM_READY:
							gsm_switch_state(gsm, GSM_STATE_IMSI_REQ, AT(AT_IMSI));
							break;
						case GSM_STATE_SIM_PIN_REQ:
							gsm_switch_state(gsm, GSM_STATE_SIM_PIN_REQ, NULL);
							gsm->ev.e = GSM_EVENT_PIN_REQUIRED;
							return &gsm->ev;
							break;
					}
				} else if (gsm_compare(buf, AT(AT_SIM_NO_INSERTED))) {
					//Freedom del 2013-07-10 10:35 Don't need alway ask GSM Module.
					//Wait for SIM insert.
					//gsm_send_at(gsm,AT(AT_ASK_PIN));	//Resend AT Again.
					//sleep(1);
					gsm->ev.e = GSM_EVENT_SIM_FAILED;
					return &gsm->ev;
				} else if(gsm_compare(buf, AT(AT_CME_ERROR))) {
					gsm_send_at(gsm,AT(AT_ASK_PIN));	//Resend AT Again.
					sleep(1);
					gsm->ev.e = GSM_EVENT_SIM_FAILED;
					return &gsm->ev;
				}
				break;


			case GSM_STATE_SIM_PIN_REQ:

				if (gsm_compare(buf, AT(AT_OK))) {
					sleep(1);
					gsm_switch_state(gsm, GSM_STATE_IMSI_REQ, AT(AT_IMSI));
				} else if (gsm_compare(buf, AT(AT_SIM_NO_INSERTED))) {
					sleep(1);
					gsm_switch_state(gsm, GSM_STATE_SIM_PIN_REQ, AT(AT_ASK_PIN));
					gsm->ev.e = GSM_EVENT_SIM_FAILED;
					return &gsm->ev;
				} else if(gsm_compare(buf, AT(AT_CME_ERROR))){
					gsm->ev.e = GSM_EVENT_PIN_ERROR;
					return &gsm->ev;
				}
				break;


			case GSM_STATE_IMSI_REQ:

				if(gsm_compare(buf, AT(AT_IMSI))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else if(gsm_compare(buf, AT(AT_ERROR))) {	//AT error.
					gsm_send_at(gsm,AT(AT_IMSI));	//Resend AT Again.
				} else if(gsm_compare(buf, AT(AT_OK))) {
					if(strlen(gsm->imsi) > 0) {
						if(AT(AT_MOC_ENABLED)) {
							gsm_switch_state(gsm, GSM_STATE_MOC_STATE_ENABLED, AT(AT_MOC_ENABLED));
						} else if(AT(AT_SET_SIDE_TONE)) {
							gsm_switch_state(gsm, GSM_STATE_SET_SIDE_TONE, AT(AT_SET_SIDE_TONE));
						} else {
							gsm_switch_state(gsm, GSM_STATE_CLIP_ENABLED, AT(AT_CLIP_ENABLED));
						}
					} else {
						gsm_send_at(gsm,AT(AT_IMSI));	//Resend AT Again.
					}
				} else {
					if (gsm_compare(gsm->at_last_sent, AT(AT_IMSI))) {
						gsm_get_imsi(gsm, buf);
					}
				}
				break;


			case GSM_STATE_MOC_STATE_ENABLED:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_MOC_ENABLED))) {
						if(AT(AT_SET_SIDE_TONE)) {
							gsm_switch_state(gsm, GSM_STATE_SET_SIDE_TONE, AT(AT_SET_SIDE_TONE));
						} else {
							gsm_switch_state(gsm, GSM_STATE_CLIP_ENABLED, AT(AT_CLIP_ENABLED));
						}
					}
				} else if(gsm_compare(buf, AT(AT_MOC_ENABLED))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_MOC_ENABLED));	//Resend AT Again.
				}
				break;


			case GSM_STATE_SET_SIDE_TONE:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_SET_SIDE_TONE))) {
						char send[1024];
						if(gsm->vol >= 0 && get_setvol_str(gsm->switchtype, gsm->vol, send, sizeof(send)) ) {
							gsm_switch_state(gsm, GSM_STATE_SET_SPEAK_VOL, send);
						} else if(gsm->mic >= 0 && get_setmic_str(gsm->switchtype, gsm->mic, send, sizeof(send)) ) {
							gsm_switch_state(gsm, GSM_STATE_SET_MIC_VOL, send);
						} else {
							gsm_switch_state(gsm, GSM_STATE_CLIP_ENABLED, AT(AT_CLIP_ENABLED));
						}
					}
				} else if(gsm_compare(buf, AT(AT_SET_SIDE_TONE))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_SET_SIDE_TONE));	//Resend AT Again.
				}
				break;


			case GSM_STATE_SET_SPEAK_VOL:

				if (gsm_compare(buf,AT(AT_OK))) {
					char send[1024];
					if(gsm->mic >= 0 && get_setmic_str(gsm->switchtype, gsm->mic, send, sizeof(send)) ) {
						gsm_switch_state(gsm, GSM_STATE_SET_MIC_VOL, send);
					} else {
						gsm_switch_state(gsm, GSM_STATE_CLIP_ENABLED, AT(AT_CLIP_ENABLED));
					}
				}
				break;


			case GSM_STATE_SET_MIC_VOL:

				if (gsm_compare(buf,AT(AT_OK))) {
					gsm_switch_state(gsm, GSM_STATE_CLIP_ENABLED, AT(AT_CLIP_ENABLED));
				}
				break;


			case GSM_STATE_CLIP_ENABLED:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_CLIP_ENABLED))) {
						char send[1024];
						if( strlen(gsm->band) > 0 && get_band_str(gsm->switchtype, gsm->band, send, sizeof(send)) ) {
						   gsm_switch_state(gsm, GSM_STATE_BAND_BINDING, send);
						} else {
							gsm_switch_state(gsm, GSM_STATE_DTR_WAKEUP_DISABLED, AT(AT_DTR_WAKEUP));
						}
					}
				} else if(gsm_compare(buf, AT(AT_CLIP_ENABLED))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_CLIP_ENABLED));	//Resend AT Again.
				}
				break;


			case GSM_STATE_BAND_BINDING:

				if (gsm_compare(buf, AT(AT_OK))) {
					gsm_switch_state(gsm, GSM_STATE_DTR_WAKEUP_DISABLED, AT(AT_DTR_WAKEUP));
				}
				break;


				//For SIMCOM5215J, Solve module send "DTR interrupt" AT error
			case GSM_STATE_DTR_WAKEUP_DISABLED:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_DTR_WAKEUP))) {
						gsm_switch_state(gsm, GSM_STATE_RSSI_ENABLED, AT(AT_RSSI_ENABLED));
					}
				} else if(gsm_compare(buf, AT(AT_DTR_WAKEUP))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_DTR_WAKEUP));	//Resend AT Again.
				}
				break;


			case GSM_STATE_RSSI_ENABLED:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_RSSI_ENABLED))) {
						gsm_switch_state(gsm, GSM_STATE_SMS_SET_CHARSET, AT(AT_SMS_SET_CHARSET));
					}
				} else if(gsm_compare(buf, AT(AT_RSSI_ENABLED))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_RSSI_ENABLED));	//Resend AT Again.
				}
				break;


			case GSM_STATE_SMS_SET_CHARSET:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_SMS_SET_CHARSET))) {
						if(AT(AT_MODE)) {
							gsm_switch_state(gsm, GSM_AT_MODE, AT(AT_MODE));
						} else {
							gsm_switch_state(gsm, GSM_STATE_SMS_SET_INDICATION, AT(AT_GSM));
						}
					}
				} else if(gsm_compare(buf, AT(AT_SMS_SET_CHARSET))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				}  else {
					gsm_send_at(gsm,AT(AT_SMS_SET_CHARSET));	//Resend AT Again.
				}
				break;


			case GSM_AT_MODE:
				
				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_MODE))) {
						gsm_switch_state(gsm, GSM_STATE_SMS_SET_INDICATION, AT(AT_GSM));
					}
				} else if(gsm_compare(buf, AT(AT_MODE))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_MODE));	//Resend AT Again.
				}
				break;


			case GSM_STATE_SMS_SET_INDICATION:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_GSM))) {
						gsm->sms_mod_flag = SMS_TEXT;
						gsm_switch_state(gsm, GSM_STATE_GET_SMSC_REQ, AT(AT_GET_SMSC));
					}
				} else if(gsm_compare(buf, AT(AT_GSM))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_GSM));	//Resend AT Again.
				}
				break;


			case GSM_STATE_GET_SMSC_REQ:
				
				if(gsm_compare(buf, AT(AT_GET_SMSC))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else if(gsm_compare(buf, AT(AT_ERROR))) {	//AT error.
					gsm_send_at(gsm,AT(AT_GET_SMSC));	//Resend AT Again.
				} else if(gsm_compare(buf, AT(AT_OK))) {	//Receive OK.
					if(strlen(gsm->sim_smsc) > 0) {
						gsm_switch_state(gsm, GSM_STATE_SET_NET_URC, AT(AT_SET_NET_URC));
					} else {
						gsm_send_at(gsm,AT(AT_GET_SMSC));	//Resend AT Again.
					}
				} else if(gsm_compare(buf,AT(AT_CHECK_SMSC))) {
					gsm_get_smsc(gsm, buf);
				}
				break;
			

			case GSM_STATE_SET_NET_URC:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_SET_NET_URC))) {
						gsm_switch_state(gsm, GSM_STATE_NET_REQ, AT(AT_ASK_NET));
					}
				} else if(gsm_compare(buf, AT(AT_SET_NET_URC))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_SET_NET_URC));	//Resend AT Again.
				}
				break;


			case GSM_STATE_NET_REQ:

				trim_CRLF(buf);
				if (gsm_compare(buf, AT(AT_OK))) {	//Receive OK
					if ((GSM_NET_HOME == gsm->network) || (GSM_NET_ROAMING == gsm->network)) {
						gsm_switch_state(gsm, GSM_STATE_NET_OK, AT(AT_NET_OK));
					} else {							
						//Freedom Add for if GSM module can't timely start. power restart modules. 2013-05-14 09:08
						if(gsm_start_progress_timeout(gsm)) {
							gsm_switch_state(gsm, GSM_STATE_POWER_RESTART, NULL);
							gsm->ev.gen.e = GSM_EVENT_POWER_RESTART;
							return &gsm->ev;
						} else {
							usleep (1000000);
							gsm_send_at(gsm,AT(AT_ASK_NET));	//Resend AT Again.
						}
					}
				} else if ( 0 == strcmp(buf, AT(AT_CREG10)) ) {					
					gsm->network = GSM_NET_UNREGISTERED;
				} else if ( 0 == strcmp(buf, AT(AT_CREG11)) ) {
					gsm->network = GSM_NET_HOME;
				} else if ( 0 == strcmp(buf, AT(AT_CREG12)) ) {
					gsm->network = GSM_NET_SEARCHING;
				} else if ( 0 == strcmp(buf, AT(AT_CREG13)) ) {
					gsm->network = GSM_NET_DENIED;
				} else if ( 0 == strcmp(buf, AT(AT_CREG14)) ) {
					gsm->network = GSM_NET_UNKNOWN;
				} else if ( 0 == strcmp(buf, AT(AT_CREG15)) ) {
					gsm->network = GSM_NET_ROAMING;
				} else if(gsm_compare(buf, AT(AT_ASK_NET))) {	//Ignore echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					if (gsm_compare(gsm->at_last_sent, AT(AT_ASK_NET))) {
						gsm->network = GSM_NET_UNREGISTERED;
						usleep (1000000);
						gsm_send_at(gsm,AT(AT_ASK_NET));	//Resend AT Again.
					}
				}
				break;


			case GSM_STATE_NET_OK:

				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_NET_OK))) {
						gsm_switch_state(gsm, GSM_STATE_NET_NAME_REQ, AT(AT_ASK_NET_NAME));
					}
				} else if(gsm_compare(buf, AT(AT_NET_OK))) { //Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_NET_OK));	//Resend AT Again.
				}
				break;



			case GSM_STATE_NET_NAME_REQ:

				if (gsm_compare(buf, AT(AT_CHECK_NET))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_ASK_NET_NAME))) {
						gsm_get_operator(gsm, buf);
					}
				} else if(gsm_compare(buf, AT(AT_ASK_NET_NAME))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else if(gsm_compare(buf, AT(AT_OK))) {	//Receive OK.

					if( strlen(gsm->net_name) > 0) {
						UPDATE_OURCALLSTATE(gsm, call, AT_CALL_STATE_NULL);
						call->peercallstate = AT_CALL_STATE_NULL;
#ifdef GSM0710_MODE
						if(gsm->already_set_mux_mode) {
							gsm_switch_state(gsm, GSM_STATE_READY, AT(AT_NET_NAME));
						} else {
							gsm_switch_state(gsm, GSM_INIT_MUX, AT(AT_CHECK));
						}
#else  //GSM0710_MODE
						gsm_switch_state(gsm, GSM_STATE_READY, AT(AT_NET_NAME));
#endif //GSM0710_MODE
						if (gsm->retranstimer) {
							gsm_schedule_del(gsm, gsm->retranstimer);
							gsm->retranstimer = 0;
						}

						if (gsm->resetting) {
							gsm->resetting = 0;
							gsm->ev.gen.e = GSM_EVENT_RESTART_ACK;
						} else {
							gsm->ev.gen.e = GSM_EVENT_DCHAN_UP;
						}
						return &gsm->ev;
					} else {
						gsm_send_at(gsm,AT(AT_ASK_NET_NAME));	//Resend AT Again.
					}
				} else {
					gsm_send_at(gsm,AT(AT_ASK_NET_NAME));	//Resend AT Again.
				}
				break;


#ifdef GSM0710_MODE
			case GSM_INIT_MUX:
				gsm->ev.gen.e = GSM_EVENT_INIT_MUX;
				return &gsm->ev;
				break;
#endif //GSM0710_MODE


			case GSM_STATE_READY:

				/* Request operators */
#ifdef GSM0710_MODE
				if(gsm->already_set_mux_mode)
					gsm->already_set_mux_mode = 0;
#endif //GSM0710_MODE

				if (gsm_compare(buf, AT(AT_INCOMING_CALL))) { /* Incoming call */

					if (!call->newcall) {
						break;
					}
					call->newcall = 0;

					char caller_id[64];
					
					get_cid(gsm->switchtype,buf,caller_id,sizeof(caller_id));

					/* Set caller number and caller name (if provided) */
					if (strlen(caller_id) > 0) {
						strncpy(gsm->ev.ring.callingnum, caller_id, sizeof(gsm->ev.ring.callingnum));
						strncpy(gsm->ev.ring.callingname, caller_id, sizeof(gsm->ev.ring.callingname));
					} else {
						strncpy(gsm->ev.ring.callingnum, "", sizeof(gsm->ev.ring.callingnum));
					}

					/* Return ring event */
					UPDATE_OURCALLSTATE(gsm, call, AT_CALL_STATE_CALL_PRESENT);
					call->peercallstate = AT_CALL_STATE_CALL_INITIATED;
					call->alive = 1;
					gsm_switch_state(gsm,GSM_STATE_RING,NULL);
					gsm->ev.e					= GSM_EVENT_RING;
					gsm->ev.ring.channel		= call->channelno; /* -1 : default */
					gsm->ev.ring.cref			= call->cr;
					gsm->ev.ring.call			= call;
					gsm->ev.ring.layer1			= GSM_LAYER_1_ALAW; /* a law */
					gsm->ev.ring.complete		= call->complete; 
					gsm->ev.ring.progress		= call->progress;
					gsm->ev.ring.progressmask	= call->progressmask;
					gsm->ev.ring.callednum[0]	= '\0';				/* called number should not be existed */ 
					return &gsm->ev;
				} else {
					if(gsm->send_at) {
						gsm_message(gsm, "%s", data);
						gsm->send_at = 0;
					}
				}
				break;


			case GSM_STATE_RING:

				if (gsm_compare(buf, AT(AT_RING))) {
					call->alive = 1;
					gsm_switch_state(gsm,GSM_STATE_RINGING,NULL);
					gsm->ev.e					= GSM_EVENT_RINGING;
					gsm->ev.ring.channel		= call->channelno;
					gsm->ev.ring.cref			= call->cr;
					gsm->ev.ring.progress		= call->progress;
					gsm->ev.ring.progressmask	= call->progressmask;
					return &gsm->ev;
				} else if(gsm_compare(buf, AT(AT_NO_CARRIER))) {
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				}
				break;


			//Freedom Add 2011-12-08 15:32 Check reject call
			////////////////////////////////////////////////////
			case GSM_STATE_RINGING:  //Wait answer or reject call.
				if( gsm_compare(buf, AT(AT_NO_CARRIER)) ||
					gsm_compare(buf, AT(AT_NO_ANSWER)) ) {
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				}
				break;
			////////////////////////////////////////////////////


			case GSM_STATE_PRE_ANSWER:

				/* Answer the remote calling */
				if (gsm_compare(buf, AT(AT_OK))) {
					if(gsm_compare(gsm->at_last_sent, AT(AT_ANSWER))) {
						UPDATE_OURCALLSTATE(gsm, call, AT_CALL_STATE_ACTIVE);
						call->peercallstate = AT_CALL_STATE_ACTIVE;
						call->alive = 1;
						gsm_switch_state(gsm,GSM_STATE_CALL_ACTIVE,NULL);
						gsm->ev.e				= GSM_EVENT_ANSWER;
						gsm->ev.answer.progress	= 0;
						gsm->ev.answer.channel	= call->channelno;
						gsm->ev.answer.cref		= call->cr;
						gsm->ev.answer.call		= call;
						return &gsm->ev;
					}
				} else if(gsm_compare(buf, AT(AT_NO_CARRIER))) {
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				} else if (gsm_compare(buf, AT(AT_ERROR))) {
					return module_dial_failed(gsm,call);
				} else if(gsm_compare(buf, AT(AT_ANSWER))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands 
				} else {
					gsm_send_at(gsm,AT(AT_ANSWER)); 	//Resend AT Again.
				}
				break;


			case GSM_STATE_CALL_ACTIVE:

				/* Remote end of active all. Waiting ...*/
				if (gsm_compare(buf, AT(AT_NO_CARRIER)) || 
					gsm_compare(buf, AT(AT_NO_ANSWER))) {
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				}

				break;


			case GSM_STATE_HANGUP_REQ:

#ifdef SIMULATE_DIAL
				if(gsm->simulatedial) {
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				}
#endif //SIMULATE_DIAL



				/* Hangup the active call */
				if (gsm_compare(buf, AT(AT_OK))) {
					if (gsm_compare(gsm->at_last_sent, AT(AT_HANGUP))) {

						//Freedom Add 2013-09-12 10:12
						if(gsm->pos->outbounded) {
							gsm->pos->outbounded = 0;
							if(!gsm->pos->answered) {
								gsm->pos->cancel_count++;
							}
							gsm->pos->answered = 0;
						}

						return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
					}
				} else if(gsm_compare(buf, AT(AT_HANGUP))) {	//Ignore AT echo.
				} else if(ignore_ats(gsm,buf)) {	//Ignore auto report AT commands
				} else {
					gsm_send_at(gsm,AT(AT_HANGUP)); 	//Resend AT Again.
				}
				break;


			case GSM_STATE_CALL_INIT:
				/* After dial */
				if (gsm_compare(buf, AT(AT_OK))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->outbound_count++;
					gsm->pos->outbounded = 1;
					gsm_switch_state(gsm, GSM_STATE_CALL_MADE, AT(AT_CALL_INIT));
				} else if (gsm_compare(buf, AT(AT_NO_CARRIER))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->nocarrier_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				} else if (gsm_compare(buf, AT(AT_NO_ANSWER))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->noanswer_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NO_ANSWER,0);
				} else if (gsm_compare(buf, AT(AT_NO_DIALTONE))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->nodialtone_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NETWORK_OUT_OF_ORDER,0);
				} else if (gsm_compare(buf, AT(AT_BUSY))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->busy_count++;
					return event_hangup(gsm,call,GSM_CAUSE_USER_BUSY,0);
				//Freedom Add 2013-05-24 16:52 for call progress failed
				///////////////////////////////////////////////////////////////////////////////////////////
				} else if (gsm_compare(buf, AT(AT_ERROR))) {
					return module_dial_failed(gsm,call);
				///////////////////////////////////////////////////////////////////////////////////////////
				} 
				break;


			case GSM_STATE_CALL_MADE:
				if (gsm_compare(buf, AT(AT_OK))) {
					//if (gsm_compare(gsm->at_last_sent, AT(AT_CALL_INIT))) {
						call->channelno = 1;
						gsm_switch_state(gsm, GSM_STATE_CALL_PROCEEDING, AT(AT_CALL_PROCEEDING));
						gsm->ev.e 					= GSM_EVENT_PROCEEDING;
						gsm->ev.proceeding.progress	= 8;
						gsm->ev.proceeding.channel	= call->channelno;
						gsm->ev.proceeding.cause	= 0;
						gsm->ev.proceeding.cref		= call->cr;
						gsm->ev.proceeding.call		= call;
						return &gsm->ev;
					//}
				} else if (gsm_compare(buf, AT(AT_NO_CARRIER))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->nocarrier_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				} else if (gsm_compare(buf, AT(AT_NO_ANSWER))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->noanswer_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NO_ANSWER,0);
				} else if (gsm_compare(buf, AT(AT_NO_DIALTONE))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->nodialtone_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NETWORK_OUT_OF_ORDER,0);
				} else if (gsm_compare(buf, AT(AT_BUSY))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->busy_count++;
					return event_hangup(gsm,call,GSM_CAUSE_USER_BUSY,0);
				//Freedom Add 2013-05-24 16:52 for call progress failed
				///////////////////////////////////////////////////////////////////////////////////////////
				} else if (gsm_compare(buf, AT(AT_ERROR))) {
					return module_dial_failed(gsm,call);
				///////////////////////////////////////////////////////////////////////////////////////////
				}
				break;


			case GSM_STATE_CALL_PROCEEDING:
				if (gsm_compare(buf, AT(AT_OK))) {
					//if (gsm_compare(gsm->at_last_sent, AT(AT_CALL_PROCEEDING))) {

						//Simulate Dial successful ... Freedom add 2013-05-28 11:18
						/////////////////////////////////////////////////////////////////////////
#ifdef SIMULATE_DIAL
						if(gsm->simulatedial) {
							call->alive = 1;
							gsm_switch_state(gsm,GSM_STATE_CALL_ACTIVE,NULL);
							gsm->ev.gen.e = GSM_EVENT_ANSWER;
							gsm->ev.answer.progress = 0;
							gsm->ev.answer.channel = call->channelno;
							gsm->ev.answer.cref = call->cr;
							gsm->ev.answer.call = call;
							return &gsm->ev;
						}
#endif //SIMULATE_DIAL
						/////////////////////////////////////////////////////////////////////////

						
						//Freedom Add 2012-02-07 15:24
						//////////////////////////////////////////////////////////////////////////
#if SIMCOM900D_NO_ANSWER_BUG
						first = 1;
#endif //SIMCOM900D_NO_ANSWER_BUG
						//////////////////////////////////////////////////////////////////////////
						gsm_switch_state(gsm,GSM_STATE_CALL_PROGRESS,NULL);
						gsm->ev.proceeding.e		= GSM_EVENT_PROGRESS;
						gsm->ev.proceeding.progress	= 8;
						gsm->ev.proceeding.channel	= call->channelno;
						gsm->ev.proceeding.cause	= 0;
						gsm->ev.proceeding.cref		= call->cr;
						gsm->ev.proceeding.call		= call;
						return &gsm->ev;
					//}
				} else if (gsm_compare(buf, AT(AT_NO_CARRIER))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->nocarrier_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				} else if (gsm_compare(buf, AT(AT_NO_ANSWER))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->noanswer_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NO_ANSWER,0);
				} else if (gsm_compare(buf, AT(AT_NO_DIALTONE))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->nodialtone_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NETWORK_OUT_OF_ORDER,0);
				} else if (gsm_compare(buf, AT(AT_BUSY))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->busy_count++;
					return event_hangup(gsm,call,GSM_CAUSE_USER_BUSY,0);
				//Freedom Add 2013-05-24 16:52 for call progress failed
				///////////////////////////////////////////////////////////////////////////////////////////
				} else if (gsm_compare(buf, AT(AT_ERROR))) {
					return module_dial_failed(gsm,call);
				///////////////////////////////////////////////////////////////////////////////////////////
				}
				break;


			case GSM_STATE_CALL_PROGRESS:
				//Freedom Add 2012-02-07 15:24
				//////////////////////////////////////////////////////////////////////////
#if SIMCOM900D_NO_ANSWER_BUG
				if(first) {
					first = 0;
					gettimeofday(&start_time,NULL);
				} else {
					gettimeofday(&end_time,NULL);
					if((end_time.tv_sec-start_time.tv_sec) >= 30 ) {
						first = 1;
						gsm_message(gsm,"Dial Timeout\n");
						gsm_switch_state(gsm,GSM_STATE_READY,NULL);
						UPDATE_OURCALLSTATE(gsm, call, AT_CALL_STATE_NULL);
						call->peercallstate = AT_CALL_STATE_NULL;
						gsm->ev.e = GSM_EVENT_HANGUP;
						gsm->ev.hangup.channel = call->channelno;
						gsm->ev.hangup.cause = GSM_CAUSE_NO_ANSWER;
						gsm->ev.hangup.cref = call->cr;
						gsm->ev.hangup.call = call;
						call->alive = 0;
						call->sendhangupack = 0;
						module_hangup(gsm);
						gsm_destroycall(gsm, call);
						return &gsm->ev;
					}
				}
#endif //SIMCOM900D_NO_ANSWER_BUG
				//////////////////////////////////////////////////////////////////////////
				
				if (gsm_compare(buf, AT(AT_RING))) {
					return event_ring(gsm,call);
				} else if (gsm_compare(buf, AT(AT_MO_CONNECTED))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->answer_count++;
					gsm->pos->answered = 1;
					return event_connect(gsm,call);
				} else if (gsm_compare(buf, AT(AT_NO_CARRIER))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->nocarrier_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NORMAL_CLEARING,0);
				} else if (gsm_compare(buf, AT(AT_NO_ANSWER))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->noanswer_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NO_ANSWER,0);
				} else if (gsm_compare(buf, AT(AT_NO_DIALTONE))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->nodialtone_count++;
					return event_hangup(gsm,call,GSM_CAUSE_NETWORK_OUT_OF_ORDER,0);
				} else if (gsm_compare(buf, AT(AT_BUSY))) {
					//Freedom Add 2013-09-12 10:12
					gsm->pos->busy_count++;
					return event_hangup(gsm,call,GSM_CAUSE_USER_BUSY,0);
				//Freedom Add 2013-05-24 16:52 for call progress failed
				///////////////////////////////////////////////////////////////////////////////////////////
				} else if (gsm_compare(buf, AT(AT_ERROR))) {
					return module_dial_failed(gsm,call);
				///////////////////////////////////////////////////////////////////////////////////////////
				}
				break;

#ifdef CONFIG_CHECK_PHONE
			case GSM_STATE_PHONE_CHECK: /*add by makes 2012-04-10 11:03 */
			{
				if(time(NULL)<gsm->check_timeout){
					if (gsm_compare(buf, AT(AT_RING))){
						if(gsm->auto_hangup_flag)
							gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
						gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
						gsm->ev.notify.info = PHONE_RING;
						gsm->phone_stat=PHONE_RING;
						return &gsm->ev;
					} else if(gsm_compare(buf, AT(AT_BUSY))){
						gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
						gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
						gsm->ev.notify.info = PHONE_BUSY;
						gsm->phone_stat=PHONE_BUSY;
						return &gsm->ev;
					} else if(gsm_compare(buf, AT(AT_MO_CONNECTED))){
						gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
						gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
						gsm->ev.notify.info = PHONE_CONNECT;
						gsm->phone_stat=PHONE_CONNECT;
						return &gsm->ev;
					} else if(gsm_compare(buf, AT(AT_NO_CARRIER))){
						gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
						gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
						gsm->ev.notify.info = PHONE_NOT_CARRIER;
						gsm->phone_stat=PHONE_NOT_CARRIER;
						return &gsm->ev;
					} else if(gsm_compare(buf, AT(AT_NO_ANSWER))){
						gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
						gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
						gsm->ev.notify.info = PHONE_NOT_ANSWER;
						gsm->phone_stat=PHONE_NOT_ANSWER;
						return &gsm->ev;
					} else if(gsm_compare(buf, AT(AT_NO_DIALTONE))){
						gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
						gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
						gsm->ev.notify.info = PHONE_NOT_DIALTONE;
						gsm->phone_stat=PHONE_NOT_DIALTONE;
						return &gsm->ev;
					}
				} else {
					if(gsm->auto_hangup_flag) {
						gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
						gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
						gsm->ev.notify.info = PHONE_TIMEOUT;
						gsm->phone_stat=PHONE_TIMEOUT;
						return &gsm->ev;
					} else {
						if(gsm_compare(buf, AT(AT_BUSY))){
							gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
							gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
							gsm->ev.notify.info = PHONE_BUSY;
							gsm->phone_stat=PHONE_BUSY;
							return &gsm->ev;
						} else if(gsm_compare(buf, AT(AT_MO_CONNECTED))){
							gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
							gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
							gsm->ev.notify.info = PHONE_CONNECT;
							gsm->phone_stat=PHONE_CONNECT;
							return &gsm->ev;
						} else if(gsm_compare(buf, AT(AT_NO_CARRIER))){
							gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
							gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
							gsm->ev.notify.info = PHONE_NOT_CARRIER;
							gsm->phone_stat=PHONE_NOT_CARRIER;
							return &gsm->ev;
						} else if(gsm_compare(buf, AT(AT_NO_ANSWER))){
							gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
							gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
							gsm->ev.notify.info = PHONE_NOT_ANSWER;
							gsm->phone_stat=PHONE_NOT_ANSWER;
							return &gsm->ev;
						} else if(gsm_compare(buf, AT(AT_NO_DIALTONE))){
							gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
							gsm->ev.gen.e = GSM_EVENT_CHECK_PHONE;
							gsm->ev.notify.info = PHONE_NOT_DIALTONE;
							gsm->phone_stat=PHONE_NOT_DIALTONE;
							return &gsm->ev;
						}
					}
				}
				break;
			}
#endif //CONFIG_CHECK_PHONE

			//Freedom Add for if GSM module can't timely start. power restart modules. 2013-05-14 09:08
			case GSM_STATE_POWER_RESTART:
				break;

			case GSM_STATE_SIM_NOT_INSERT:
				break;

			default:
				break;
		}

		i ++;
				
		module_check_coverage(gsm,buf);

		res_event = module_check_sms(gsm, buf, i);
		if (res_event) {
			goto out;
		}
		
		if (gsm->state == GSM_STATE_READY) {
			res_event = module_check_network(gsm, call ,buf, i);
			if (res_event) {
				goto out;
			}
		}

		res_event = module_check_ussd(gsm, buf, i);
		if (res_event) {
			goto out;
		}
	}


out:
	if(strlen(p) > 0) {
		process_at_leak(gsm, p);
	}

	return res_event;
}

#ifdef CONFIG_CHECK_PHONE
void module_hangup_phone(struct gsm_modul *gsm)
{
	gsm_switch_state(gsm, GSM_STATE_HANGUP_REQ, AT(AT_HANGUP));
}

int module_check_phone_stat(struct gsm_modul *gsm, const char *phone_number,int hangup_flag,unsigned int timeout)
{
	char buf[128];
	int time_out=0;
	memset(buf, 0x0, sizeof(buf));
	gsm->phone_stat = -1;
	gsm->auto_hangup_flag = hangup_flag;
	if(timeout<=0)
		time_out = DEFAULT_CHECK_TIMEOUT;
	else
		time_out = timeout;

	if(gsm->state != GSM_STATE_READY) {
		return -1;
	} else {
		gsm->check_timeout = time(NULL) + time_out;
		get_dial_str(gsm->switchtype, phone_number, buf, sizeof(buf));
		gsm_switch_state(gsm, GSM_STATE_PHONE_CHECK, buf);
	}
	return 0;
}
#endif

