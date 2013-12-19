#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/types.h>

#include "openflow/openflow.h"

// sigh.. why is this not defined in some standard place
#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif
#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

#define CONFIG_GUEST_SUFFIX	".guest"
#define CONFIG_SWITCH_SUFFIX	".switch"

#define malloc_and_check(x) _realloc_and_check(NULL,(x),__FILE__,__LINE__);
#define realloc_and_check(ptr,x) _realloc_and_check((ptr),(x),__FILE__,__LINE__);
void * _realloc_and_check(void * ptr,size_t bytes, char * file, int lineno);


enum flowvisor_log_levels{
	FVISOR_MIN,
	FVISOR_PKT,
	FVISOR_DEBUG,
	FVISOR_LOG,
	FVISOR_ERR,
	FVISOR_MAX,
};

#ifndef FVISORLOG_DEFAULT_THRESH
#define FVISORLOG_DEFAULT_THRESH	FVISOR_LOG
#endif
extern FILE * FVisorLogfile;

#ifndef BUFLEN
#define BUFLEN 4096
#endif


#define flowvisor_pkt(format...) _flowvisor_log_level(__FILE__,__LINE__,0,FVisorLogfile,FVISOR_PKT,format)
#define flowvisor_debug(format...) _flowvisor_log_level(__FILE__,__LINE__,0,FVisorLogfile,FVISOR_DEBUG,format)
#define flowvisor_log(format...) _flowvisor_log_level(__FILE__,__LINE__,0,FVisorLogfile,FVISOR_LOG,format)
#define flowvisor_err(format...) do { \
			_flowvisor_log_level(__FILE__,__LINE__,0,stderr,FVISOR_ERR,format); \
			_flowvisor_log_level(__FILE__,__LINE__,0,FVisorLogfile,FVISOR_ERR,format); \
			} while(0)
#define flowvisor_exit(exit,format...) _flowvisor_log_level(__FILE__,__LINE__,exit,stderr,FVISOR_ERR,format)
#define flowvisor_log_level(exit,level,format...) _flowvisor_log_level(__FILE__,__LINE__,exit,level,format)
int _flowvisor_log_level(char * file, size_t line, int exitval, FILE * out, int loglevel, char * format, ... );
int flowvisor_log_set_thresh(int loglevel);
int flowvisor_log_get_thresh(void);


struct ofpbuf * make_error_msg(uint32_t xid, int error_type, int error_code);
char * make_error_msg_str(uint32_t xid, int error_type, int error_code, int * msg_len);

char * config_next_line(FILE * f, int *lineno, char * line, int maxlen);
// assumes token buffer is at least as big as strlen(line);
int config_next_token(char * token,int * index, const char * line);
int config_is_whitespace(char c);
int config_is_comment_or_blank(char *line);

char * ofp_type_to_string(int ofp_type);



int reverse_strcmp(const char * s1, const char * s2);

char * name_from_file(char * filename);

char * ofpbuf_msg_summary(struct ofpbuf * msg);
char * ofp_msg_summary(struct ofp_header * ofph);
int flowvisor_set_logfile(FILE * new);
int flowvisor_set_print_preamble(int print);

#endif
