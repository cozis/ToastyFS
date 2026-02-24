#ifndef HTTP_PARSE_INCLUDED
#define HTTP_PARSE_INCLUDED

#include "basic.h"

#define CHTTP_MAX_HEADERS 32

typedef struct {
	unsigned int data;
} CHTTP_IPv4;

typedef struct {
	unsigned short data[8];
} CHTTP_IPv6;

typedef enum {
	CHTTP_HOST_MODE_VOID = 0,
	CHTTP_HOST_MODE_NAME,
	CHTTP_HOST_MODE_IPV4,
	CHTTP_HOST_MODE_IPV6,
} CHTTP_HostMode;

typedef struct {
	CHTTP_HostMode mode;
	string text;
	union {
		string name;
		CHTTP_IPv4 ipv4;
		CHTTP_IPv6 ipv6;
	};
} CHTTP_Host;

typedef struct {
	string userinfo;
	CHTTP_Host host;
	int        port;
} CHTTP_Authority;

// ZII
typedef struct {
	string scheme;
	CHTTP_Authority authority;
	string path;
	string query;
	string fragment;
} CHTTP_URL;

typedef enum {
	CHTTP_METHOD_GET,
	CHTTP_METHOD_HEAD,
	CHTTP_METHOD_POST,
	CHTTP_METHOD_PUT,
	CHTTP_METHOD_DELETE,
	CHTTP_METHOD_CONNECT,
	CHTTP_METHOD_OPTIONS,
	CHTTP_METHOD_TRACE,
	CHTTP_METHOD_PATCH,
} CHTTP_Method;

typedef struct {
	string name;
	string value;
} CHTTP_Header;

typedef struct {
    bool        secure;
	CHTTP_Method method;
	CHTTP_URL    url;
	int         minor;
	int         num_headers;
	CHTTP_Header headers[CHTTP_MAX_HEADERS];
	string body;
} CHTTP_Request;

typedef struct {
    void*       context;
	int         minor;
	int         status;
	string reason;
	int         num_headers;
	CHTTP_Header headers[CHTTP_MAX_HEADERS];
	string body;
} CHTTP_Response;

int chttp_parse_ipv4(char *src, int len, CHTTP_IPv4     *ipv4);
int chttp_parse_ipv6(char *src, int len, CHTTP_IPv6     *ipv6);
int chttp_parse_url(char *src, int len, CHTTP_URL      *url);
int chttp_parse_request(char *src, int len, CHTTP_Request  *req);
int chttp_parse_response(char *src, int len, CHTTP_Response *res);

int chttp_find_header(CHTTP_Header *headers, int num_headers, string name);

string chttp_get_cookie(CHTTP_Request *req, string name);
string chttp_get_param(string body, string str, char *mem, int cap);
int    chttp_get_param_i(string body, string str);

// Checks whether the request was meant for the host with the given
// domain an port. If port is -1, the default value of 80 is assumed.
bool chttp_match_host(CHTTP_Request *req, string domain, int port);

// Date and cookie types for Set-Cookie header parsing
typedef enum {
    CHTTP_WEEKDAY_MON,
    CHTTP_WEEKDAY_TUE,
    CHTTP_WEEKDAY_WED,
    CHTTP_WEEKDAY_THU,
    CHTTP_WEEKDAY_FRI,
    CHTTP_WEEKDAY_SAT,
    CHTTP_WEEKDAY_SUN,
} CHTTP_WeekDay;

typedef enum {
    CHTTP_MONTH_JAN,
    CHTTP_MONTH_FEB,
    CHTTP_MONTH_MAR,
    CHTTP_MONTH_APR,
    CHTTP_MONTH_MAY,
    CHTTP_MONTH_JUN,
    CHTTP_MONTH_JUL,
    CHTTP_MONTH_AUG,
    CHTTP_MONTH_SEP,
    CHTTP_MONTH_OCT,
    CHTTP_MONTH_NOV,
    CHTTP_MONTH_DEC,
} CHTTP_Month;

typedef struct {
    CHTTP_WeekDay week_day;
    int          day;
    CHTTP_Month   month;
    int          year;
    int          hour;
    int          minute;
    int          second;
} CHTTP_Date;

typedef struct {
    string name;
    string value;

    bool secure;
    bool chttp_only;

    bool have_date;
    CHTTP_Date date;

    bool have_max_age;
    uint32_t max_age;

    bool have_domain;
    string domain;

    bool have_path;
    string path;
} CHTTP_SetCookie;

// Parses a Set-Cookie header value
// Returns 0 on success, -1 on error
int chttp_parse_set_cookie(string str, CHTTP_SetCookie *out);

#endif // HTTP_PARSE_INCLUDED