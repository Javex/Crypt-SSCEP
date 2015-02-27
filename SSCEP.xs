#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "sscep.h"

MODULE = Crypt::SSCEP		PACKAGE = Crypt::SSCEP		

char *
print_transid(certrep)
char * certrep
CODE:
	RETVAL = transid(certrep);
OUTPUT:
	RETVAL

const char *
pkcsreq(key_str, ca_str, req_str)
char * key_str
char * ca_str
char * req_str
CODE:
	RETVAL = get_pkcsreq(key_str, ca_str, req_str);
OUTPUT:
	RETVAL
	
	
char * 
certrep(cakey_str, ca_str, pkcsreq_str, status_str, reason_str, signed_cert_str)
char * cakey_str
char * ca_str
char * pkcsreq_str
char * status_str
char * reason_str
char * signed_cert_str
CODE:
	RETVAL = create_certrep(cakey_str, ca_str, pkcsreq_str, status_str, reason_str, signed_cert_str);
OUTPUT:
	RETVAL
