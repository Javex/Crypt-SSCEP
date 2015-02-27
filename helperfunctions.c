#include "sscep.h"
#define SCEP_OPERATION_TRANS    8
#define SCEP_OPERATION_CERTREP  9
#define SCEP_PKISTATUS_PENDING_STR  "3"
#define SCEP_PKISTATUS_SUCCESS_STR  "0"
#define SCEP_PKISTATUS_FAILURE_STR  "2"
#define SCEP_FAILINFO_BADALG_ASSTR      "0"
#define SCEP_FAILINFO_BADMSGCHK_ASSTR       "1"
#define SCEP_FAILINFO_BADREQ_ASSTR      "2"
#define SCEP_FAILINFO_BADTIME_ASSTR     "3"
#define SCEP_FAILINFO_BADCERTID_ASSTR       "4"

X509 *str_read_cert(char *x509_str);
EVP_PKEY *str_read_key(char *key_str);
X509_REQ *str_read_req(char *req_str);
int pkcs7_wrap_certrep(struct scep *s, X509 *issued_cert);
void basic_config();
int pkcs7_unwrap_certrep(struct scep *s, char *certrep);

void
basic_config()
{
    pname = "sscep";
    init_scep();
    enc_alg = (EVP_CIPHER *)EVP_des_cbc();
    sig_alg = (EVP_MD *)EVP_md5();
    fp_alg = (EVP_MD *)EVP_md5();
}

char *
transid(char *certrep)
{
    struct scep     scep_t;
    basic_config();
    operation_flag = SCEP_OPERATION_TRANS;
    pkcs7_unwrap_certrep(&scep_t, certrep);
    return scep_t.transaction_id;
}

const char *
get_pkcsreq(char *key_str, char *ca_str, char *req_str)
{
    struct scep     scep_t;
    const char *reply;
    basic_config();
	
    if (v_flag)
    {
        fprintf(stdout, "%s: SCEP_OPERATION_ENROLL\n", pname);
    }
    operation_flag = SCEP_OPERATION_ENROLL;
    cacert = str_read_cert(ca_str);

    //PEM_write_X509(stdout, cacert);
    rsa = str_read_key(key_str);
    request = str_read_req(req_str);
    //PEM_write_X509_REQ(stdout, request);

    if (v_flag)
        fprintf(stdout, "%s: new transaction\n", pname);

    new_transaction(&scep_t);

    new_selfsigned(&scep_t);

    if (v_flag)
        fprintf(stdout, "%s: set "
                "certificate\n", pname);

    /*I assume that I have to add the following stuff*/
    scep_t.ias_getcertinit->issuer = X509_get_issuer_name(cacert);
    scep_t.ias_getcert->issuer = scep_t.ias_getcertinit->issuer;
    scep_t.ias_getcrl->issuer = scep_t.ias_getcertinit->issuer;
    scep_t.ias_getcrl->serial = X509_get_serialNumber(cacert);
    scep_t.request_type = SCEP_REQUEST_PKCSREQ;

    pkcs7_wrap(&scep_t);

    BIO *memorybio = BIO_new(BIO_s_mem());

    PEM_write_bio_PKCS7(memorybio, scep_t.request_p7);
    /*looks like I have to terminate the buffer manually*/
    BIO_write(memorybio, "", 1);
    //PEM_write_PKCS7(stdout, scep_t.request_p7);
    BIO_get_mem_data(memorybio, &reply);
    BIO_set_close(memorybio, BIO_NOCLOSE);
    PKCS7_free(scep_t.request_p7);
    BIO_free(memorybio);
    return reply;
}

char *
create_certrep(char *cakey_str, char *ca_str, char *pkcsreq_str, char *status_str, char *reason_str, char *signed_cert_str)
{
    struct scep     scep_t;
    X509    *signed_cert;
    char     *reply;

    basic_config();

    if (v_flag)
        fprintf(stdout,
                "%s: SCEP_OPERATION_CERTREP\n", pname);

    operation_flag = SCEP_OPERATION_CERTREP;

    rsa = str_read_key(cakey_str);
    cacert = str_read_cert(ca_str);
    signed_cert = str_read_cert(signed_cert_str);
    pkcs7_unwrap_certrep(&scep_t, pkcsreq_str);

    if (!strncmp(status_str, "PENDING", 7))
    {
        scep_t.pki_status = SCEP_PKISTATUS_PENDING;
        scep_t.pki_status_str = SCEP_PKISTATUS_PENDING_STR;
    }
    else if (!strncmp(status_str, "SUCCESS", 7))
    {
        //insert additional information here
        scep_t.pki_status = SCEP_PKISTATUS_SUCCESS;
        scep_t.pki_status_str = SCEP_PKISTATUS_SUCCESS_STR;
        if (!signed_cert_str)
        {
            fprintf(stderr, "%s: Status SUCESS requires the issued certificate\n", pname);
            exit (SCEP_PKISTATUS_ERROR);
        }
    }
    else if (!strncmp(status_str, "FAILURE", 7))
    {
        //insert additional information here
        scep_t.pki_status = SCEP_PKISTATUS_FAILURE;
        scep_t.pki_status_str = SCEP_PKISTATUS_FAILURE_STR;
        if (!reason_str)
        {
            fprintf(stderr, "%s: Status FAILURE requires failInfo\n", pname);
            exit (SCEP_PKISTATUS_ERROR);
        }
        if (!strncmp(reason_str, "badAlg", 6))
            scep_t.fail_info_str = SCEP_FAILINFO_BADALG_ASSTR;
        else if (!strncmp(reason_str, "badMessageCheck", 16))
            scep_t.fail_info_str = SCEP_FAILINFO_BADMSGCHK_ASSTR;
        else if (!strncmp(reason_str, "badRequest", 10))
            scep_t.fail_info_str = SCEP_FAILINFO_BADREQ_ASSTR;
        else if (!strncmp(reason_str, "badTime", 7))
            scep_t.fail_info_str = SCEP_FAILINFO_BADTIME_ASSTR;
        else if (!strncmp(reason_str, "badCertId", 9))
            scep_t.fail_info_str = SCEP_FAILINFO_BADCERTID_ASSTR;
        else
        {
            printf("FailInfo not supported (badAlg|badMessageCheck|badRequest|badRequest|badTime|badCertId)\n");
            exit (SCEP_PKISTATUS_ERROR);
        }
    }
    else
    {
        fprintf(stderr, "%s: status can be PENDING, SUCCESS, or FAILURE\n", pname);
        exit (SCEP_PKISTATUS_ERROR);
    }


    /* Use existing certificate */
    scep_t.signercert = cacert;
    scep_t.signerkey = rsa;

    pkcs7_wrap_certrep(&scep_t, signed_cert);
    BIO *memorybio = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS7(memorybio, scep_t.reply_p7);
    BIO_write(memorybio, "", 1);
    free(scep_t.reply_recipient_nonce);

    BIO_get_mem_data(memorybio, &reply);
    BIO_set_close(memorybio, BIO_NOCLOSE);
    BIO_free(memorybio);
    return reply;
}

X509 *
str_read_cert(char *x509_str)
{
    BIO             *memorybio;
    X509            *cert;
    /*read string into memory bio*/
    memorybio = BIO_new(BIO_s_mem());
    BIO_write(memorybio, x509_str, strlen(x509_str));

    /* Read a cert from bio */
    if (!( cert = PEM_read_bio_X509(memorybio, NULL, 0, NULL)))
    {
        fprintf(stderr, "%s: error while reading cert\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_FILE);
    }
    BIO_set_close(memorybio, BIO_NOCLOSE);
    BIO_free(memorybio);
    return cert;
}

X509_REQ *
str_read_req(char *req_str)
{
    BIO             *memorybio;
    X509_REQ        *req;
    /*read string into memory bio*/
    memorybio = BIO_new(BIO_s_mem());
    BIO_write(memorybio, req_str, strlen(req_str));
    /* Read a req from bio */
    if (!( req = PEM_read_bio_X509_REQ(memorybio, NULL, NULL, NULL)))
    {
        fprintf(stderr, "%s: error while reading request\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_FILE);
    }
    BIO_set_close(memorybio, BIO_NOCLOSE);
    BIO_free(memorybio);
    return req;
}

EVP_PKEY *
str_read_key(char *key_str)
{
    BIO             *memorybio;
    EVP_PKEY        *key;

    /*read string into memory bio*/
    memorybio = BIO_new(BIO_s_mem());
    BIO_write(memorybio, key_str, strlen(key_str));

    /* Read a key from bio */
    if (!(key = PEM_read_bio_PrivateKey(memorybio, NULL, NULL, NULL)))
    {
        fprintf(stderr, "%s: error while reading key\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_FILE);
    }
    BIO_set_close(memorybio, BIO_NOCLOSE);
    BIO_free(memorybio);
    return key;
}

int pkcs7_unwrap_certrep(struct scep *s, char *certrep)
{
    BIO             *memorybio;
    BIO             *outbio;
    BIO             *pkcs7bio;
    int             i, bytes, used;
    STACK_OF(PKCS7_SIGNER_INFO) *sk;
    PKCS7               *p7enc, *p7;
    PKCS7_SIGNER_INFO       *si;
    STACK_OF(X509_ATTRIBUTE)    *attribs;
    char                *p;
    unsigned char           buffer[1024];
    X509                *recipientcert;
    EVP_PKEY            *recipientkey;

    memorybio = BIO_new(BIO_s_mem());
    BIO_write(memorybio, certrep, strlen(certrep));

    if(!(p7 = PEM_read_bio_PKCS7(memorybio, NULL, NULL, NULL))) {
		fprintf(stderr, "%s: error while reading certrep\n", pname);
	}
	BIO_set_close(memorybio, BIO_NOCLOSE);
    BIO_free(memorybio);
    s->reply_p7 = p7;

    /* Read in data */
    if (v_flag)
        printf("%s: reading outer PKCS#7\n", pname);

    if (d_flag)
    {
        printf("%s: printing PEM fomatted PKCS#7\n", pname);
        PEM_write_PKCS7(stdout, s->reply_p7);
    }

    /* Make sure this is a signed PKCS#7 */
    if (!PKCS7_type_is_signed(s->reply_p7))
    {
        fprintf(stderr, "%s: PKCS#7 is not signed!\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Create BIO for content data */
    pkcs7bio = PKCS7_dataInit(s->reply_p7, NULL);
    if (pkcs7bio == NULL)
    {
        fprintf(stderr, "%s: cannot get PKCS#7 data\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Copy enveloped data from PKCS#7 */
    outbio = BIO_new(BIO_s_mem());
    used = 0;
    for (;;)
    {
        bytes = BIO_read(pkcs7bio, buffer, sizeof(buffer));
        used += bytes;
        if (bytes <= 0) break;
        BIO_write(outbio, buffer, bytes);
    }
    
    if (v_flag)
        printf("%s: PKCS#7 contains %d bytes of enveloped data\n",
               pname, used);

    /* Get signer */
    sk = PKCS7_get_signer_info(s->reply_p7);
    if (sk == NULL)
    {
        fprintf(stderr, "%s: cannot get signer info!\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Verify signature */
    if (v_flag)
        printf("%s: verifying signature\n", pname);

    si = sk_PKCS7_SIGNER_INFO_value(sk, 0);

    /*I assume there will be just one cert*/
    STACK_OF(X509) * pkcs7certs = s->reply_p7->d.sign->cert;
    X509 *pkcs7cert = sk_X509_value(pkcs7certs, 0);

    if (PKCS7_signatureVerify(pkcs7bio, s->reply_p7, si, pkcs7cert) <= 0)
    {
        fprintf(stderr, "%s: error verifying signature\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    if (v_flag)
        printf("%s: signature ok\n", pname);

    /* Get signed attributes */
    if (v_flag)
        printf("%s: finding signed attributes\n", pname);
    attribs = PKCS7_get_signed_attributes(si);
    if (attribs == NULL)
    {
        fprintf(stderr, "%s: no attributes found\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Transaction id */
    if ((get_signed_attribute(attribs, nid_transId,
                              V_ASN1_PRINTABLESTRING, &p)) == 1)
    {
        fprintf(stderr, "%s: cannot find transId\n", pname);
        exit (SCEP_PKISTATUS_P7);
    }
    /*we can just set our transaction id*/
    s->transaction_id = p;
    if (operation_flag == SCEP_OPERATION_TRANS)
    {
        /*we are ready*/
        return (0);
    }

    if (v_flag)
        printf("%s: reply transaction id: %s\n", pname, p);

    if ((i = get_signed_attribute(attribs, nid_messageType,
                                  V_ASN1_PRINTABLESTRING, &p)) == 1)
    {
        fprintf(stderr, "%s: cannot find messageType\n", pname);
        exit (SCEP_PKISTATUS_P7);
    }
    /*certrep or pkcsreq in this case*/
    if (atoi(p) != 3 && atoi(p) != 19)
    {
        fprintf(stderr, "%s: wrong message type in reply\n", pname);
        exit (SCEP_PKISTATUS_P7);
    }
    if (v_flag)
        printf("%s: reply message type is good\n", pname);

    /* Sender and recipient nonces: */
    if ((i = get_signed_attribute(attribs, nid_senderNonce,
                                  V_ASN1_OCTET_STRING, &p)) == 1)
    {
        if (v_flag)
            fprintf(stderr, "%s: cannot find senderNonce\n", pname);
        /* Some implementations don't put in on reply */
        /* XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        exit (SCEP_PKISTATUS_P7); */
    }
    s->reply_sender_nonce = p;
    if (v_flag)
    {
        printf("%s: senderNonce in reply: ", pname);
        for (i = 0; i < 16; i++)
        {
            printf("%02X", s->reply_sender_nonce[i]);
        }
        printf("\n");
    }
    /*I think enough information is extracted*/
    return (0);
}

int pkcs7_wrap_certrep(struct scep *s, X509 *issued_cert)
{
    BIO         *pkcs7bio = NULL;
    BIO         *memorybio = NULL;
    unsigned char       *buffer = NULL;
    STACK_OF(X509)      *recipients;
    PKCS7           *p7enc;
    PKCS7_SIGNER_INFO   *si;
    STACK_OF(X509_ATTRIBUTE) *attributes;
    X509            *signercert = NULL;
    EVP_PKEY        *signerkey = NULL;

    /* Create a new sender nonce for all messages
     * XXXXXXXXXXXXXX should it be per transaction? */
    /*this is now actually the recipient nonce*/
    s->recipient_nonce_len = 16;
    s->sender_nonce_len = 16;
    s->reply_recipient_nonce = (unsigned char *)malloc(s->sender_nonce_len);
    RAND_bytes(s->reply_recipient_nonce, s->recipient_nonce_len);

    /* Prepare data payload */
    s->reply_type = SCEP_REPLY_CERTREP;
    s->reply_type_str = SCEP_REPLY_CERTREP_STR;

    /*
     * Set printable message type
     * We set this later as an autheticated attribute
     * "messageType".
     */

    /* Signer cert */
    signercert = s->signercert;
    signerkey = s->signerkey;


    /* Create outer PKCS#7  */
    if (v_flag)
        printf("%s: creating outer PKCS#7\n", pname);
    s->reply_p7 = PKCS7_new();
    if (s->reply_p7 == NULL)
    {
        fprintf(stderr, "%s: failed creating PKCS#7 for signing\n",
                pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    if (!PKCS7_set_type(s->reply_p7, NID_pkcs7_signed))
    {
        fprintf(stderr, "%s: failed setting PKCS#7 type\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Add signer certificate and signature */
    PKCS7_add_certificate(s->reply_p7, signercert);
    if ((si = PKCS7_add_signature(s->reply_p7,
                                  signercert, signerkey, sig_alg)) == NULL)
    {
        fprintf(stderr, "%s: error adding PKCS#7 signature\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    if (v_flag)
        printf("%s: signature added successfully\n", pname);

    /* Set signed attributes */
    if (v_flag)
        printf("%s: adding signed attributes\n", pname);
    attributes = sk_X509_ATTRIBUTE_new_null();
    add_attribute_string(attributes, nid_transId, s->transaction_id);
    add_attribute_string(attributes, nid_pkiStatus, s->pki_status_str);
    add_attribute_string(attributes, nid_messageType, s->reply_type_str);
    add_attribute_octet(attributes, nid_senderNonce, s->reply_sender_nonce,
                        s->sender_nonce_len);
    add_attribute_octet(attributes, nid_recipientNonce, s->reply_recipient_nonce,
                        s->recipient_nonce_len);
    if (s->pki_status == SCEP_PKISTATUS_FAILURE)
    {
        add_attribute_string(attributes, nid_failInfo, s->fail_info_str);
    }
    PKCS7_set_signed_attributes(si, attributes);

    /* Add contentType */
    if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
                                    V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data)))
    {
        fprintf(stderr, "%s: error adding NID_pkcs9_contentType\n",
                pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Create new content */
    if (!PKCS7_content_new(s->reply_p7, NID_pkcs7_data))
    {
        fprintf(stderr, "%s: failed setting PKCS#7 content type\n",
                pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Write data  */
    pkcs7bio = PKCS7_dataInit(s->reply_p7, NULL);
    if (pkcs7bio == NULL)
    {
        fprintf(stderr, "%s: error opening bio for writing PKCS#7 "
                "data\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    /*now experiment with the content*/
    if (s->pki_status == SCEP_PKISTATUS_SUCCESS)
    {

        PKCS7 *degen;
        degen = PKCS7_new();
        if (degen == NULL)
        {
            fprintf(stderr, "%s: failed creating degen PKCS#7 for signing\n",
                    pname);
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }

        if (!PKCS7_set_type(degen, NID_pkcs7_signed))
        {
            fprintf(stderr, "%s: failed setting PKCS#7 type\n", pname);
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }

        if (!PKCS7_content_new(degen, NID_pkcs7_data))
        {
            fprintf(stderr, "%s: failed setting PKCS#7 content type\n", pname);
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }

        PKCS7_add_certificate(degen, issued_cert);
        BIO *degenbio = BIO_new ( BIO_s_mem());
        int len = i2d_PKCS7_bio( degenbio, degen );

        /* Create encryption certificate stack */
        if ((recipients = sk_X509_new(NULL)) == NULL)
        {
            fprintf(stderr, "%s: error creating "
                    "certificate stack\n", pname);
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }

        if (sk_X509_push(recipients, signercert) <= 0)   /*right cert??*/
        {
            fprintf(stderr, "%s: error adding recipient encryption "
                    "certificate\n", pname);
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }

        if (d_flag)
        {
            fprintf(stdout, "%s: printing degenerated PKCS#7 cert only structure\n", pname);
            PEM_write_PKCS7(stdout, degen);

        }

        /* Encrypt */
        if (!(p7enc = PKCS7_encrypt(recipients, degenbio,
                                    enc_alg, PKCS7_BINARY)))
        {
            fprintf(stderr, "%s: request payload encrypt failed\n", pname);
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }
        BIO_set_close(degenbio, BIO_NOCLOSE);
        BIO_free(degenbio);

        if (v_flag)
            printf("%s: successfully encrypted payload\n", pname);


        /* Write encrypted data */
        memorybio = BIO_new(BIO_s_mem());
        if (i2d_PKCS7_bio(memorybio, p7enc) <= 0)
        {
            fprintf(stderr, "%s: error writing encrypted data\n", pname);
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }
        BIO_set_flags(memorybio, BIO_FLAGS_MEM_RDONLY);
        len = BIO_get_mem_data(memorybio, &buffer);
        if (v_flag)
            printf("%s: envelope size: %d bytes\n", pname, len);
        if (d_flag)
        {
            printf("%s: printing PEM fomatted encrypted degenerated PKCS#7\n", pname);
            PEM_write_PKCS7(stdout, p7enc);
        }
        BIO_free(memorybio);

        if (len != BIO_write(pkcs7bio, buffer, len))
        {
            fprintf(stderr, "%s: error writing PKCS#7 data\n", pname);
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }
    }

    if (v_flag)
        printf("%s: PKCS#7 data written successfully\n", pname);

    /* Finalize PKCS#7  */
    if (!PKCS7_dataFinal(s->reply_p7, pkcs7bio))
    {
        fprintf(stderr, "%s: error finalizing outer PKCS#7\n", pname);
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    if (d_flag)
    {
        printf("%s: printing PEM fomatted PKCS#7\n", pname);
        PEM_write_PKCS7(stdout, s->reply_p7);
    }
    
    return (0);
}
