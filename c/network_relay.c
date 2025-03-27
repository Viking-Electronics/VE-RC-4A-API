/*
Copyright 2025 Viking Electronics

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define API_VERSION "1.0.0"

// function prototypes, structs, and enums that the user should utilize for using this library
#include "network_relay.h"

#include <stdlib.h>
#include <errno.h>      //for checking errors following standard lib calls that could set errno
#include <sys/select.h> //for select, checking if data is available to read from sockets
#include <sys/socket.h> //for sockets and networking
#include <arpa/inet.h>  //inet_addr
#include <netinet/ip_icmp.h>
#include <string.h>
#include <time.h>
#include <unistd.h> //getpid
// for MD5_DIGEST_LENGTH MACRO
#include <openssl/md5.h>
// for hashing algorithms used by digest auth
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

#include <stdio.h>
#include <stdbool.h>

// relay id, state or timed string, and state enum or seconds

#define C_RELAY_COMMAND_STRUCTURE "/protect/relays.cgi?relay=%d&%s=%s"
#define C_RELAY_COMMAND_STATE "state"
#define C_RELAY_COMMAND_TIME "time"
#define C_RELAY_COMMAND_STATE_ON "on"
#define C_RELAY_COMMAND_STATE_OFF "off"
#define C_RELAY_COMMAND_STATE_TOGGLE "toggle"
#define C_RELAY_MAX_COMMAND_URI_LENGTH (sizeof(C_RELAY_COMMAND_STRUCTURE) + sizeof(C_RELAY_COMMAND_STATE) + sizeof(C_RELAY_COMMAND_STATE_OFF))

#define VIKING_MAC_ADDR_PREFIX "18-E8-0F"
#define MAC_ADDRESS_LENGTH 17U
#define VIKING_RC4A_MODEL_STR "Viking RC-4A"
#define VIKING_DEFAULT_USERNAME "admin"
#define VIKING_DEFAULT_PASSWORD "viking"
#define BROADCAST_ADDR "255.255.255.255"
#define BROADCAST_PORT 30303
#define BROADCAST_MESSAGE "Discovery: Who is out there?"
#define MAX_MSG_SIZE 512
#define BUFFER_SIZE 1024
#define MD5_HEX_LENGTH 32
#define MAX_USERNAME_LENGTH 64
#define MAX_PASSWORD_LENGTH 64
#define C_NR_MAX_ATTEMPTS 3

#define MILLI_SEC 1000

#define HTTP_PREFIX "HTTP"
#define HTTP_UNAUTHORIZED "Unauthorized"
#define HTTP_WWW_AUTH "WWW-Authenticate"
#define HTTP_AUTH_REALM "realm"
#define HTTP_AUTH_NONCE "nonce"
#define HTTP_BASIC_AUTH "Basic"
#define HTTP_DIGEST_AUTH "Digest"

#define HTTP_RC_BLANK_COMMAND "/protect/relays.cgi?"

/*server, then address*/
#define HTTP_GET_HEADER \
"GET %s HTTP/1.1\r\n\
Host: http://%s:%d\r\n\
User-Agent: librc-4a-api/%s\r\n\
\r\n"

/**
 * @brief uri, ip_addr, int port, username, realm, nonce, uri, response, version
 *
 */
#define HTTP_GET_AUTHENTICATED_DIGEST "GET %s HTTP/1.1\r\nHost: http://%s:%d\r\n\
Authorization: Digest username=\"%s\", realm=\"%s\", \
nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n\
User-Agent: librc-4a-api/%s\r\n\
Accept: */*\r\n\r\n"

/**
 * @brief uri, ip_addr, int port, auth, version
 *
 */
#define HTTP_GET_AUTHENTICATED_BASIC "GET %s HTTP/1.1\r\n \
Host: http://%s:%d\r\n\
Authorization: Basic %s\r\n\
User-Agent: librc-4a-api/%s\r\n\
Accept: */*\r\n\r\n"



const char TERMINATOR_SEQUENCE[] = {0x0d, 0x0A};

typedef enum e_network_relay_msg_order
{
    NR_E_PORT = 0,
    NR_E_NAME,
    NR_E_MAC_ADDR,
    NR_E_MODEL,
    NR_E_PRODUCT_END
} network_relay_msg_order_t;

typedef enum e_network_relay_command_states
{
    NRCS_CONNECT = 0,
    NRCS_TEST_CONNECTION,
    NRCS_TRY_BASIC,
    NRCS_TRY_DIGEST,
    NRCS_COMMAND_COMPLETE,
    NRCS_FAILURE
} e_network_relay_command_states_t;

typedef enum e_message_type
{
    NR_INVALID_RESPONSE,
    NR_NOT_AUTHORIZED,
    NR_ACTION_SUCCESSFUL
} e_message_type_t;

typedef struct
{
    unsigned char isBasicAuth : 1; // just true or false
    char realm[32 + 1];            // rc-4a has a max hostname length of 16 bytes (extra characters for string termination and buffer space)
    char nonce[32 + 1];            // rc-4a uses a 24 byte nonce for http auth (extra characters for string termination and buffer space)
    e_message_type_t message_type;
} packet_info_t;

static int generate_basic_auth(char *username, char *password, char **auth_buffer);

static int network_relay_command_format(network_relay_command_args_t command, char *buffer, int buffer_length)
{
    int error = 0;
    char on_time_seconds_buffer[4] = {0};

    if (NULL == buffer)
    {
        error = EINVAL;
    }
    else if (buffer_length < (C_RELAY_MAX_COMMAND_URI_LENGTH))
    {
        error = EINVAL;
    }
    else if ((command.index < 1) || command.index > 4)
    {
        error = ENXIO;
    }

    if (!error)
    {
        switch (command.command)
        {
        case RELAY_SET:
            snprintf(buffer, buffer_length, C_RELAY_COMMAND_STRUCTURE, command.index, C_RELAY_COMMAND_STATE, C_RELAY_COMMAND_STATE_ON);
            break;
        case RELAY_RESET:
            snprintf(buffer, buffer_length, C_RELAY_COMMAND_STRUCTURE, command.index, C_RELAY_COMMAND_STATE, C_RELAY_COMMAND_STATE_OFF);
            break;
        case RELAY_TOGGLE:
            snprintf(buffer, buffer_length, C_RELAY_COMMAND_STRUCTURE, command.index, C_RELAY_COMMAND_STATE, C_RELAY_COMMAND_STATE_TOGGLE);
            break;
        case RELAY_TIMED:
            snprintf(on_time_seconds_buffer, sizeof(on_time_seconds_buffer), "%d", command.duration_s);
            snprintf(buffer, buffer_length, C_RELAY_COMMAND_STRUCTURE, command.index, C_RELAY_COMMAND_TIME, on_time_seconds_buffer);
            break;
        default:
            error = EINVAL;
            break;
        }
    }

    return error;
}

static int
parse_response_packet(char *buffer, size_t buffer_length, packet_info_t *packet_info)
{
    int error = 0;
    int response_length = 0;
    int http_response_code = 0;
    char parsing_buffer[BUFFER_SIZE] = {0};
    char *ptr = NULL;
    char *save_ptr = NULL;

    if (NULL == buffer)
    {
        error = EINVAL;
    }
    else if (buffer_length < 1)
    {
        error = EINVAL;
    }

    /*Should always start with HTTP*/
    if (!error && strncmp(parsing_buffer, HTTP_PREFIX, sizeof(HTTP_PREFIX) - 1) == 0)
    {
        error = ENXIO;
    }

    if (!error)
    {
        strncpy(parsing_buffer, buffer, buffer_length);
        response_length = strnlen(parsing_buffer, sizeof(parsing_buffer));

        ptr = strtok_r(parsing_buffer, " ", &save_ptr);

        if (NULL != ptr)
        {
            ptr = strtok_r(NULL, " ", &save_ptr);
            if (NULL != ptr)
            {
                http_response_code = atoi(ptr);
                ptr = strtok_r(NULL, "\r\n", &save_ptr);
            }
            else
            {
                error = ENXIO;
            }
        }
        else
        {
            error = ENXIO;
        }
    }

    if (!error)
    {
        switch (http_response_code)
        {
        case 200:
            packet_info->message_type = NR_ACTION_SUCCESSFUL;
            return E_NR_SUCCESS;
        case 401:
        case 403:
            packet_info->message_type = NR_NOT_AUTHORIZED;
            break;

        default:
            packet_info->message_type = NR_INVALID_RESPONSE;
            break;
        }
    }

    if (!error)
    {
        // Move ptr to the http auth part of header
        for (ptr = strtok_r(NULL, " ", &save_ptr);
             (NULL != ptr) && (strncmp(ptr, HTTP_WWW_AUTH, sizeof(HTTP_WWW_AUTH) - 1) != 0) && (ptr <= (parsing_buffer + response_length));
             ptr++);

        if (strncmp(ptr, HTTP_WWW_AUTH, sizeof(HTTP_WWW_AUTH) - 1) == 0)
        {
            ptr += sizeof(HTTP_WWW_AUTH) + 1; // advance ptr to after the auth text to before the auth type
            if (strncmp(ptr, HTTP_BASIC_AUTH, sizeof(HTTP_BASIC_AUTH) - 1) == 0)
            {
                // basic auth
                packet_info->isBasicAuth = 1;
                ptr += sizeof(HTTP_BASIC_AUTH);
            }
            else if (strncmp(ptr, HTTP_DIGEST_AUTH, sizeof(HTTP_DIGEST_AUTH) - 1) == 0)
            {
                // digest auth
                packet_info->isBasicAuth = 0;
                ptr += sizeof(HTTP_DIGEST_AUTH);
            }
            else
            {
                // error, no auth found
                error = E_NR_NETWORK_FAILURE;
            }
            char *save_ptr = NULL;
            char *tok = strtok_r(ptr, " ", &save_ptr);
            while ((NULL != tok) && (tok < (parsing_buffer + BUFFER_SIZE)))
            {
                if (strncmp(tok, HTTP_AUTH_REALM, sizeof(HTTP_AUTH_REALM) - 1) == 0)
                {
                    // we are at the token for the realm
                    char *end_of_realm = NULL;
                    strtok_r(tok, "\"", &end_of_realm);
                    char *realm = strtok_r(NULL, "\"", &end_of_realm);
                    if ((NULL != realm) && (strnlen(realm, sizeof(packet_info->realm) - 1))) // realm has a max length of 16 bytes
                    {
                        strncpy(packet_info->realm, realm, strnlen(realm, sizeof(packet_info->realm) - 1));
                    }
                }
                else if (strncmp(tok, HTTP_AUTH_NONCE, sizeof(HTTP_AUTH_NONCE) - 1) == 0)
                {
                    // we are at the token for the nonce
                    char *end_of_nonce = NULL;
                    strtok_r(tok, "\"", &end_of_nonce);
                    char *nonce = strtok_r(NULL, "\"", &end_of_nonce);
                    if ((NULL != nonce) && (strnlen(nonce, sizeof(packet_info->nonce) - 1))) // realm has a max length of 16 bytes
                    {
                        strncpy(packet_info->nonce, nonce, strnlen(nonce, sizeof(packet_info->nonce) - 1));
                    }
                }

                tok = strtok_r(NULL, " ", &save_ptr);
            }
        }
        else
        {
            error = EFAULT;
        }
    }
    else
    {
        // error, not a HTTP responce
        error = E_NR_NETWORK_FAILURE;
    }

    return error;
}

/**
 * @brief Convert from the binary md5 hash, to an ascii formatted md5 hash
 *
 * @param Bin 16 byte md5 hash array
 * @param Hex 33 byte hex storage location (hex hash + null terminator)
 */
static void
cvtBinHex(char bin[], char hex[])
{
    unsigned short i;
    unsigned char j;

    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        j = (bin[i] >> 4) & 0xf;
        if (j <= 9)
            hex[i * 2] = (j + '0');
        else
            hex[i * 2] = (j + 'a' - 10);
        j = bin[i] & 0xf;
        if (j <= 9)
            hex[i * 2 + 1] = (j + '0');
        else
            hex[i * 2 + 1] = (j + 'a' - 10);
    };
    hex[MD5_HEX_LENGTH] = '\0';
};

static int
get_digest(const char *algorithm, const void *memory, size_t memory_length, char *result_buffer)
{
    int error = 0;
    char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    EVP_MD_CTX *md5_instance = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname(algorithm);

    if ((NULL == md5_instance))
    {
        error = ENOMEM;
    }
    else if (NULL == md)
    {
        error = EOPNOTSUPP;
    }
    else
    {
        if (EVP_DigestInit(md5_instance, md)) // initalizes the hashing alg to use the insecure, obsolete md5
        {
            // successful init
            if (EVP_DigestUpdate(md5_instance, memory, memory_length)) // hash updated with bytes from hashing_buffer
            {
                // successful digest update
                if (EVP_DigestFinal(md5_instance, (unsigned char *)md_value, &md_len)) // md5_instance is reset after moving result into md_value
                {
                    // successfully converted and finish digest
                    cvtBinHex(md_value, result_buffer);
                }
                else
                {
                    // failed conversion to the final digest
                    error = EFAULT;
                }
            }
            else
            {
                // failed digest update
                error = EFAULT;
            }
        }
        else
        {
            // failed init
            error = EFAULT;
        }
    }

    if (NULL != md5_instance)
    {
        EVP_MD_CTX_destroy(md5_instance);
    }

    return error;
}


static char* base64_encode(char *input, size_t length) {
    // Create a BIO object for Base64 encoding
    BIO* bmem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, bmem);

    // Disable line breaks in the output
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Write data to BIO for encoding
    BIO_write(b64, (const void*)input, length);
    BIO_flush(b64);

    // Determine the encoded data length
    size_t output_length = BIO_get_mem_data(bmem, NULL);

    // Allocate memory for the encoded string
    char* encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL) {
        BIO_free_all(b64);
        return NULL;  // Memory allocation failed
    }

    // Copy the encoded data to the output string
    BIO_read(bmem, encoded_data, output_length);
    encoded_data[output_length] = '\0';

    // Clean up
    BIO_free_all(b64);

    return encoded_data;
}

static int generate_basic_auth(char *username, char *password, char **auth_buffer)
{
    int error = 0;
    int tmp_buffer_sz = 0;
    char *p_auth_buffer = NULL;

    if (NULL == username)
    {
        error = EINVAL;
    }
    else if (NULL == password)
    {
        error = EINVAL;
    }
    else if (NULL == auth_buffer)
    {
        error = EINVAL;
    }

    if (!error)
    {
        tmp_buffer_sz = strnlen(username, MAX_USERNAME_LENGTH) + strnlen(password, MAX_PASSWORD_LENGTH) + 2; //room for username:password\0
        if (NULL == (p_auth_buffer = malloc(tmp_buffer_sz)))
        {
            //allocation error
            error = ENOMEM;
        }
        else
        {
            if (snprintf(p_auth_buffer, tmp_buffer_sz, "%s:%s", username, password) >= tmp_buffer_sz)
            {
                //output was truncated, error condition
                error = E2BIG;
            }
            else
            {
                *auth_buffer = base64_encode(p_auth_buffer, strnlen(p_auth_buffer, tmp_buffer_sz));
                if (NULL == *auth_buffer)
                {
                    error = ENOMEM;
                }
            }
        } 
    }

    if (p_auth_buffer)
    {
        free(p_auth_buffer);
    }

    return error;
}

network_relay_command_errors_t generate_digest(const char *hashing_alg, char *username, char *password, char *realm, char *nonce, char *uri, char *digest_hash)
{
    int error = 0;
    if (NULL == username)
    {
        error = E_NR_INVALID_LOGIN;
    }
    else if (NULL == password)
    {
        error = E_NR_INVALID_LOGIN;
    }
    else if (NULL == realm)
    {
        error = E_NR_NETWORK_FAILURE;
    }
    else if (NULL == nonce)
    {
        error = E_NR_NETWORK_FAILURE;
    }
    else if (NULL == uri)
    {
        error = E_NR_INVALID_COMMAND;
    }
    else if (NULL == digest_hash)
    {
        error = E_NR_NETWORK_FAILURE;
    }
    else if (!strlen(username))
    {
        error = E_NR_INVALID_LOGIN;
    }
    else if (!strlen(password))
    {
        error = E_NR_INVALID_LOGIN;
    }
    else if (!strlen(realm))
    {
        error = E_NR_NETWORK_FAILURE;
    }
    else if (!strlen(nonce))
    {
        error = E_NR_NETWORK_FAILURE;
    }
    else if (!strlen(uri))
    {
        error = E_NR_NETWORK_FAILURE;
    }

    if (!error)
    {

        char hashing_buffer[BUFFER_SIZE] = {0};
        char HA_1_ASCII[MD5_HEX_LENGTH + 1];
        char HA_2_ASCII[MD5_HEX_LENGTH + 1];

        /*
        Generate HA1
        HA1 = MD5(username:realm:password)
        */
        int length = snprintf(hashing_buffer, BUFFER_SIZE, "%s:%s:%s", username, realm, password);
        if (length < BUFFER_SIZE)
        {
            error = get_digest(hashing_alg, hashing_buffer, length, HA_1_ASCII);
            if (error)
            {
                error = E_NR_DIGEST_GENERATION_FAILURE;
            }
        }
        else
        {
            // encoding error
            error = E_NR_ENCODING_FAILURE;
        }

        /*
        Generate HA2
        HA2 = MD5(method:digestURI)
        */
        if (!error)
        {
            length = snprintf(hashing_buffer, BUFFER_SIZE, "%s:%s", "GET", uri);
            if (length < BUFFER_SIZE)
            {
                error = get_digest(hashing_alg, hashing_buffer, length, HA_2_ASCII);
                if (error)
                {
                    error = E_NR_DIGEST_GENERATION_FAILURE;
                }
            }
            else
            {
                // encoding error
                error = E_NR_ENCODING_FAILURE;
            }
        }

        /*
        Generate response
        response = MD5(HA1:nonce:HA2)
        */
        if (!error)
        {
            length = snprintf(hashing_buffer, BUFFER_SIZE, "%s:%s:%s", HA_1_ASCII, nonce, HA_2_ASCII);
            if (length < BUFFER_SIZE)
            {
                error = get_digest(hashing_alg, hashing_buffer, length, digest_hash);
                if (error)
                {
                    error = E_NR_DIGEST_GENERATION_FAILURE;
                }
            }
            else
            {
                // encoding error
                error = E_NR_ENCODING_FAILURE;
            }
        }
    }

    return error;
}

static int
socket_connect(char *ip, in_port_t port)
{
    int error = 0;
    struct sockaddr_in addr;
    int sock_fd = -1;

    if (NULL == ip)
    {
        error = EINVAL;
    }
    else
    {
        if (!error)
        {
            addr.sin_port = htons(port);
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = inet_addr(ip);

            sock_fd = socket(PF_INET, SOCK_STREAM, 0);
            if (-1 == sock_fd)
            {
                perror("socket open failed");
                error = errno;
            }
            else
            {

                if (-1 == connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)))
                {
                    perror("connect failed");
                    error = errno;
                }
            }
        }
    }
    if (error)
    {
        return -1;
    }

    return sock_fd;
}

static network_relay_command_errors_t network_relay_check(network_relay_t *relay)
{
    int error = 0;

    if (NULL == relay)
    {
        error = E_NR_INVALID_RELAY_DETAILS;
    }
    else
    {
        if (NULL == relay->http_port)
        {
            error = E_NR_INVALID_RELAY_DETAILS;
        }
        else if (NULL == relay->ip_addr)
        {
            error = E_NR_INVALID_RELAY_DETAILS;
        }
        else if (NULL == relay->mac_addr)
        {
            error = E_NR_INVALID_RELAY_DETAILS;
        }
        else if (NULL == relay->model)
        {
            error = E_NR_INVALID_RELAY_DETAILS;
        }
        else if (NULL == relay->name)
        {
            error = E_NR_INVALID_RELAY_DETAILS;
        }
    }
    return error;
}

/**
 * @brief single socket connection write then read, will place result in the buffer, then shutdown the fd
 *
 * @param socket_fd
 * @param sock_xfer_buffer
 * @param timeout
 * @return int
 */
network_relay_command_errors_t socket_xfer(int socket_fd, char *sock_xfer_buffer, size_t buffer_length, struct timeval timeout)
{
    network_relay_command_errors_t error = 0;
    if (!error)
    {
        int len = strnlen(sock_xfer_buffer, buffer_length);

        if (len > 0)
        {
            int read_complete = 0;
            int length_written = send(socket_fd, sock_xfer_buffer, len, 0);
            if (len == length_written)
            {
                // successful write
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(socket_fd, &read_fds);
                int fd_status = select(socket_fd + 1, &read_fds, NULL, NULL, &timeout);
                FD_CLR(socket_fd, &read_fds);
                switch (fd_status)
                {
                case 1:
                    len = recv(socket_fd, sock_xfer_buffer, buffer_length, 0);
                    if (len > 0)
                    {
                        read_complete = 1;
                        // read success
                        sock_xfer_buffer[len] = 0; // terminate end of received message
                    }
                    else if (len < 0)
                    {
                        error = E_NR_NETWORK_FAILURE;
                    }
                    else
                    {
                        if (read_complete)
                        {

                            shutdown(socket_fd, SHUT_RDWR);
                        }
                        else
                        {
                            error = E_NR_NETWORK_FAILURE;
                        }
                    }
                    break;

                case -1:
                    if (ETIMEDOUT == errno)
                    {
                        error = E_NR_NETWORK_TIMEOUT;
                    }
                    else
                    {
                        error = E_NR_NETWORK_FAILURE;
                    }
                    break;
                case 0:
                    error = E_NR_NETWORK_FAILURE;
                    break;
                default:
                    error = E_NR_NETWORK_FAILURE;
                    break;
                }
            }
            else
            {
                error = E_NR_NETWORK_FAILURE;
                // error during write
            }
        }
    }

    return error;
}

network_relay_command_errors_t network_relay_command(network_relay_t *relay, network_relay_command_args_t command)
{
    network_relay_command_errors_t error = 0;
    network_relay_command_errors_t cmd_error = 0;
    int sock_fd = -1;
    int error_count = 0;
    char sock_buffer[BUFFER_SIZE] = {0};
    char digest_hash[MD5_HEX_LENGTH + 1];
    struct timeval timeout = {0};
    int len = 0;
    int digest_status = 0;
    char uri[256] = {0};
    packet_info_t packet_info = {0};
    char *p_auth_buffer = NULL;

    e_network_relay_command_states_t state = NRCS_CONNECT;

    timeout.tv_sec = 1;
    timeout.tv_usec = 500 * MILLI_SEC;

    error = network_relay_check(relay);

    if (!error)
    {
        if (NULL == relay->username)
        {
            relay->username = strdup(VIKING_DEFAULT_USERNAME);
            if (NULL == relay->username)
            {
                error = E_NR_NOMEM; // must be out of memory if allocate default
            }
        }
        if (NULL == relay->password)
        {
            relay->password = strdup(VIKING_DEFAULT_PASSWORD);
            if (NULL == relay->password)
            {
                error = E_NR_NOMEM; // must be out of memory if allocate default
            }
        }
    }
    if (!error)
    {
        error = network_relay_command_format(command, uri, sizeof(uri));

        while ((state < NRCS_COMMAND_COMPLETE) && !error)
        {

            switch (state)
            {
            case NRCS_CONNECT:
                state = NRCS_TEST_CONNECTION;
                break;
                sock_fd = socket_connect(relay->ip_addr, *(relay->http_port));
                if (-1 == sock_fd)
                {
                    error = E_NR_NETWORK_FAILURE;
                }
                else
                {
                    close(sock_fd);
                    sock_fd = -1;
                    state = NRCS_TEST_CONNECTION; // try to make an unauthenticated basic connection and see what happens
                }
                break;

            case NRCS_TEST_CONNECTION:
                sock_fd = socket_connect(relay->ip_addr, *(relay->http_port));
                if (-1 == sock_fd)
                {
                    error = E_NR_NETWORK_FAILURE;
                }
                else
                {
                    len = sprintf(sock_buffer, HTTP_GET_HEADER, HTTP_RC_BLANK_COMMAND, relay->ip_addr, *(relay->http_port), API_VERSION);
                    if (len > 0)
                    {
                        error = socket_xfer(sock_fd, sock_buffer, BUFFER_SIZE, timeout); 
                        
                        if (!error && (!parse_response_packet(sock_buffer, sizeof(sock_buffer), &packet_info)))
                        {
                            if (NR_NOT_AUTHORIZED == packet_info.message_type)
                            {
                                if (!packet_info.isBasicAuth)
                                {
                                    state = NRCS_TRY_DIGEST; // preferred
                                }
                                else
                                {
                                    state = NRCS_TRY_BASIC; // not recommended..
                                }
                            }
                            else
                            {
                                // error, packet didn't contain the unauth message it should have
                                error = E_NR_NETWORK_FAILURE;
                            }
                        }
                        else
                        {
                            error = E_NR_NETWORK_OUT_OF_ORDER;
                        }
                    }
                    else
                    {
                        error = E_NR_INVALID_RELAY_DETAILS;
                    }
                }
                break;

            case NRCS_TRY_BASIC:
                p_auth_buffer = NULL;
                int auth_status = generate_basic_auth(relay->username, relay->password, &p_auth_buffer);
                if (auth_status || (NULL == p_auth_buffer))
                {
                    error = E_NR_AUTH_GENERATION_FAILURE;
                    break;
                }

                sock_fd = socket_connect(relay->ip_addr, *relay->http_port);
                if (-1 == sock_fd)
                {
                    error = E_NR_NETWORK_FAILURE;
                }
                else
                {
                    len = sprintf(sock_buffer, HTTP_GET_AUTHENTICATED_BASIC, uri, relay->ip_addr, *(relay->http_port), p_auth_buffer, API_VERSION);
                    if (len > 0)
                    {
                        timeout.tv_sec = 1;
                        timeout.tv_usec = 500 * MILLI_SEC;
                        error = socket_xfer(sock_fd, sock_buffer, BUFFER_SIZE, timeout);
                        if (!error && (!parse_response_packet(sock_buffer, sizeof(sock_buffer), &packet_info)))
                        {
                            if (NR_ACTION_SUCCESSFUL == packet_info.message_type)
                            {
                                error = cmd_error = E_NR_SUCCESS;
                            }
                            else if (NR_NOT_AUTHORIZED == packet_info.message_type)
                            {
                                cmd_error = E_NR_INVALID_RELAY_DETAILS;
                            }
                            else
                            {
                                // error, packet didn't contain the unauth message it should have
                                error = E_NR_NETWORK_FAILURE;
                            }
                        }
                        else
                        {
                            error = E_NR_NETWORK_OUT_OF_ORDER;
                        }
                    }
                    if (!error)
                    {
                        state = NRCS_COMMAND_COMPLETE;
                    }
                    
                    if (p_auth_buffer)
                    {
                        free(p_auth_buffer);
                    }
                }
                break;

            case NRCS_TRY_DIGEST:
                digest_status = generate_digest("md5", relay->username, relay->password, packet_info.realm, packet_info.nonce, uri, digest_hash);
                if (digest_status)
                {
                    error = E_NR_DIGEST_GENERATION_FAILURE;
                    break;
                }
                sock_fd = socket_connect(relay->ip_addr, *relay->http_port);
                if (-1 == sock_fd)
                {
                    error = E_NR_AUTH_GENERATION_FAILURE;
                }
                else
                {
                    len = sprintf(sock_buffer, HTTP_GET_AUTHENTICATED_DIGEST, uri, relay->ip_addr, *(relay->http_port), relay->username, packet_info.realm, packet_info.nonce, uri, digest_hash, API_VERSION);
                    if (len > 0)
                    {
                        timeout.tv_sec = 1;
                        timeout.tv_usec = 500 * MILLI_SEC;
                        error = socket_xfer(sock_fd, sock_buffer, BUFFER_SIZE, timeout);
                        if (!error && (!parse_response_packet(sock_buffer, sizeof(sock_buffer), &packet_info)))
                        {
                            if (NR_ACTION_SUCCESSFUL == packet_info.message_type)
                            {
                                error = cmd_error = E_NR_SUCCESS;
                            }
                            else if (NR_NOT_AUTHORIZED == packet_info.message_type)
                            {
                                cmd_error = E_NR_INVALID_RELAY_DETAILS;
                            }
                            else
                            {
                                // error, packet didn't contain the unauth message it should have
                                error = E_NR_NETWORK_FAILURE;
                            }
                        }
                        else
                        {
                            error = E_NR_NETWORK_OUT_OF_ORDER;
                        }
                    }
                    if (!error && !cmd_error)
                    {
                        state = NRCS_COMMAND_COMPLETE;
                    }
                    else if (error_count >= C_NR_MAX_ATTEMPTS)
                    {
                        error = E_NR_NETWORK_FAILURE;
                        state = NRCS_FAILURE;
                    }
                    else
                    {
                        error_count++;
                    }
                }
                break;

            case NRCS_FAILURE:

                break;
            default:

                break;
            }
        }

    }

    return error;
}

static int
relay_ll_append(network_relay_t *head, network_relay_t *relay_node)
{
    int error = 0;
    network_relay_t *ptr = NULL;

    if (NULL == head)
    {
        error = EINVAL;
    }
    else if (NULL == relay_node)
    {
        error = EINVAL;
    }

    if (!error)
    {
        ptr = head;
        while (NULL != ptr->next)
        {
            ptr = ptr->next;
        }
        ptr->next = relay_node;
        relay_node->next = NULL;
    }
    return error;
}

/**
 * @brief parse the message received from the socket following a discovery broadcast
 *
 * @param msg string containing the response that may be from the relay
 * @param relay if the response is from a rc4a, this will be the device info structure
 * @return error, non-zero responses indicate malformed message or not from rc4a
 */
network_relay_t *
network_relay_parse(const char *msg, const char *device_name)
{
    int error = 0;
    int i = 0;
    char *last_element_start = NULL;
    char *ptr = NULL;
    network_relay_msg_order_t msg_index = 0;
    network_relay_t *new_relay = NULL;
    char parsing_buffer[MAX_MSG_SIZE + sizeof(TERMINATOR_SEQUENCE)]; // add extra space for the absolute worst case checking
    strncpy(parsing_buffer, msg, MAX_MSG_SIZE);

    if (!error)
    {
        new_relay = malloc(sizeof(network_relay_t));
        if (NULL == new_relay)
        {
            error = ENOMEM;
        }
        else
        {
            memset(new_relay, 0, sizeof(network_relay_t));
        }
    }

    if (!error)
    {
        ptr = parsing_buffer;
        last_element_start = parsing_buffer;

        for (i = 0; (i < (MAX_MSG_SIZE)) && (*(ptr + i + 1)) && !error; i++)
        {
            // check for the line breaks in the message
            if (((TERMINATOR_SEQUENCE[0] == *(ptr + i)) &&
                 (TERMINATOR_SEQUENCE[1] == *(ptr + i + 1))) ||
                (*(ptr + i + sizeof(TERMINATOR_SEQUENCE)) == 0))
            {
                // adds a terminating character for all segments except that last, which will have a null terminating character from strncpy
                if (!(*(ptr + i + sizeof(TERMINATOR_SEQUENCE)) == 0))
                {
                    *(ptr + i) = '\0'; // put a null character at the end of the message segment
                }

                if (strlen(last_element_start) < 1)
                {
                    error = EINVAL;
                }
                if (!error)
                {
                    switch (msg_index++)
                    {
                    case NR_E_PORT: // https port for relay, defaults to 80

                        new_relay->http_port = malloc(sizeof(int));
                        if (NULL == new_relay->http_port)
                        {
                            error = ENOMEM;
                        }
                        else
                        {
                            *(new_relay->http_port) = atoi(last_element_start);
                        }
                        break;
                    case NR_E_NAME: // Unit name, user configurable
                        new_relay->name = strdup(last_element_start);
                        if (NULL == new_relay->name)
                        {
                            error = ENOMEM;
                        }
                        else
                        {
                            strtok(new_relay->name, " ");
                        }
                        break;

                    case NR_E_MAC_ADDR:
                        new_relay->mac_addr = strdup(last_element_start);
                        if (NULL == new_relay->mac_addr)
                        {
                            error = ENOMEM;
		       	        }
			            //Not a Viking device
			            if (strncmp(VIKING_MAC_ADDR_PREFIX, new_relay->mac_addr, sizeof(VIKING_MAC_ADDR_PREFIX) - 1))
			            {
			                error = EINVAL;
			            }
                    
			            break;

                    case NR_E_MODEL: // product name + message
                        new_relay->model = strdup(last_element_start);
                        if (NULL == new_relay->model)
                        {
                            error = ENOMEM;
                        }
                        else
                        {
                            if (strncmp(new_relay->model, device_name, strlen(device_name)) != 0)
                            {
                                // Not the device we are looking for
                                error = EINVAL;
                            }
                        }
                        break;

                    case NR_E_PRODUCT_END: // product name alone to finish message

                        break;

                    default:
                        error = EINVAL;
                        break;
                    }
                    // advance beyond the terminator characters
                    i += 2;
                    // place ptr to start of next section
                    last_element_start = (parsing_buffer + i);
                }
            }
        }
    }

    if (error)
    {
        network_relay_destroy(new_relay);
        new_relay = NULL;
    }

    return new_relay;
}

network_relay_t *
network_relay_discovery(int discovery_timeout, char *mac_addr)
{
    int error = 0;
    int udp_socket = 0;
    struct sockaddr_in broadcast_address;
    network_relay_t *head = NULL;

    if (!error)
    {
        broadcast_address.sin_family = AF_INET;
        broadcast_address.sin_port = htons(BROADCAST_PORT);
        broadcast_address.sin_addr.s_addr = inet_addr(BROADCAST_ADDR);
    }

    if (!error)
    {
        const int broadcast_enable = 1;
        udp_socket = socket(PF_INET, AF_INET, 0);
        if (udp_socket < 0)
        {
            error = errno;
        }
        else
        {
            if (setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST,
                           &broadcast_enable, sizeof(broadcast_enable)) < 0)
            {
                error = errno;
            }
        }
    }

    if (!error)
    {
        int n_bytes = sendto(udp_socket, BROADCAST_MESSAGE, sizeof(BROADCAST_MESSAGE),
                             0, (struct sockaddr *)&broadcast_address, sizeof(broadcast_address));

        if (n_bytes < 0)
        {
            error = errno;
        }
    }

    if (!error)
    {
        char buffer[MAX_MSG_SIZE] = {0};

        struct sockaddr_in ip_addr_buffer;
        socklen_t address_length = sizeof(ip_addr_buffer);

        network_relay_t *relay_ptr = NULL;

        int n_bytes = 0;
        int ret_val = 0;

        fd_set read_fds;
        struct timeval timeout = {0};

        if (discovery_timeout > 0)
        {
            if (discovery_timeout > 999)
            {
                timeout.tv_sec = discovery_timeout / 1000;
            }
            timeout.tv_usec = (discovery_timeout % 1000) * 1000;
        }
        else
        {
            timeout.tv_usec = 500 * 1000; // 500 ms default
        }

        int found_target = 0;
        do
        {
            FD_ZERO(&read_fds);            // clear set
            FD_SET(udp_socket, &read_fds); // set fd into read fds set

            ret_val = select(udp_socket + 1, &read_fds, NULL, NULL, &timeout);

            switch (ret_val)
            {
            case -1:
                error = errno;
            // intentially falls through to next case to end reading loop
            case 0: // no descriptors ready for reading after timeout
                n_bytes = 0;
                break;
            default:
                // ready to read from socket
                memset(buffer, 0, sizeof(buffer));
                n_bytes = recvfrom(udp_socket, buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr *)&(ip_addr_buffer), &address_length);
                relay_ptr = network_relay_parse(buffer, VIKING_RC4A_MODEL_STR);
                if (NULL != relay_ptr)
                {
                    relay_ptr->ip_addr = strdup(inet_ntoa(ip_addr_buffer.sin_addr));

                    if (NULL == mac_addr)
                    {
                        if (NULL == head)
                        {
                            head = relay_ptr; // first relay
                        }
                        else
                        {
                            relay_ll_append(head, relay_ptr); // append to the list of relays
                        }
                    }
                    else
                    {
                        if (strncmp(mac_addr, relay_ptr->mac_addr, MAC_ADDRESS_LENGTH) == 0)
                        {
                            // found the right one
                            found_target = 1;
                            head = relay_ptr;
                        }
                        else
                        {
                            // not what we are looking for, destroy
                            network_relay_destroy(relay_ptr);
                            relay_ptr = NULL;
                        }
                    }
                }
                else
                {
                    continue;
                }

                break;
            }
            // should stop spinning when there are no bytes available, or when the target has been found if a mac address was specified
        } while ((n_bytes > 0) && !(found_target && mac_addr));
    }

    if (-1 != udp_socket)
    {
        shutdown(udp_socket, SHUT_RDWR);
    }

    if (error)
    {
        network_relays_destroy(head);
    }

    return head;
}

void network_relay_destroy(network_relay_t *relay)
{
    if (NULL != relay)
    {
        if (NULL != relay->http_port)
        {
            free(relay->http_port);
            relay->http_port = NULL;
        }

        if (NULL != relay->mac_addr)
        {
            free(relay->mac_addr);
            relay->mac_addr = NULL;
        }

        if (NULL != relay->model)
        {
            free(relay->model);
            relay->model = NULL;
        }

        if (NULL != relay->name)
        {
            free(relay->name);
            relay->name = NULL;
        }

        if (NULL != relay->ip_addr)
        {
            free(relay->ip_addr);
            relay->ip_addr = NULL;
        }

        if (NULL != relay->username)
        {
            free(relay->username);
            relay->username = NULL;
        }

        if (NULL != relay->password)
        {
            free(relay->password);
            relay->password = NULL;
        }

        free(relay);
    }
}

int network_relays_destroy(network_relay_t *head)
{
    int error = 0;
    network_relay_t *ptr = NULL;
    network_relay_t *last = NULL;

    if (NULL == head)
    {
        error = EINVAL;
    }

    if (!error)
    {
        ptr = head;
        while (NULL != ptr)
        {
            last = ptr;
            ptr = ptr->next;
            network_relay_destroy(last);
        }
    }
    return error;
}
