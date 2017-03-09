#if defined(DTLS)
#include <FreeRTOS.h>
#include <task.h>

#include <lwm2m/wakaama/wakaama_network.h>
#include <lwm2m/wakaama/wakaama_simple_client.h>
#include <lwm2m/network/network_utils.h>
#include <lwm2m/internals.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_MBEDTLS
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/pk.h>
#endif

#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 512
#endif

//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>

typedef struct _connection_t_
{
    struct _connection_t *  next;
    int                     sock;
    struct sockaddr_in     addr;
    size_t                  addrLen;

#ifdef USE_MBEDTLS
    //mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    //mbedtls_x509_crt cacert;
    //mbedtls_timing_delay_context timer;
    //mbedtls_pk_context pkey;
#endif
} connection_t;

connection_t * connection_find(connection_t * connList, struct sockaddr * addr, size_t addrLen);
connection_t * connection_create(network_t * network, char * host, char * port);
void connection_free(connection_t * connList);

#ifdef USE_MBEDTLS
static void lwm2m_mbedtls_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    const char *p, *basename;

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;
  printf("%s:%04d: |%d| %s\n", basename, line, level, str);
}

void * lwm2m_mbedtls_calloc( size_t n, size_t size )
{
  void* p = pvPortMalloc(n * size);
  if (p == NULL) return NULL;

  memset(p, 0, n *size);
  return p;
}

void lwm2m_mbedtls_free( void *ptr )
{
  vPortFree(ptr);
}

int lwm2m_mbedtls_sendto(void *ctx, const unsigned char *buf, size_t len)
{
  connection_t *conn = (connection_t*) ctx;
  return sendto(conn->sock, buf, len, 0,
                (struct sockaddr *)&(conn->addr), conn->addrLen);
}

int lwm2m_mbedtls_recvfrom(void *ctx, unsigned char *buf, size_t len)
{
  connection_t *conn = (connection_t*) ctx;
  struct sockaddr_in addr;
  socklen_t sock_len = sizeof(addr);
  int recvLen = 0;
  recvLen = recvfrom(conn->sock, buf, len, 0, (struct sockaddr*)&addr, &sock_len);
  return recvLen;
}

typedef struct _lwm2m_mbedtls_delay_context {
  TickType_t timer;
  uint32_t int_ms;
  uint32_t fin_ms;
} lwm2m_mbedtls_delay_context;

TickType_t lwm2m_mbedtls_get_timer(TickType_t *val, int reset)
{
  unsigned long delta;
  TickType_t offset = xTaskGetTickCount(); 
  
  printf("start = %u ms, current = %u ms\n", *val, offset); 
  
  if (reset) {
    *val = offset;
    return 0;
  }
  
  delta = offset - *val;
  printf("delta = %u ms\n", delta);
  return delta;
}

void lwm2m_mbedtls_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
  lwm2m_mbedtls_delay_context *ctx = (lwm2m_mbedtls_delay_context*) data;
  ctx->int_ms = int_ms;
  ctx->fin_ms = fin_ms;
  
  if (fin_ms != 0)
    lwm2m_mbedtls_get_timer(&ctx->timer, 1);
}

int lwm2m_mbedtls_get_delay(void *data)
{
  lwm2m_mbedtls_delay_context *ctx = (lwm2m_mbedtls_delay_context*) data;
  unsigned long elapsed_ms;
  if (ctx->fin_ms == 0) return -1;
  
  elapsed_ms = lwm2m_mbedtls_get_timer(&ctx->timer, 0);
  
  if (elapsed_ms >= ctx->fin_ms) return 2;
  if (elapsed_ms >= ctx->int_ms) return 1;
  
  return 0;
}

static lwm2m_mbedtls_delay_context g_delayCtx;

static void lwm2m_mbedtls_init_cb()
{
 //mbedtls_debug_set_threshold(3);
  // original calloc in mbedtls lib cannot get memory successfully.
  // TODO: non-thread safe in current implementation
  mbedtls_platform_set_calloc_free(lwm2m_mbedtls_calloc, lwm2m_mbedtls_free);
}

static uint32_t lwm2m_mbedtls_init(connection_t *conn)
{
  int ret;
  //mbedtls_net_init(&conn->server_fd);
  
  mbedtls_ssl_init(&conn->ssl);
  mbedtls_ssl_config_init(&conn->conf);
  //mbedtls_x509_crt_init(&conn->cacert);
  //mbedtls_pk_init(&conn->pkey);
  mbedtls_ctr_drbg_init(&conn->ctr_drbg);
  mbedtls_entropy_init(&conn->entropy);
  if ((ret = mbedtls_ctr_drbg_seed(&conn->ctr_drbg, mbedtls_entropy_func, &conn->entropy,
                                   "DTLS_CLIENT", strlen("DTLS_CLIENT"))) != 0) {
    printf("failed\n ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    return -1;
  }

  /* conn will be keep in conn->ssl->p_bio and for future data exchange. */
  mbedtls_ssl_set_bio(&conn->ssl, conn, lwm2m_mbedtls_sendto,
                      lwm2m_mbedtls_recvfrom, NULL);
  mbedtls_ssl_set_timer_cb(&conn->ssl, &g_delayCtx,
                           lwm2m_mbedtls_set_delay,
                           lwm2m_mbedtls_get_delay);
    printf("%s, %d\n", __func__, __LINE__);
  return 0;
}
                                                    
static uint8_t gPsk[4] = {0x26, 0x43, 0x60, 0x77};
static int gCiphersuite[2];
static uint32_t lwm2m_mbedtls_ssl_config(connection_t *conn, uint8_t *psk,
                                         uint32_t psk_len, char *identity)
{
  int ret;
  gCiphersuite[0] = mbedtls_ssl_get_ciphersuite_id("TLS-PSK-WITH-AES-128-CCM-8");
  
  if ((ret = mbedtls_ssl_config_defaults(&conn->conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    printf("failed\n ! mbedtls_ssl_config_defaults returned %d\n", ret);
    return -1;                                           
  }

  //mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  //mbedtls_ssl_conf_ca_chain(&conn->conf, &conn->cacert, NULL);
  mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->ctr_drbg);
  //mbedtls_ssl_conf_dbg( &conn->conf, lwm2m_mbedtls_debug, NULL);

  mbedtls_ssl_conf_ciphersuites(&conn->conf, gCiphersuite);
;
  if ((ret = mbedtls_ssl_conf_psk(&conn->conf, psk, psk_len, identity,
                                  strlen(identity))) != 0) {
    printf("%s, %d, failed\n ! mbedtls_ssl_conf_psk returned 0x%X\n", __func__, __LINE__, -ret);    
    return -1;
  }

  mbedtls_ssl_conf_handshake_timeout(&conn->conf, 0, 0);
  if ((ret = mbedtls_ssl_setup(&conn->ssl, &conn->conf)) != 0) {
    printf("%s, %d, failed\n ! mbedtls_ssl_setup returned 0x%x\n", __func__, __LINE__, ret);    
    return -1;     
  }

  printf("%s, %d\n", __func__, __LINE__);
  return 0;
}
 
static uint32_t lwm2m_mbedtls_handshake(connection_t *conn)
{
  int ret;
  if ((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
     printf("failed\n ! mbedtls_ssl_handshake returned 0x%X\n", -ret);
     return -1;    
  }
  printf("%s ok\n", __func__);  
  return 0;
}

static uint32_t lwm2m_mbedtls_close(connection_t *conn)
{
  mbedtls_ssl_close_notify(&conn->ssl);
  mbedtls_ssl_free(&conn->ssl);
  mbedtls_ssl_config_free(&conn->conf);
  mbedtls_ctr_drbg_free(&conn->ctr_drbg);
  mbedtls_entropy_free(&conn->entropy);
  return 0;
}

#endif

uint8_t lwm2m_network_init(lwm2m_context_t * contextP, const char *localPort) {
    // The network can only be initialized once. We also need the userdata pointer
    // and therefore check if it is not used so far.
    if (contextP->userData != NULL)
    {
        return 0;
    }

    // Allocate memory for the network structure
    contextP->userData = lwm2m_malloc(sizeof(network_t));
    if (contextP->userData == NULL)
    {
        return 0;
    }

    network_t* network = (network_t*)contextP->userData;
    memset(network, 0, sizeof(network_t));

    int s = -1;
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *p;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM;
    //hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0; // any protocol
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    int r;
    if (localPort) {
        // Server
        network->type = NET_SERVER_PROCESS;
        r = getaddrinfo(NULL, localPort, &hints, &res);
    } else {
        // client
        network->type = NET_CLIENT_PROCESS;
        r = getaddrinfo(NULL, "12873", &hints, &res);
    }

    if (0 != r || res == NULL)
    {
        return -1;
    }

    network->open_listen_sockets = 0;
    for(p = res ; p != NULL && s == -1 ; p = p->ai_next)
        ++network->open_listen_sockets;

    printf("network->open_listen_sockets = %d\n", network->open_listen_sockets);
    network->socket_handle = (int*)malloc(sizeof(int)*network->open_listen_sockets);

    network->open_listen_sockets = 0;
    for(p = res ; p != NULL; p = p->ai_next)
    {
        // get socket
        network->socket_handle[network->open_listen_sockets] = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        //  check socket fd is valid or not.        
        if (network->socket_handle[network->open_listen_sockets] >= 0)
        {
            int opt = 1;
            if (setsockopt(network->socket_handle[network->open_listen_sockets],
                           SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
              printf("Fail to setsockopt.\n");
              close(network->socket_handle[network->open_listen_sockets]);
              network->socket_handle[network->open_listen_sockets] = -1;
              continue;
            }
          
            // bind
        struct sockaddr_in c_addr;
  c_addr.sin_family = AF_INET;
  c_addr.sin_addr.s_addr = inet_addr("192.168.2.127");
  c_addr.sin_port = htons(12873);
  
            //if (-1 == bind(network->socket_handle[network->open_listen_sockets], p->ai_addr, p->ai_addrlen))
            if (-1 == bind(network->socket_handle[network->open_listen_sockets], (struct sockaddr*)&c_addr, sizeof(c_addr)))
            {
                // bind failed.
                close(network->socket_handle[network->open_listen_sockets]);
                network->socket_handle[network->open_listen_sockets] = -1;
            } else
            {   
                // bind successfully.
                ++network->open_listen_sockets;
            }
        }
    }
    
    lwm2m_mbedtls_init_cb();
    freeaddrinfo(res);

    return network->open_listen_sockets;
}

#ifdef WITH_LOGS
void prv_log_addr(connection_t * connP, size_t length, bool sending)
{
    char s[INET6_ADDRSTRLEN];
    in_port_t port;

    s[0] = 0;

    if (AF_INET == connP->addr.sin6_family)
    {
        struct sockaddr_in *saddr = (struct sockaddr_in *)&connP->addr;
        inet_ntop(saddr->sin_family, &saddr->sin_addr, s, INET6_ADDRSTRLEN);
        port = saddr->sin_port;
    }

    if (sending)
        printf("Sending %d bytes to [%s]:%hu\r\n", length, s, ntohs(port));
    else
        printf("Receiving %d bytes from [%s]:%hu\r\n", length, s, ntohs(port));

    //output_buffer(stderr, buffer, length, 0);
}
#endif

bool lwm2m_network_process(lwm2m_context_t * contextP) {
    network_t* network = (network_t*)contextP->userData;
    uint8_t buffer[MAX_PACKET_SIZE];
    int numBytes;
    struct sockadd_in addr;
    socklen_t addrLen = sizeof(addr);

    for (unsigned c = 0; c < network->open_listen_sockets; ++c)
    {
		// FIXME: Original implementation is get sockaddr by recvfrom, and
		// check whether the connection of address exists or not.
		// However, wolfSSL_read doesn't provide the arguments to pass back sockaddr.
		// I decide not to add a new pointer to network->connection_list but I am
		// not sure it will lead to another problem or not.
#ifdef USE_MBEDTLS
		// Use MSG_PEEK to peek the information from queue without poping it.
		// We will pop the packet date later with mbedtls_ssl_read.
        numBytes = recvfrom(network->socket_handle[c], buffer, MAX_PACKET_SIZE,
							MSG_PEEK, (struct sockaddr *)&addr, &addrLen);
#else
        numBytes = recvfrom(network->socket_handle[c], buffer, MAX_PACKET_SIZE,
							0, (struct sockaddr *)&addr, &addrLen);
#endif
        if (numBytes < 0)
        {
            printf("Error in recvfrom()\r\n");
            continue;
        } else if (numBytes == 0)
            continue; // no new data

        connection_t * connP = connection_find(network->connection_list, &addr, addrLen);

        if (connP == NULL && network->type == NET_SERVER_PROCESS) {
            connP = (connection_t *)malloc(sizeof(connection_t));
            if (connP == NULL)
            {
                printf("memory alloc for new connection failed");
                goto failed;
            }
            connP->sock = network->socket_handle[c];
            memcpy(&(connP->addr), (struct sockaddr *)&addr, addrLen);
            connP->addrLen = addrLen;

#ifdef USE_MBEDTLS
            if (lwm2m_mbedtls_init(connP) < 0) {
              free(connP);
              connP = NULL;
              goto failed;
            }
            
            if (lwm2m_mbedtls_ssl_config(connP, gPsk, sizeof(gPsk), "od_identity") < 0) {
              lwm2m_mbedtls_close(connP);
              free(connP);
              connP = NULL;
              goto failed;
            }
#endif

            connP->next = (struct _connection_t *)network->connection_list;
            network->connection_list = connP;
        }

        if (connP != NULL) {
            #ifdef WITH_LOGS
            prv_log_addr(connP, numBytes, false);
            #endif
            
#ifdef USE_MBEDTLS
            if ((numBytes = mbedtls_ssl_read(&connP->ssl, buffer, MAX_PACKET_SIZE)) <= 0) {
				printf("%s, %d\n", __func__, __LINE__);
				continue;
            }
#endif
            lwm2m_handle_packet(contextP, buffer, numBytes, connP);
        } else {
failed:
#ifdef USE_MBEDTLS
			// Pop data from queue.
			recvfrom(network->socket_handle[c], buffer, MAX_PACKET_SIZE,
					0, (struct sockaddr *)&addr, &addrLen);
#endif
            printf("received bytes ignored!\r\n");
        }
    }

    return network->open_listen_sockets;
}

void lwm2m_network_close(lwm2m_context_t * contextP) {
    network_t* network = (network_t*)contextP->userData;
    for (unsigned c = 0; c < network->open_listen_sockets; ++c)
    {
        close(network->socket_handle[c]);
    }
    
    connection_free(network->connection_list);
    free(network->socket_handle);
    network->open_listen_sockets = 0;
    free(network);
    contextP->userData = NULL;
}

uint8_t lwm2m_buffer_send(void * sessionH,
                          uint8_t * buffer,
                          size_t length,
                          void * userdata)
{
    //network_t* network = (network_t*)userdata;
    connection_t * connP = (connection_t*) sessionH;

    if (connP == NULL)
    {
        printf("#> failed sending %lu bytes, missing connection\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    #ifdef WITH_LOGS
    prv_log_addr(connP, length, true);
    #endif

    int nbSent;
    size_t offset = 0;
    while (offset != length)
    {
#ifdef USE_MBEDTLS
        nbSent = mbedtls_ssl_write(&connP->ssl, buffer + offset, length - offset);
#else
        nbSent = sendto(connP->sock, buffer + offset, length - offset, 0, (struct sockaddr *)&(connP->addr), connP->addrLen);
#endif
        if (nbSent < 0)
        {
            printf("#> failed sending %lu bytes\r\n", length);
            return COAP_500_INTERNAL_SERVER_ERROR ;
        }
        offset += nbSent;
    }

    return COAP_NO_ERROR;
}

bool lwm2m_session_is_equal(void * session1,
                            void * session2,
                            void * userData)
{
    return (session1 == session2);
}

void * lwm2m_connect_server(uint16_t secObjInstID,
                            void * userData)
{

    char * host;
    char * port;
    char uri[255];

    if (!lwm2m_get_server_uri(secObjInstID, uri, sizeof(uri)))
        return NULL;

    #ifdef WITH_LOG
    LOG("Connecting to %s\r\n", uri);
    #endif

    decode_uri(uri, &host, &port);

    network_t* network = (network_t*)userData;
    connection_t * newConnP = connection_create(network, host, port);
    if (newConnP == NULL) {
        printf("Connection creation failed.\r\n");
    }
    else {
        network->connection_list = newConnP;
    }

    return (void *)newConnP;
}

void lwm2m_close_connection(void * sessionH,
                            void * userData)
{
    network_t* network = (network_t*)userData;
    connection_free(network->connection_list);
}

void lwm2m_network_force_interface(lwm2m_context_t * contextP, void* interface)
{
    // do nothing for posix sockets
}

connection_t * connection_find(connection_t * connList,
                               struct sockaddr * addr,
                               size_t addrLen)
{
    connection_t * connP;

    connP = connList;
    while (connP != NULL)
    {
        if ((connP->addrLen == addrLen)
         && (memcmp(&(connP->addr), addr, addrLen) == 0))
        {
            return connP;
        }
        connP = (connection_t*)connP->next;
    }

    return connP;
}

connection_t * connection_create(network_t* network,
                                 char * host,
                                 char * port)
{
    if (!network->open_listen_sockets)
        return NULL;

    struct addrinfo hints;
    struct addrinfo *servinfo = NULL;
    struct addrinfo *p;
    int s;
    struct sockaddr *sa;
    socklen_t sl;
    connection_t * connP = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    //hints.ai_flags = AI_NUMERICSERV|AI_ADDRCONFIG;

    printf("%s, %s\n", host, port);
    
    if (0 != getaddrinfo(host, port, &hints, &servinfo) || servinfo == NULL) {
        return NULL;
    }

    // we test the various addresses with the sockets we know
    s = -1;
    for(p = servinfo ; p != NULL; p = p->ai_next)
    {
        for (unsigned sock_no = 0; sock_no < network->open_listen_sockets; ++sock_no)
        {
            s = network->socket_handle[sock_no];
            sa = p->ai_addr;
            sl = p->ai_addrlen;
            // We test if the given socket is able to connect to the ip address
            if (-1 != connect(s, p->ai_addr, p->ai_addrlen))
            {
                // "Connection" possible. If you use connect on a udp socket, that
                // socket will only receive from the given address. To make the socket
                // listen to any address again, call connect with sa_family == AF_UNSPEC.
                struct sockaddr any_addr;
                any_addr.sa_family = AF_UNSPEC;
                connect(s,&any_addr,sizeof(any_addr));
                break;
            } else {
                s = -1;
            }
        }
    }

    if (s >= 0)
    {
        connP = (connection_t *)malloc(sizeof(connection_t));
        if (connP != NULL)
        {
            connP->sock = s;
            memcpy(&(connP->addr), sa, sl);
            connP->addrLen = sl;
            connP->next = (struct _connection_t *)network->connection_list;
#ifdef USE_MBEDTLS
            if (lwm2m_mbedtls_init(connP) < 0) {
              free(connP);
              connP = NULL;
              goto connection_create_exit;
            }
            
              /*gPsk[0] = 0x26;
              gPsk[1] = 0x43;
              gPsk[2] = 0x60;
              gPsk[3] = 0x77;*/
            
            if (lwm2m_mbedtls_ssl_config(connP, gPsk, sizeof(gPsk), "od_identity") < 0) {
              lwm2m_mbedtls_close(connP);
              free(connP);
              connP = NULL;
              goto connection_create_exit;
            }
#endif
        }
    }

connection_create_exit:
    if (NULL != servinfo) {
        freeaddrinfo(servinfo);
    }

    return connP;
}

void connection_free(connection_t * connList)
{
    while (connList != NULL)
    {
        connection_t * nextP;

        nextP = (connection_t*)connList->next;
        lwm2m_mbedtls_close(connList);
        free(connList);

        connList = nextP;
    }
}

#endif
