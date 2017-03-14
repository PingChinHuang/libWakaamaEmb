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

    uint8_t                 securityMode;
    char                    *identity;
    unsigned char           *psk;
    size_t                  pskLen;
    

#ifdef USE_MBEDTLS
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
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
  
  if (conn->sock < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  
  return sendto(conn->sock, buf, len, 0,
                (struct sockaddr *)&(conn->addr), conn->addrLen);
}

int lwm2m_mbedtls_recvfrom(void *ctx, unsigned char *buf, size_t len)
{
  connection_t *conn = (connection_t*) ctx;
  struct sockaddr_in addr;
  socklen_t sock_len = sizeof(addr);
  int recvLen = 0;
  
  if (conn->sock < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  
  recvLen = recvfrom(conn->sock, buf, len, 0, (struct sockaddr*)&addr, &sock_len);
  return recvLen;
}

int lwm2m_mbedtls_recvfrom_nb(void *ctx, unsigned char *buf, size_t len,
                              uint32_t timeout)
{
  struct timeval tv;
  fd_set read_fds;
  connection_t *conn = (connection_t*) ctx;
  struct sockaddr_in addr;
  socklen_t sock_len = sizeof(addr);
  int recvLen = 0;
  int ret;
  int fd = conn->sock;

  if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

  FD_ZERO(&read_fds);
  FD_SET(fd, &read_fds);
  
  tv.tv_sec = timeout / 1000;
  tv.tv_usec = (timeout % 1000) * 1000;
  
  ret = select(fd + 1, &read_fds, NULL, NULL, &tv);
  if (ret == 0){
    printf("%s, %d: timeout\n", __func__, __LINE__);
    return MBEDTLS_ERR_SSL_TIMEOUT;
  }
  if (ret < 0) return MBEDTLS_ERR_SSL_WANT_READ;
    
  printf("%s, %d\n", __func__, __LINE__);
  recvLen = recvfrom(fd, buf, len, MSG_DONTWAIT, (struct sockaddr*)&addr, &sock_len);
  printf("%s, %d\n", __func__, __LINE__);
  return recvLen;
}

typedef struct _lwm2m_mbedtls_delay_context {
  time_t timer;
  uint32_t int_ms;
  uint32_t fin_ms;
} lwm2m_mbedtls_delay_context;

time_t lwm2m_mbedtls_get_timer(time_t *val, int reset)
{
  unsigned long delta;
  time_t offset = xTaskGetTickCount();
  
  
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
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
//static mbedtls_ssl_config g_conf;

static int lwm2m_mbedtls_common_init()
{
  int ret = 0;
  //mbedtls_debug_set_threshold(3);
  // original calloc in mbedtls lib cannot get memory successfully.
  // TODO: non-thread safe in current implementation
  mbedtls_platform_set_calloc_free(lwm2m_mbedtls_calloc, lwm2m_mbedtls_free);
  //mbedtls_ssl_config_init(&g_conf);
  mbedtls_ctr_drbg_init(&g_ctr_drbg);
  mbedtls_entropy_init(&g_entropy);
  if ((ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                                   "DTLS_CLIENT", strlen("DTLS_CLIENT"))) != 0) {
    printf("failed\n ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    return -1;
  }
  
  return 0;
}

static int lwm2m_mbedtls_ssl_init(connection_t *conn)
{
  int ret;
  
  mbedtls_ssl_init(&conn->ssl);
  lwm2m_mbedtls_delay_context *timer = (lwm2m_mbedtls_delay_context*) pvPortMalloc(sizeof(lwm2m_mbedtls_delay_context));
  if (NULL == timer) {
    printf("%s, %d\n", __func__, __LINE__);
    return -1;
  }
  
  /* conn will be keep in conn->ssl->p_bio and for future data exchange. */
  mbedtls_ssl_set_bio(&conn->ssl, conn, lwm2m_mbedtls_sendto,
                      lwm2m_mbedtls_recvfrom, lwm2m_mbedtls_recvfrom_nb);
  mbedtls_ssl_set_timer_cb(&conn->ssl, timer,
                           lwm2m_mbedtls_set_delay,
                           lwm2m_mbedtls_get_delay);
  
  printf("%s, %d\n", __func__, __LINE__);
  return 0;
}
                                                    
static uint8_t gPsk[4] = {0x26, 0x43, 0x60, 0x77};
static int gCiphersuite[2];
static int lwm2m_mbedtls_set_config(connection_t *conn/*, uint8_t securityMode,
                                    uint8_t *psk, uint32_t psk_len, char *identity*/)
{
  int ret;
  
  /*conn->securityMode = securityMode;
  if (securityMode != LWM2M_SECURITY_MODE_NONE) {
    if (NULL == psk || NULL == identity || 0 == psk_len) return -1;
    
    memcpy(conn->psk, psk, psk_len);
    strncpy(conn->identity, identity, strlen(identity));
    conn->pskLen = psk_len;
  }*/
  
  gCiphersuite[0] = mbedtls_ssl_get_ciphersuite_id("TLS-PSK-WITH-AES-128-CCM-8");

  mbedtls_ssl_config_init(&conn->conf);
  if ((ret = mbedtls_ssl_config_defaults(&conn->conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    printf("failed\n ! mbedtls_ssl_config_defaults returned %d\n", ret);
    return -1;                                           
  }

  mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
  //mbedtls_ssl_conf_dbg( &conn->conf, lwm2m_mbedtls_debug, NULL);

  mbedtls_ssl_conf_ciphersuites(&conn->conf, gCiphersuite);

  if (conn->securityMode == LWM2M_SECURITY_MODE_PRE_SHARED_KEY) {
    if ((ret = mbedtls_ssl_conf_psk(&conn->conf, conn->psk, conn->pskLen,
                                    conn->identity,
                                    strlen(conn->identity))) != 0) {
      printf("%s, %d, failed\n ! mbedtls_ssl_conf_psk returned 0x%X\n", __func__, __LINE__, -ret);    
      return -1;
    }
  }

  mbedtls_ssl_conf_handshake_timeout(&conn->conf, 1000, 30000);
  mbedtls_ssl_conf_read_timeout(&conn->conf, 1000);
  printf("%s, %d\n", __func__, __LINE__);
  return 0;
}

static int lwm2m_mbedtls_ssl_setup(connection_t *conn)
{
  int ret;
  if ((ret = mbedtls_ssl_setup(&conn->ssl, &conn->conf)) != 0) {
    printf("%s, %d, failed\n ! mbedtls_ssl_setup returned 0x%x\n", __func__, __LINE__, ret);    
    return -1;     
  }

  printf("%s, %d\n", __func__, __LINE__);
  return 0;
}
 
static int lwm2m_mbedtls_handshake(connection_t *conn)
{
  int ret;
  if ((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
     printf("failed\n ! mbedtls_ssl_handshake returned 0x%X\n", -ret);
     return -1;    
  }
  printf("%s ok\n", __func__);  
  return 0;
}

static void lwm2m_mbedtls_ssl_close(connection_t *conn)
{
  vPortFree(conn->ssl.p_timer);
  mbedtls_ssl_close_notify(&conn->ssl);
  mbedtls_ssl_free(&conn->ssl);
  mbedtls_ssl_config_free(&conn->conf);
  //mbedtls_ctr_drbg_free(&conn->ctr_drbg);
  //mbedtls_entropy_free(&conn->entropy);
}

static void lwm2m_mbedtls_close()
{
  //mbedtls_ssl_config_free(&g_conf);
  mbedtls_ctr_drbg_free(&g_ctr_drbg);
  mbedtls_entropy_free(&g_entropy);
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
        
            opt = fcntl(network->socket_handle[network->open_listen_sockets],
                        F_GETFL, 0);
            opt |= O_NONBLOCK;
            fcntl(network->socket_handle[network->open_listen_sockets],
                        F_SETFL, opt);
          
            // bind
        struct sockaddr_in c_addr;
  c_addr.sin_family = AF_INET;
  c_addr.sin_addr.s_addr = inet_addr("192.168.2.208");
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

    freeaddrinfo(res);

#ifdef USE_MBEDTLS
    if (lwm2m_mbedtls_common_init() < 0) {
      return -1;
    }
    
    /*if (lwm2m_mbedtls_set_config(gPsk, sizeof(gPsk), "od_identity") < 0) {
      lwm2m_mbedtls_close();
      return -1;
    }*/
#endif
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
  struct timeval tv;
  fd_set read_fds;
    network_t* network = (network_t*)contextP->userData;
    uint8_t buffer[MAX_PACKET_SIZE];
    int numBytes, ret, max_fd = 0;
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
  
    FD_ZERO(&read_fds);
    for (unsigned c = 0; c < network->open_listen_sockets; ++c) {
      FD_SET(network->socket_handle[c], &read_fds);
      if (network->socket_handle[c] > max_fd)
        max_fd = network->socket_handle[c];
    }
  
  tv.tv_sec = 30;
  tv.tv_usec = 0;
  
  ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
  if (ret == 0){
    printf("%s, %d: timeout\n", __func__, __LINE__);
    return network->open_listen_sockets;
  }
  if (ret < 0) {
    printf("%s, %d: select returned error %d\n", __func__, __LINE__, ret);
    return  network->open_listen_sockets;
  }

    for (unsigned c = 0; c < network->open_listen_sockets; ++c)
    {
      if (!FD_ISSET(network->socket_handle[c], &read_fds)) {
        printf("%s, %d, socket = %d no data.\n", __func__, __LINE__, network->socket_handle[c]);        
        continue;
      }
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
            printf("Error in recvfrom() %d\r\n", numBytes);
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
            if (lwm2m_mbedtls_ssl_init(connP) < 0) {
              connection_free(connP);
              connP = NULL;
              goto failed;
            }
            
            if (lwm2m_mbedtls_set_config(connP) < 0) {
              lwm2m_mbedtls_ssl_close(connP);
              connection_free(connP);
              connP = NULL;
              goto failed;
            }
        
            if (lwm2m_mbedtls_ssl_setup(connP) < 0) {
              lwm2m_mbedtls_ssl_close(connP);
              connection_free(connP);
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
            if (connP->securityMode == LWM2M_SECURITY_MODE_PRE_SHARED_KEY) {
                printf("%s, %d\n", __func__, __LINE__);
              if ((numBytes = mbedtls_ssl_read(&connP->ssl, buffer, MAX_PACKET_SIZE)) <= 0) {
                printf("%s, %d\n", __func__, __LINE__);
                continue;
              }
            } else {
              numBytes = recvfrom(network->socket_handle[c], buffer, MAX_PACKET_SIZE,
                                  MSG_DONTWAIT, (struct sockaddr *)&addr, &addrLen);
            }
#endif
            lwm2m_handle_packet(contextP, buffer, numBytes, connP);
        } else {
failed:
#ifdef USE_MBEDTLS
            // Pop data from queue.
            recvfrom(network->socket_handle[c], buffer, MAX_PACKET_SIZE,
                     MSG_DONTWAIT, (struct sockaddr *)&addr, &addrLen);
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
#ifdef USE_MBEDTLS    
    lwm2m_mbedtls_close();
#endif
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
        if (connP->securityMode == LWM2M_SECURITY_MODE_PRE_SHARED_KEY) {
            printf("%s, %d\n", __func__, __LINE__);
          nbSent = mbedtls_ssl_write(&connP->ssl, buffer + offset, length - offset);
        } else {
          nbSent = sendto(connP->sock, buffer + offset, length - offset, 0,
                          (struct sockaddr *)&(connP->addr), connP->addrLen);
        }
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
        newConnP->pskLen = sizeof(newConnP->psk);
        if (!lwm2m_get_server_security(secObjInstID,
                                  &newConnP->securityMode,
                                  &newConnP->psk,
                                  &newConnP->pskLen,
                                  &newConnP->identity)
            ) {
              printf("Get server security information failed.\r\n");
              connection_free(newConnP);
              return NULL;
        }
#ifdef USE_MBEDTLS
        if (lwm2m_mbedtls_ssl_init(newConnP) < 0) {
          connection_free(newConnP);
          newConnP = NULL;
          return NULL;
        }

        if (lwm2m_mbedtls_set_config(newConnP) < 0) {
          lwm2m_mbedtls_ssl_close(newConnP);
          connection_free(newConnP);
          newConnP = NULL;
          return NULL;
        }

        if (lwm2m_mbedtls_ssl_setup(newConnP) < 0) {
          lwm2m_mbedtls_ssl_close(newConnP);
          connection_free(newConnP);
          newConnP = NULL;
          return NULL;
        }
#endif
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
        }
    }

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
#ifdef USE_MBEDTLS   
        lwm2m_mbedtls_ssl_close(connList);
#endif
        free(connList);

        connList = nextP;
    }
}

#endif
