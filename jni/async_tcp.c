#include <jni.h>
#include <android/log.h>
#include <android/looper.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h> /* INT_MAX, PATH_MAX */
#include <sys/uio.h> /* writev */
#include <sys/ioctl.h>
#include <errno.h>
#include <strings.h>
#include <netdb.h>
#include <assert.h>
#include <openssl/ssl.h>
#include "socket.h"



#define JOWW(rettype, name)                                             \
  rettype JNIEXPORT JNICALL Java_com_beetle_##name

#define DEBUG 1
#if DEBUG
#define  LOG(fmt, ...)  __android_log_print(ANDROID_LOG_INFO,"beetle",\
                                            "file:%s, line:%d "fmt, __FILE__, __LINE__, \
                                              ##__VA_ARGS__)
#else
#define  LOG(...)  do {} while (0)
#endif

#define BUF_SIZE (64*1024)

enum AsyncTCPState{
    TCP_CONNECTING,
    TCP_SSL_CONNECTING,
    TCP_READING,
    TCP_WRITING
};


static JavaVM* javavm = NULL;

static JNIEnv *getEnv();

static int callback(int fd, int events, void* data);

static jweak getSelf(JNIEnv *env, jobject object);
static void setSelf(JNIEnv *env, jobject object, jweak self);

static SSL_CTX* getSSLCTX(JNIEnv *env, jobject object);
static void setSSLCTX(JNIEnv *env, jobject object, SSL_CTX *ctx);

static SSL* getSSL(JNIEnv *env, jobject object);
static void setSSL(JNIEnv *env, jobject object, SSL *ssl);

static int getState(JNIEnv *env, jobject object);
static void setState(JNIEnv *env, jobject object, int state);

static int getSock(JNIEnv *env, jobject object);

static void setSock(JNIEnv *env, jobject object, int sock);

static int getEvents(JNIEnv *env, jobject object);

static void setEvents(JNIEnv *env, jobject object, int events);

static jbyteArray getData(JNIEnv *env, jobject object);

static void setData(JNIEnv *env, jobject object, jbyteArray bytes);

static jbyteArray concatArray(JNIEnv *env, jbyteArray arr1, jbyteArray arr2);

static jbyteArray concatBytes(JNIEnv *env, jbyteArray arr, 
                              jbyte *bytes, int len);



static void call_onRead(JNIEnv *env, jobject cb, jobject tcp, jbyteArray bytes) {
    jclass class = (*env)->GetObjectClass(env, cb);
    jmethodID method = (*env)->GetMethodID(env, class, "onRead", "(Ljava/lang/Object;[B)V");
    (*env)->CallVoidMethod(env, cb, method, tcp, bytes);
}

static void call_read_cb(JNIEnv *env, jobject object, char *buf, int len) {
    jbyteArray d = (*env)->NewByteArray(env, len);
    if (len) {
        (*env)->SetByteArrayRegion(env, d, 0, len, buf);
    }
    
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "readCallback", "Lcom/beetle/TCPReadCallback;");
    jobject cb = (*env)->GetObjectField(env, object, field);
    if (cb)
        call_onRead(env, cb, object, d);
}

static void call_onConnect(JNIEnv *env, jobject cb, jobject tcp, int status) {
    jclass class = (*env)->GetObjectClass(env, cb);
    jmethodID method = (*env)->GetMethodID(env, class, "onConnect", "(Ljava/lang/Object;I)V");
    (*env)->CallVoidMethod(env, cb, method, tcp, status);
}

static void call_connect_cb(JNIEnv *env, jobject object, int status) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "connectCallback", "Lcom/beetle/TCPConnectCallback;");
    jobject cb = (*env)->GetObjectField(env, object, field);
    if (cb)
        call_onConnect(env, cb, object, status);
}

static void suspendWriteEvent(JNIEnv *env, jobject object, int sock) {
    int events = getEvents(env, object);
    int mask = ALOOPER_EVENT_OUTPUT;
    if (!(events & mask)) {
        return;
    }
    events &= (~mask);
    setEvents(env, object, events);
    ALooper* looper = ALooper_forThread();
    jweak ref = getSelf(env, object);
    ALooper_addFd(looper, sock, ALOOPER_POLL_CALLBACK, 
                  events, callback, ref);
}

static void resumeWriteEvent(JNIEnv *env, jobject object, int sock) {
    int events = getEvents(env, object);
    int mask = ALOOPER_EVENT_OUTPUT;
    if (events & mask) {
        return;
    }
    events |= mask;
    setEvents(env, object, events);
    ALooper* looper = ALooper_forThread();
    jweak ref = getSelf(env, object);
    ALooper_addFd(looper, sock, ALOOPER_POLL_CALLBACK, 
                  events, callback, ref);
}

static int on_event(int fd, jobject object) {
    int n;
    JNIEnv *env = getEnv();
    int sock = getSock(env, object);
    SSL *ssl = getSSL(env, object);
    int state = getState(env, object);
    if (state == TCP_CONNECTING) {
        int error;
        socklen_t errorsize = sizeof(int);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorsize);
        if (error == EINPROGRESS)
            return 0;

        if (error != 0) {
            LOG("connect error:%d, %s", error, strerror(error));
            call_connect_cb(env, object, error);
            return 0;
        }

        setState(env, object, TCP_SSL_CONNECTING);

        int r = SSL_connect(ssl);
        if (r <= 0) {
            int e = SSL_get_error(ssl, r);
            if (e == SSL_ERROR_WANT_WRITE) {
                resumeWriteEvent(env, object, sock);                
                return 0;
            }
            if (e == SSL_ERROR_WANT_READ) {
                suspendWriteEvent(env, object, sock);            
                return 0;
            }

            call_connect_cb(env, object, e);
            return -1;
        } else {
            setState(env, object, TCP_READING);
            call_connect_cb(env, object, 0);
            return 0;
        }
    } else if (state == TCP_SSL_CONNECTING) {
        int r = SSL_connect(ssl);
        if (r <= 0) {
            int e = SSL_get_error(ssl, r);
            if (e == SSL_ERROR_WANT_WRITE) {
                resumeWriteEvent(env, object, sock);                

                return 0;
            }
            if (e == SSL_ERROR_WANT_READ) {
                suspendWriteEvent(env, object, sock);
                return 0;
            }

            call_connect_cb(env, object, e);
            return -1;
        } else {
            setState(env, object, TCP_READING);
            call_connect_cb(env, object, 0);
            return 0;
        }
    } else if (state == TCP_WRITING) {
        jbyteArray data = getData(env, object);
        jsize len = 0;
        if (data != NULL) {
            len = (*env)->GetArrayLength(env, data);
        }
        if (data == NULL || len == 0) {
            setState(env, object, TCP_READING);
            suspendWriteEvent(env, object, sock);
            return 0;
        }
        jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
        
        n = SSL_write(ssl, bytes, len);
        if (n <= 0) {
            (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
            int e = SSL_get_error(ssl, n);
            if (e == SSL_ERROR_WANT_WRITE) {
                resumeWriteEvent(env, object, sock);
                return 0;
            }
            if (e == SSL_ERROR_WANT_READ) {
                //do not support ssl renegotiation, drop connection
                LOG("ssl write, error:want read, drop connection");
                call_read_cb(env, object, NULL, 0);
                return -1;
            }
            return -1;
        } else {
            int left = len - n;
            jbyteArray d = (*env)->NewByteArray(env, left);
            if (left) {
                (*env)->SetByteArrayRegion(env, d, 0, left, bytes+n);
            }
            setData(env, object, d);
            (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
            if (!left) {
                setState(env, object, TCP_READING);
                suspendWriteEvent(env, object, sock);
            }
            return 0;
        }
    } else if (state == TCP_READING) {
        while (1) {
            int nread;
            char buf[BUF_SIZE];
            nread = SSL_read(ssl, buf, BUF_SIZE);
            if (nread <= 0) {
                int e = SSL_get_error(ssl, (int)nread);
                if (e == SSL_ERROR_WANT_READ) {
                    suspendWriteEvent(env, object, sock);
                    return 0;
                }

                if (e == SSL_ERROR_WANT_WRITE) {
                    //do not support ssl renegotiation, drop connection
                    LOG("ssl read, error:want write, drop connection");
                    call_read_cb(env, object, NULL, 0);                    
                    return -1;
                }
                call_read_cb(env, object, NULL, 0);
                return -1;
            } else {
                call_read_cb(env, object, buf, nread);
                if (nread < BUF_SIZE)
                    return 0;
            }
        }
    }
}

static void on_error(int fd, jobject object) {
    JNIEnv *env = getEnv();
    int state = getState(env, object);
    if (state == TCP_CONNECTING || state == TCP_SSL_CONNECTING) {
        int error = 0;
        socklen_t errorsize = sizeof(int);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorsize);
        if (error == 0) {
            error = -1;
        } else {
            LOG("connect error:%d, %s", error, strerror(error));
        }
        call_connect_cb(env, object, error);
    } else {
        call_read_cb(env, object, NULL, 0);
    }
}

#define UNREGISTER_CALLBACK 0
#define REGISTER_CALLBACK 1
static int callback(int fd, int events, void* data) {
    int err = 0;
    JNIEnv *env = getEnv();
    jweak wref = (jweak)data;
    jobject object = (*env)->NewLocalRef(env, wref);
    if (!object) {
        goto ERROR;
    }

    if (events & ALOOPER_EVENT_ERROR) {
        on_error(fd, object);
        goto ERROR;
    }
    err = on_event(fd, object);
    if (err) goto ERROR;

    return REGISTER_CALLBACK;

ERROR:
    return UNREGISTER_CALLBACK;
}

JOWW(void, AsyncTCP_startRead)(JNIEnv *env, jobject object) {

}

static void flush(JNIEnv *env, jobject object) {
    SSL *ssl = getSSL(env, object);
    jbyteArray data = getData(env, object);
    jsize len = 0;
    if (data != NULL) {
        len = (*env)->GetArrayLength(env, data);
    }
    if (data == NULL || len == 0) {
        return;
    }
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
        
    int n = SSL_write(ssl, bytes, len);
    if (n <= 0) {
        (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
        int e = SSL_get_error(ssl, n);
        LOG("ssl write err:%d", e);
    } else {
        int left = len - n;
        jbyteArray d = (*env)->NewByteArray(env, left);
        if (left) {
            (*env)->SetByteArrayRegion(env, d, 0, left, bytes+n);
        }
        setData(env, object, d);
        (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    }    
}


JOWW(void, AsyncTCP_writeData)(JNIEnv *env, jobject object, jbyteArray data) {
    int n;
    jsize len;
    jbyte *bytes;
    int state = getState(env, object);
    SSL *ssl = getSSL(env, object);
    int sock = getSock(env, object);
    int events = getEvents(env, object);


    jbyteArray d = getData(env, object);
    data = concatArray(env, d, data);
    setData(env, object, data);
    
    flush(env, object);
    
    data = getData(env, object);    
    len = (*env)->GetArrayLength(env, data);
    if (len > 0) {
        resumeWriteEvent(env, object, sock);
        setState(env, object, TCP_WRITING);        
    }
}

JOWW(void, AsyncTCP_close)(JNIEnv *env, jobject object) {
    SSL *ssl = getSSL(env, object);
    SSL_CTX *ctx = getSSLCTX(env, object);
    int sock = getSock(env, object);
    jweak self = getSelf(env, object);

    setEvents(env, object, 0);
    (*env)->DeleteWeakGlobalRef(env, self);
    setSelf(env, object, NULL);

    ALooper* looper = ALooper_forThread();
    ALooper_removeFd(looper, sock);
    close(sock);

    if (ssl) {
        SSL_free(ssl);
        setSSL(env, object, NULL);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
        setSSLCTX(env, object, NULL);
    }
}

JOWW(jboolean, AsyncTCP_connect)(JNIEnv *env, jobject object,
                             jstring host, jint port) {
    int r;
    int sockfd;
    const char *h;
    int events = ALOOPER_EVENT_OUTPUT|ALOOPER_EVENT_INPUT;    
    struct sockaddr_storage addr;

    bzero(&addr, sizeof(addr));
    h = (*env)->GetStringUTFChars(env, host, NULL);
    r = ip_to_address(h, port, &addr);
    if (r == -1) {
        LOG("dns resolve:%s", h);
        r = sock_addr(h, port, &addr);
    }
    (*env)->ReleaseStringUTFChars(env, host, h);
    if (r == -1) {
        LOG("can't get socket address");
        return JNI_FALSE;
    }

    sa_family_t family = ((struct sockaddr*)&addr)->sa_family;
    socklen_t  addr_len = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    sockfd = socket(family, SOCK_STREAM, 0);
    if (sockfd == -1) {
    	LOG("socket err:%d", errno);
        return JNI_FALSE;
    }
    sock_nonblock(sockfd, 1);
    
    do {
    	r = connect(sockfd, (const struct sockaddr*)&addr, addr_len);
    } while (r == -1 && errno == EINTR);
    if (r == -1) {
        if (errno != EINPROGRESS) {
            LOG("connect error:%d, %s", errno, strerror(errno));
            close(sockfd);
            return JNI_FALSE;
        }
    }

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    SSL *ssl = SSL_new(ctx);
    SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_set_fd(ssl, sockfd);
    
    setSSLCTX(env, object, ctx);
    setSSL(env, object, ssl);
    setSock(env, object, sockfd);
    setEvents(env, object, events);
    setState(env, object, TCP_CONNECTING);

    jweak ref = (*env)->NewWeakGlobalRef(env, object);
    setSelf(env, object, ref);
    ALooper* looper = ALooper_forThread();
    ALooper_addFd(looper, sockfd, ALOOPER_POLL_CALLBACK, events, callback, ref);
    return JNI_TRUE;
}


static JNIEnv *getEnv() {
    JNIEnv* env;
    jint ret_val = (*javavm)->GetEnv(javavm, (void**)(&env), JNI_VERSION_1_4);
    assert(ret_val != JNI_EDETACHED);
    return env;
}

static jweak getSelf(JNIEnv *env, jobject object) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "self", "J");
    jlong self = (*env)->GetLongField(env, object, field);
    return (jobject)self;
}

static void setSelf(JNIEnv *env, jobject object, jweak self) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "self", "J");
    (*env)->SetLongField(env, object, field, (jlong)self);
}

static SSL_CTX* getSSLCTX(JNIEnv *env, jobject object) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "sslCTX", "J");
    jlong self = (*env)->GetLongField(env, object, field);
    return (jobject)self;
}

static void setSSLCTX(JNIEnv *env, jobject object, SSL_CTX *ctx) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "sslCTX", "J");
    (*env)->SetLongField(env, object, field, (jlong)ctx);
}

static SSL* getSSL(JNIEnv *env, jobject object) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "ssl", "J");
    jlong ssl = (*env)->GetLongField(env, object, field);
    return (SSL*)ssl;
}

static void setSSL(JNIEnv *env, jobject object, SSL *ssl) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "ssl", "J");
    (*env)->SetLongField(env, object, field, (jlong)ssl);
}

static int getSock(JNIEnv *env, jobject object) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "sock", "I");
    int sock = (*env)->GetIntField(env, object, field);
    return sock;
}

static void setSock(JNIEnv *env, jobject object, int sock) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "sock", "I");
    (*env)->SetIntField(env, object, field, sock);
}

static int getEvents(JNIEnv *env, jobject object) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "events", "I");
    int events = (*env)->GetIntField(env, object, field);
    return events;
}

static void setEvents(JNIEnv *env, jobject object, int events) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "events", "I");
    (*env)->SetIntField(env, object, field, events);
}


static int getState(JNIEnv *env, jobject object) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "state", "I");
    int events = (*env)->GetIntField(env, object, field);
    return events;
}

static void setState(JNIEnv *env, jobject object, int state) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "state", "I");
    (*env)->SetIntField(env, object, field, state);
}


static jbyteArray getData(JNIEnv *env, jobject object) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "data", "[B");
    jbyteArray bytes = (*env)->GetObjectField(env, object, field);
    return bytes;
}

static void setData(JNIEnv *env, jobject object, jbyteArray bytes) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "data", "[B");
    (*env)->SetObjectField(env, object, field, bytes);
}

static jbyteArray concatArray(JNIEnv *env, jbyteArray arr1, jbyteArray arr2) {
    jbyteArray arr;
    jsize len1, len2;
    jbyte *bytes;
    if (!arr1) return arr2;
    if (!arr2) return arr1;


    len1 = (*env)->GetArrayLength(env, arr1);
    len2 = (*env)->GetArrayLength(env, arr2);
    
    arr = (*env)->NewByteArray(env, len1 + len2);
    
    bytes = (*env)->GetByteArrayElements(env, arr1, NULL);
    (*env)->SetByteArrayRegion(env, arr, 0, len1, bytes);
    (*env)->ReleaseByteArrayElements(env, arr1, bytes, JNI_ABORT);

    bytes = (*env)->GetByteArrayElements(env, arr2, NULL);
    (*env)->SetByteArrayRegion(env, arr, len1, len2, bytes);
    (*env)->ReleaseByteArrayElements(env, arr2, bytes, JNI_ABORT);
    
    return arr;
}

static jbyteArray concatBytes(JNIEnv *env, jbyteArray arr, 
                              jbyte *bytes, int len) {
    jbyteArray r;
    jbyteArray d = (*env)->NewByteArray(env, len);
    if (len) {
        (*env)->SetByteArrayRegion(env, d, 0, len, bytes);
    }
    r = concatArray(env, arr, d);
    return r;
}


jint JNIEXPORT JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
  javavm = vm;
  SSL_library_init();
  return JNI_VERSION_1_4;
}
