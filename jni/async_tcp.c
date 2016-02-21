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
#include <netdb.h>
#include <assert.h>

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


static JavaVM* javavm = NULL;

static JNIEnv *getEnv();

static int callback(int fd, int events, void* data);

static jweak getSelf(JNIEnv *env, jobject object);
static void setSelf(JNIEnv *env, jobject object, jweak self);
static jboolean getConnecting(JNIEnv *env, jobject object);

static void setConnecting(JNIEnv *env, jobject object, jboolean connecting);

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

static void clearOutputEvent(JNIEnv *env, jobject object, int sock) {
    int events = getEvents(env, object);
    int mask = ALOOPER_EVENT_OUTPUT;
    events &= (~mask);
    setEvents(env, object, events);
    if (events) {
        ALooper* looper = ALooper_forThread();
        jweak ref = getSelf(env, object);
        ALooper_addFd(looper, sock, ALOOPER_POLL_CALLBACK, 
                      events, callback, ref);
    } else {
        ALooper* looper = ALooper_forThread();
        ALooper_removeFd(looper, sock);
    }
}

static int on_write(int fd, jobject object) {
    int n;
    JNIEnv *env = getEnv();
    jboolean connecting;
    connecting = getConnecting(env, object);
    if (connecting) {
        int error;
        socklen_t errorsize = sizeof(int);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorsize);
        if (error == EINPROGRESS)
            return 0;

        if (error != 0) {
            LOG("connect error:%d, %s", error, strerror(error));
        }
        setConnecting(env, object, 0);
        call_connect_cb(env, object, error);
        return 0;
    }

    int sock = getSock(env, object);
    jbyteArray data = getData(env, object);
    if (data == NULL) {
        clearOutputEvent(env, object, sock);
        return 0;
    }
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    n = write_data(fd, bytes, len);
    if (n < 0) {
        (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
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
            clearOutputEvent(env, object, sock);
        }
        return 0;
    }
}

#define BUF_SIZE (64*1024)

static int on_read(int fd, jobject object) {
    JNIEnv *env = getEnv();
    
    while (1) {
        int nread;
        char buf[BUF_SIZE];

        do {
            nread = read(fd, buf, BUF_SIZE);
        }while (nread < 0 && errno == EINTR);

        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            } else {
                call_read_cb(env, object, NULL, 0);
                return -1;
            }
        } else if (nread == 0) {
            call_read_cb(env, object, NULL, 0);
            return 0;
        } else {
            call_read_cb(env, object, buf, nread);
            if (nread < BUF_SIZE)
                return 0;
        }
    }
}

static void on_error(int fd, jobject object) {
    JNIEnv *env = getEnv();
    jboolean connecting;
    connecting = getConnecting(env, object);
    if (connecting) {
        int error = 0;
        socklen_t errorsize = sizeof(int);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorsize);
        if (error == 0) {
            error = -1;
        } else {
            LOG("connect error:%d, %s", error, strerror(error));
        }
        setConnecting(env, object, 0);
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

    if (events & ALOOPER_EVENT_INPUT) {
        err = on_read(fd, object);
        if (err) goto ERROR;
    }
    if (events & ALOOPER_EVENT_OUTPUT) {
        err = on_write(fd, object);
        if (err) goto ERROR;
    }
    
    return REGISTER_CALLBACK;

ERROR:
    return UNREGISTER_CALLBACK;
}

JOWW(void, AsyncTCP_startRead)(JNIEnv *env, jobject object) {
    int sock = getSock(env, object);
    int events = getEvents(env, object);
    events |= ALOOPER_EVENT_INPUT;
    setEvents(env, object, events);

    jweak self = getSelf(env, object);
    ALooper* looper = ALooper_forThread();
    ALooper_addFd(looper, sock, ALOOPER_POLL_CALLBACK, events, callback, self);
}

JOWW(void, AsyncTCP_writeData)(JNIEnv *env, jobject object, jbyteArray data) {
    int n;
    jsize len;
    jbyte *bytes;
    int sock = getSock(env, object);
    int events = getEvents(env, object);

    if (events & ALOOPER_EVENT_OUTPUT) {
        jbyteArray d = getData(env, object);
        jbyteArray tmp = concatArray(env, d, data);
        setData(env, object, tmp);
        return;
    }
    
    len = (*env)->GetArrayLength(env, data);
    bytes = (*env)->GetByteArrayElements(env, data, NULL);
    n = write_data(sock, bytes, len);
    if (n < 0) {
        (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
        return;
    } else {
        jbyteArray tmp = getData(env, object);
        tmp = concatBytes(env, tmp, bytes+n, len-n);
        setData(env, object, tmp);
        (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
        return;
    }
}

JOWW(void, AsyncTCP_close)(JNIEnv *env, jobject object) {
    int sock = getSock(env, object);
    setEvents(env, object, 0);
    jweak self = getSelf(env, object);
    (*env)->DeleteWeakGlobalRef(env, self);
    setSelf(env, object, NULL);

    ALooper* looper = ALooper_forThread();
    ALooper_removeFd(looper, sock);
    close(sock);
}

JOWW(jboolean, AsyncTCP_connect)(JNIEnv *env, jobject object,
                             jstring host, jint port) {
    int r;
    int sockfd;
    const char *h;
    int events = ALOOPER_EVENT_OUTPUT;
    struct sockaddr_in addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
    	LOG("socket err:%d", errno);
        return JNI_FALSE;
    }
    sock_nonblock(sockfd, 1);

    h =  (*env)->GetStringUTFChars(env, host, NULL);
    addr = sock_addr(h, port);

    (*env)->ReleaseStringUTFChars(env, host, h);

    do {
    	r = connect(sockfd, (const struct sockaddr*)&addr, sizeof(addr));
    } while (r == -1 && errno == EINTR);
    if (r == -1) {
        if (errno != EINPROGRESS) {
            LOG("connect error:%d, %s", errno, strerror(errno));
            close(sockfd);
            return JNI_FALSE;
        }
    }

    setSock(env, object, sockfd);
    setEvents(env, object, events);
    setConnecting(env, object, 1);

    jweak ref = (*env)->NewWeakGlobalRef(env, object);
    setSelf(env, object, ref);
    ALooper* looper = ALooper_forThread();
    ALooper_addFd(looper, sockfd, ALOOPER_POLL_CALLBACK, events, callback, ref);
    return JNI_TRUE;
}

jint JNIEXPORT JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
  javavm = vm;
  return JNI_VERSION_1_4;
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

static jboolean getConnecting(JNIEnv *env, jobject object) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "connecting", "Z");
    jboolean connecting = (*env)->GetBooleanField(env, object, field);
    return connecting;
}

static void setConnecting(JNIEnv *env, jobject object, jboolean connecting) {
    jclass class = (*env)->GetObjectClass(env, object);
    jfieldID field = (*env)->GetFieldID(env, class, "connecting", "Z");
    (*env)->SetBooleanField(env, object, field, connecting);
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
    jbyteArray tmp;
    jbyteArray d = (*env)->NewByteArray(env, len);
    if (len) {
        (*env)->SetByteArrayRegion(env, d, 0, len, bytes);
    }
    tmp = concatArray(env, d, tmp);
    return tmp;
}

