/*
 * This file Copyright (C) Mnemosyne LLC
 *
 * This file is licensed by the GPL version 2. Works owned by the
 * Transmission project are granted a special exemption to clause 2(b)
 * so that the bulk of its code can remain under the MIT license.
 * This exemption does not extend to derived works not owned by
 * the Transmission project.
 *
 * $Id$
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <libutp/utp.h>

#include <openssl/err.h>

#include "transmission.h"
#include "session.h"
#include "bandwidth.h"
#include "crypto.h"
#include "net.h"
#include "peer-common.h" /* MAX_BLOCK_SIZE */
#include "peer-io.h"
#include "trevent.h" /* tr_runInEventThread() */
#include "tr-utp.h"
#include "utils.h"


#ifdef WIN32
 #define EAGAIN       WSAEWOULDBLOCK
 #define EINTR        WSAEINTR
 #define EINPROGRESS  WSAEINPROGRESS
 #define EPIPE        WSAECONNRESET
#endif

/* The amount of read bufferring that we allow for uTP sockets. */

#define UTP_READ_BUFFER_SIZE (256 * 1024)

static size_t
guessPacketOverhead( size_t d )
{
    /**
     * http://sd.wareonearth.com/~phil/net/overhead/
     *
     * TCP over Ethernet:
     * Assuming no header compression (e.g. not PPP)
     * Add 20 IPv4 header or 40 IPv6 header (no options)
     * Add 20 TCP header
     * Add 12 bytes optional TCP timestamps
     * Max TCP Payload data rates over ethernet are thus:
     *  (1500-40)/(38+1500) = 94.9285 %  IPv4, minimal headers
     *  (1500-52)/(38+1500) = 94.1482 %  IPv4, TCP timestamps
     *  (1500-52)/(42+1500) = 93.9040 %  802.1q, IPv4, TCP timestamps
     *  (1500-60)/(38+1500) = 93.6281 %  IPv6, minimal headers
     *  (1500-72)/(38+1500) = 92.8479 %  IPv6, TCP timestamps
     *  (1500-72)/(42+1500) = 92.6070 %  802.1q, IPv6, ICP timestamps
     */
    const double assumed_payload_data_rate = 94.0;

    return (unsigned int)( d * ( 100.0 / assumed_payload_data_rate ) - d );
}

/**
***
**/

#define dbgmsg( io, ... ) \
    do { \
        if( tr_deepLoggingIsActive( ) ) \
            tr_deepLog( __FILE__, __LINE__, tr_peerIoGetAddrStr( io ), __VA_ARGS__ ); \
    } while( 0 )

/**
***
**/

struct bio_internal
{
    const unsigned char * read_buf;
    size_t read_length;
    struct evbuffer * write_buf;
};


/* Called to initialize a new BIO */
static int
bio_peerio_new(BIO *b)
{
    b->init = 0;
    b->num = -1;
    b->ptr = NULL; /* We'll be putting the peerIO in this field.*/
    b->flags = 0;
    return 1;
}

/* Called to uninitialize the BIO. */
static int
bio_peerio_free(BIO *b)
{
    if (!b)
        return 0;
    if (b->shutdown) {
        b->ptr = NULL;
        b->init = 0;
        b->flags = 0;
        b->ptr = NULL;
    }
    return 1;
}

/* Called to extract data from the BIO. */
static int
bio_peerio_read(BIO *b, char *out, int outlen)
{
    int r = 0;
    struct bio_internal *i;

    BIO_clear_retry_flags( b );

    if ( !out )
         return 0;
    if ( !b->ptr )
         return -1;

    i = b->ptr;
    r = i->read_length;

    if ( r == 0 )
    {
        /* If there's no data to read, say so. */
        BIO_set_retry_read( b );
        return -1;
    }
    else
    {
        r = MIN( r, outlen );
        memcpy( out, i->read_buf, r );
        i->read_length -= r;
        i->read_buf += r;
    }

    return r;
}

/* Called to write data info the BIO */
static int
bio_peerio_write(BIO *b, const char *in, int inlen)
{
    struct bio_internal *i;

    BIO_clear_retry_flags(b);

    if (!b->ptr)
        return -1;

    i = b->ptr;

    assert(inlen > 0);
    evbuffer_add(i->write_buf, in, inlen);
    return inlen;
}

/* Called to handle various requests */
static long
bio_peerio_ctrl(BIO *b, int cmd, long num, void *ptr UNUSED)
{
    struct bio_internal *i = b->ptr;
    long ret = 1;

    switch (cmd) {
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_PENDING:
        ret = i->read_length != 0;
        break;
    case BIO_CTRL_WPENDING:
        ret = evbuffer_get_length( i->write_buf ) != 0;
        break;
    /* XXXX These two are given a special-case treatment because
     * of cargo-cultism.  I should come up with a better reason. */
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    default:
        ret = 0;
        break;
    }
    return ret;
}

/* Called to write a string to the BIO */
static int
bio_peerio_puts(BIO *b, const char *s)
{
    return bio_peerio_write(b, s, strlen(s));
}

#define BIO_TYPE_TR_PEERIO_PRIV 58

/* Method table for the peerio BIO */
static BIO_METHOD methods_peerio = {
    BIO_TYPE_TR_PEERIO_PRIV, "tr_peerIo private",
    bio_peerio_write,
    bio_peerio_read,
    bio_peerio_puts,
    NULL /* bio_bufferevent_gets */,
    bio_peerio_ctrl,
    bio_peerio_new,
    bio_peerio_free,
    NULL /* callback_ctrl */,
};

/* Return the method table for the peerio BIO */
static BIO_METHOD *
BIO_s_peerio(void)
{
    return &methods_peerio;
}

static BIO *
getBio( tr_peerIo * io )
{
    BIO * b = BIO_new( BIO_s_peerio() );
    b->ptr = tr_new0( struct bio_internal, 1 );
    ( (struct bio_internal *) b->ptr )->write_buf = tr_peerIoGetWriteBuffer( io );
    b->init = 1;
    return b;
}

static void
initBioReadBuf( BIO * bio, const unsigned char* buf, size_t len)
{
    struct bio_internal *i = bio->ptr;

    i->read_buf = buf;
    i->read_length = len;
}


/**
***
**/

struct tr_datatype
{
    struct tr_datatype * next;
    size_t length;
    size_t overhead;
    bool isPieceData;
};

static struct tr_datatype * datatype_pool = NULL;

static const struct tr_datatype TR_DATATYPE_INIT = { NULL, 0, 0, false };

static struct tr_datatype *
datatype_new( void )
{
    struct tr_datatype * ret;

    if( datatype_pool == NULL )
        ret = tr_new( struct tr_datatype, 1 );
    else {
        ret = datatype_pool;
        datatype_pool = datatype_pool->next;
    }

    *ret = TR_DATATYPE_INIT;
    return ret;
}

static void
datatype_free( struct tr_datatype * datatype )
{
    datatype->next = datatype_pool;
    datatype_pool = datatype;
}

static void
peer_io_pull_datatype( tr_peerIo * io )
{
    struct tr_datatype * tmp;

    if(( tmp = io->outbuf_datatypes ))
    {
        io->outbuf_datatypes = tmp->next;
        datatype_free( tmp );
    }
}

static void
peer_io_push_datatype( tr_peerIo * io, struct tr_datatype * datatype )
{
    struct tr_datatype * tmp;

    if(( tmp = io->outbuf_datatypes )) {
        while( tmp->next != NULL )
            tmp = tmp->next;
        tmp->next = datatype;
    } else {
        io->outbuf_datatypes = datatype;
    }
}

static struct tr_datatype *
addDatatype( tr_peerIo * io, size_t byteCount, size_t overhead, bool isPieceData )
{
    struct tr_datatype * d;
    d = datatype_new( );
    d->isPieceData = isPieceData != 0;
    d->length = byteCount;
    d->overhead = overhead;
    peer_io_push_datatype( io, d );
    return d;
}

/***
****
***/

static void
didWriteWrapper( tr_peerIo * io, unsigned int bytes_transferred )
{
     while( bytes_transferred && tr_isPeerIo( io ) )
     {
        struct tr_datatype * next = io->outbuf_datatypes;

        const unsigned int overhead_transferred = MIN( next->overhead, bytes_transferred );
        const unsigned int payload = MIN( next->length, bytes_transferred - overhead_transferred );
        /* For uTP sockets, the overhead is computed in utp_on_overhead. */
        const unsigned int overhead = overhead_transferred +
            io->socket ? guessPacketOverhead( payload ) : 0;
        const uint64_t now = tr_time_msec( );

        dbgmsg( io, "didWrite %u bytes overhead and %u bytes payload", overhead_transferred, payload );

        if( payload > 0 )
            tr_bandwidthUsed( &io->bandwidth, TR_UP, payload, next->isPieceData, now );

        if( overhead > 0 )
            tr_bandwidthUsed( &io->bandwidth, TR_UP, overhead, false, now );

        if( io->didWrite && payload )
            io->didWrite( io, payload, next->isPieceData, io->userData );

        if( tr_isPeerIo( io ) )
        {
            bytes_transferred -= payload + overhead_transferred;
            next->overhead -= overhead_transferred;
            next->length -= payload;

            if( !next->length && !next->overhead )
                peer_io_pull_datatype( io );
        }
    }
}

static void
canReadWrapper( tr_peerIo * io )
{
    bool err = 0;
    bool done = 0;
    tr_session * session;

    dbgmsg( io, "canRead" );

    tr_peerIoRef( io );

    session = io->session;

    /* try to consume the input buffer */
    if( io->canRead )
    {
        const uint64_t now = tr_time_msec( );

        tr_sessionLock( session );

        while( !done && !err )
        {
            size_t piece = 0;
            const size_t oldLen = evbuffer_get_length( io->inbuf );
            const int ret = io->canRead( io, io->userData, &piece );
            const size_t used = oldLen - evbuffer_get_length( io->inbuf );
            const unsigned int overhead = guessPacketOverhead( used );

            if( piece || (piece!=used) )
            {
                if( piece )
                    tr_bandwidthUsed( &io->bandwidth, TR_DOWN, piece, true, now );

                if( used != piece )
                    tr_bandwidthUsed( &io->bandwidth, TR_DOWN, used - piece, false, now );
            }

            if( overhead > 0 )
                tr_bandwidthUsed( &io->bandwidth, TR_UP, overhead, false, now );

            switch( ret )
            {
                case READ_NOW:
                    if( evbuffer_get_length( io->inbuf ) )
                        continue;
                    done = 1;
                    break;

                case READ_LATER:
                    done = 1;
                    break;

                case READ_ERR:
                    err = 1;
                    break;
            }

            assert( tr_isPeerIo( io ) );
        }

        tr_sessionUnlock( session );
    }

    tr_peerIoUnref( io );
}

static int
tlsDoRead( tr_peerIo * io, unsigned int * const howmuch )
{
    unsigned int bytesread = 0;
    int res;
    size_t outbuf_len = evbuffer_get_length( io->outbuf );

    do
    {
        unsigned char pc;

        res = SSL_peek( io->tls, &pc, 1 );

        if ( res == 1 )
        {
            struct evbuffer_iovec iov[2];
            int iov_given;
            unsigned int howmuchnow = (unsigned)SSL_pending( io->tls );
            howmuchnow = MIN( *howmuch - bytesread, howmuchnow );

            iov_given = evbuffer_reserve_space( io->inbuf, howmuchnow, iov, 2 );

            res = SSL_read( io->tls, iov[0].iov_base, MIN( howmuchnow, iov[0].iov_len ) );
            bytesread += res;
            if ( iov_given == 2 && res == (int)iov[0].iov_len )
            {
                res = SSL_read( io->tls, iov[1].iov_base, howmuchnow - iov[0].iov_len );
                iov[1].iov_len = res;
                bytesread += res;
            }
            else
            {
                iov[0].iov_len = res;
            }

            evbuffer_commit_space( io->inbuf, iov, iov_given );
        }
    } while ( res > 0 && bytesread < *howmuch );

    outbuf_len = evbuffer_get_length( io->outbuf ) - outbuf_len;

    if ( outbuf_len )
    {
        dbgmsg( io, "wrote %zu bytes while reading", outbuf_len );
        if ( io->outbuf_datatypes )
            io->outbuf_datatypes->overhead += outbuf_len;
        else
            addDatatype( io, 0, outbuf_len, false );
    }

    *howmuch = bytesread;

    return res;
}

static size_t tlsWriteBuffer( tr_peerIo * io, struct evbuffer * buf );

static void tlsTryWritePending( tr_peerIo * io )
{
    const size_t outbuf_len = evbuffer_get_length( io->outbuf );
    size_t bytes_written = tlsWriteBuffer( io, io->outbuf_pending );

    dbgmsg( io, "wrote %zu deferred bytes", bytes_written );

    /* Charge the overhead to the first pending datatype. Not entirely fair
        but this should happen infrequently enough for it not to matter. */
    io->outbuf_pending_datatype->overhead += evbuffer_get_length( io->outbuf ) - outbuf_len - bytes_written;

    evbuffer_drain( io->outbuf_pending, bytes_written );
    if ( evbuffer_get_length( io->outbuf_pending ) == 0 )
    {
        evbuffer_free( io->outbuf_pending );
        io->outbuf_pending = NULL;
        io->outbuf_pending_datatype = NULL;
        io->outbuf_pending_datatype_bytes = 0;
    }
    else
    {
        while ( bytes_written )
        {
            size_t datatype_bytes_written = MIN( io->outbuf_pending_datatype_bytes, bytes_written );
            io->outbuf_pending_datatype_bytes -= datatype_bytes_written;
            bytes_written -= datatype_bytes_written;
            if ( io->outbuf_pending_datatype_bytes == 0 )
            {
                io->outbuf_pending_datatype = io->outbuf_pending_datatype->next;
                io->outbuf_pending_datatype_bytes = io->outbuf_pending_datatype->length;
            }
        }
    }
}

static unsigned int
tlsCanRead( tr_peerIo * io, unsigned int howmuch )
{
    int res;
    int e;
    size_t curlen = evbuffer_get_length( io->inbuf );
    char errstr[512];
    short what = BEV_EVENT_READING;

    res = tlsDoRead( io, &howmuch );
    e = SSL_get_error( io->tls, res );

    if ( ( res > 0 || e == SSL_ERROR_WANT_READ ) && io->outbuf_pending )
    {
        /* Writes have been held up waiting for read data so try
        to write them out now that we've gotten some. */
        tlsTryWritePending( io );
    }

    if ( res > 0 )
    {
        tr_peerIoSetEnabled( io, TR_DOWN, true );
        canReadWrapper( io );
    }
    else
    {
        unsigned long error;

        if( res == 0 ) /* EOF */
            what |= BEV_EVENT_EOF;

        /* SSL_ERROR_WANT_WRITE never happens because writes are bufferd in the io's outbuf */
        if ( e == SSL_ERROR_WANT_READ )
        {
            tr_peerIoSetEnabled( io, TR_DOWN, true );

            if ( evbuffer_get_length( io->inbuf ) > curlen )
                /* Invoke the user callback - must always be called last */
                canReadWrapper( io );
            return res;
        }
        what |= BEV_EVENT_ERROR;

        error = ERR_get_error();
        ERR_error_string_n( error, errstr, 512 );

        dbgmsg( io, "tlsCanRead got an error. res is %d, what is %hd, errno is %lu (%s)",
                res, what, error, errstr );

        if( io->gotError != NULL )
            io->gotError( io, what, io->userData );
    }

    return howmuch;
}

static void
event_read_cb( int fd, short event UNUSED, void * vio )
{
    int res;
    int e;
    tr_peerIo * io = vio;

    /* Limit the input buffer to 256K, so it doesn't grow too large */
    unsigned int howmuch;
    unsigned int curlen;
    const tr_direction dir = TR_DOWN;
    const unsigned int max = 256 * 1024;

    assert( tr_isPeerIo( io ) );
    assert( io->socket >= 0 );

    io->pendingEvents &= ~EV_READ;

    curlen = evbuffer_get_length( io->inbuf );
    howmuch = curlen >= max ? 0 : max - curlen;
    howmuch = tr_bandwidthClamp( &io->bandwidth, TR_DOWN, howmuch );

    dbgmsg( io, "libevent says this peer is ready to read" );

    /* if we don't have any bandwidth left, stop reading */
    if( howmuch < 1 ) {
        tr_peerIoSetEnabled( io, dir, false );
        return;
    }

    if ( io->tls )
    {
        tlsCanRead( io, howmuch );
    }
    else
    {
        EVUTIL_SET_SOCKET_ERROR( 0 );
        res = evbuffer_read( io->inbuf, fd, (int)howmuch );
        e = EVUTIL_SOCKET_ERROR( );

        if( res > 0 )
        {
            tr_peerIoSetEnabled( io, dir, true );

            /* Invoke the user callback - must always be called last */
            canReadWrapper( io );
        }
        else
        {
            char errstr[512];
            short what = BEV_EVENT_READING;

            if( res == 0 ) /* EOF */
                what |= BEV_EVENT_EOF;
            else if( res == -1 ) {
                if( e == EAGAIN || e == EINTR ) {
                    tr_peerIoSetEnabled( io, dir, true );
                    return;
                }
                what |= BEV_EVENT_ERROR;
            }

            dbgmsg( io, "event_read_cb got an error. res is %d, what is %hd, errno is %d (%s)",
                    res, what, e, tr_net_strerror( errstr, sizeof( errstr ), e ) );

            if( io->gotError != NULL )
                io->gotError( io, what, io->userData );
        }
    }
}

static int
tr_evbuffer_write( tr_peerIo * io, int fd, size_t howmuch )
{
    int e;
    int n;
    char errstr[256];

    EVUTIL_SET_SOCKET_ERROR( 0 );
    n = evbuffer_write_atmost( io->outbuf, fd, howmuch );
    e = EVUTIL_SOCKET_ERROR( );
    dbgmsg( io, "wrote %d to peer (%s)", n, (n==-1?tr_net_strerror(errstr,sizeof(errstr),e):"") );

    return n;
}

static void
event_write_cb( int fd, short event UNUSED, void * vio )
{
    int res = 0;
    int e;
    short what = BEV_EVENT_WRITING;
    tr_peerIo * io = vio;
    size_t howmuch;
    const tr_direction dir = TR_UP;
    char errstr[1024];

    assert( tr_isPeerIo( io ) );
    assert( io->socket >= 0 );

    io->pendingEvents &= ~EV_WRITE;

    dbgmsg( io, "libevent says this peer is ready to write" );

    /* Write as much as possible, since the socket is non-blocking, write() will
     * return if it can't write any more data without blocking */
    howmuch = tr_bandwidthClamp( &io->bandwidth, dir, evbuffer_get_length( io->outbuf ) );

    /* if we don't have any bandwidth left, stop writing */
    if( howmuch < 1 ) {
        tr_peerIoSetEnabled( io, dir, false );
        return;
    }

    EVUTIL_SET_SOCKET_ERROR( 0 );
    res = tr_evbuffer_write( io, fd, howmuch );
    e = EVUTIL_SOCKET_ERROR( );

    if (res == -1) {
        if (!e || e == EAGAIN || e == EINTR || e == EINPROGRESS)
            goto reschedule;
        /* error case */
        what |= BEV_EVENT_ERROR;
    } else if (res == 0) {
        /* eof case */
        what |= BEV_EVENT_EOF;
    }
    if (res <= 0)
        goto error;

    if( evbuffer_get_length( io->outbuf ) )
        tr_peerIoSetEnabled( io, dir, true );

    didWriteWrapper( io, res );
    return;

 reschedule:
    if( evbuffer_get_length( io->outbuf ) )
        tr_peerIoSetEnabled( io, dir, true );
    return;

 error:

    tr_net_strerror( errstr, sizeof( errstr ), e );
    dbgmsg( io, "event_write_cb got an error. res is %d, what is %hd, errno is %d (%s)", res, what, e, errstr );

    if( io->gotError != NULL )
        io->gotError( io, what, io->userData );
}

/**
***
**/

static void
maybeSetCongestionAlgorithm( int socket, const char * algorithm )
{
    if( algorithm && *algorithm )
    {
        const int rc = tr_netSetCongestionControl( socket, algorithm );

        if( rc < 0 )
            tr_ninf( "Net", "Can't set congestion control algorithm '%s': %s",
                     algorithm, tr_strerror( errno ));
    }
}

#ifdef WITH_UTP
/* UTP callbacks */

static void
utp_on_read(void *closure, const unsigned char *buf, size_t buflen)
{
    tr_peerIo *io = closure;
    assert( tr_isPeerIo( io ) );

    dbgmsg( io, "utp_on_read reading %zu bytes...", buflen );

    if ( io->tls )
    {
        int res;
        initBioReadBuf( SSL_get_rbio( io->tls ), buf, buflen );
        res = tlsCanRead( io, UINT_MAX );
        if ( res > 0 && tr_isPeerIo( io ) )
        {
            assert( BIO_pending( SSL_get_rbio( io->tls ) ) == 0 );
        }
     }
    else
    {
        int rc = evbuffer_add( io->inbuf, buf, buflen );

        if( rc < 0 ) {
            tr_nerr( "UTP", "On read evbuffer_add" );
            return;
        }

        tr_peerIoSetEnabled( io, TR_DOWN, true );
        canReadWrapper( io );
    }

}

static void
utp_on_write(void *closure, unsigned char *buf, size_t buflen)
{
    int rc;
    tr_peerIo *io = closure;
    assert( tr_isPeerIo( io ) );

    rc = evbuffer_remove( io->outbuf, buf, buflen );
    dbgmsg( io, "utp_on_write sending %zu bytes... evbuffer_remove returned %d", buflen, rc );
    assert( rc == (int)buflen ); /* if this fails, we've corrupted our bookkeeping somewhere */
    if( rc < (long)buflen ) {
        tr_nerr( "UTP", "Short write: %d < %ld", rc, (long)buflen);
    }

    didWriteWrapper( io, buflen );
}

static size_t
utp_get_rb_size(void *closure)
{
    size_t bytes;
    tr_peerIo *io = closure;
    assert( tr_isPeerIo( io ) );

    bytes = tr_bandwidthClamp( &io->bandwidth, TR_DOWN, UTP_READ_BUFFER_SIZE );

    dbgmsg( io, "utp_get_rb_size is saying it's ready to read %zu bytes", bytes );
    return UTP_READ_BUFFER_SIZE - bytes;
}

static void
utp_on_state_change(void *closure, int state)
{
    tr_peerIo *io = closure;
    assert( tr_isPeerIo( io ) );

    if( state == UTP_STATE_CONNECT ) {
        dbgmsg( io, "utp_on_state_change -- changed to connected" );
        io->utpSupported = true;
    } else if( state == UTP_STATE_WRITABLE ) {
        dbgmsg( io, "utp_on_state_change -- changed to writable" );
    } else if( state == UTP_STATE_EOF ) {
        if( io->gotError )
            io->gotError( io, BEV_EVENT_EOF, io->userData );
    } else if( state == UTP_STATE_DESTROYING ) {
        tr_nerr( "UTP", "Impossible state UTP_STATE_DESTROYING" );
        return;
    } else {
        tr_nerr( "UTP", "Unknown state %d", state );
    }
}

static void
utp_on_error(void *closure, int errcode)
{
    tr_peerIo *io = closure;
    assert( tr_isPeerIo( io ) );

    dbgmsg( io, "utp_on_error -- errcode is %d", errcode );

    if( io->gotError ) {
        errno = errcode;
        io->gotError( io, BEV_EVENT_ERROR, io->userData );
    }
}

static void
utp_on_overhead(void *closure, bool send, size_t count, int type UNUSED)
{
    tr_peerIo *io = closure;
    assert( tr_isPeerIo( io ) );

    dbgmsg( io, "utp_on_overhead -- count is %zu", count );

    tr_bandwidthUsed( &io->bandwidth, send ? TR_UP : TR_DOWN,
                      count, false, tr_time_msec() );
}

static struct UTPFunctionTable utp_function_table = {
    .on_read = utp_on_read,
    .on_write = utp_on_write,
    .get_rb_size = utp_get_rb_size,
    .on_state = utp_on_state_change,
    .on_error = utp_on_error,
    .on_overhead = utp_on_overhead
};


/* Dummy UTP callbacks. */
/* We switch a UTP socket to use these after the associated peerIo has been
   destroyed -- see io_dtor. */

static void
dummy_read( void * closure UNUSED, const unsigned char *buf UNUSED, size_t buflen UNUSED )
{
    /* This cannot happen, as far as I'm aware. */
    tr_nerr( "UTP", "On_read called on closed socket" );

}

static void
dummy_write(void * closure UNUSED, unsigned char *buf, size_t buflen)
{
    /* This can very well happen if we've shut down a peer connection that
       had unflushed buffers.  Complain and send zeroes. */
    tr_ndbg( "UTP", "On_write called on closed socket" );
    memset( buf, 0, buflen );
}

static size_t
dummy_get_rb_size( void * closure UNUSED )
{
    return 0;
}

static void
dummy_on_state_change(void * closure UNUSED, int state UNUSED )
{
    return;
}

static void
dummy_on_error( void * closure UNUSED, int errcode UNUSED )
{
    return;
}

static void
dummy_on_overhead( void *closure UNUSED, bool send UNUSED, size_t count UNUSED, int type UNUSED )
{
    return;
}

static struct UTPFunctionTable dummy_utp_function_table = {
    .on_read = dummy_read,
    .on_write = dummy_write,
    .get_rb_size = dummy_get_rb_size,
    .on_state = dummy_on_state_change,
    .on_error = dummy_on_error,
    .on_overhead = dummy_on_overhead
};

#endif /* #ifdef WITH_UTP */

static tr_peerIo*
tr_peerIoNew( tr_session       * session,
              tr_bandwidth     * parent,
              const tr_address * addr,
              tr_port            port,
              const uint8_t    * torrentHash,
              bool               isIncoming,
              bool               isSeed,
              int                socket,
              struct UTPSocket * utp_socket)
{
    tr_peerIo * io;

    assert( session != NULL );
    assert( session->events != NULL );
    assert( tr_isBool( isIncoming ) );
    assert( tr_isBool( isSeed ) );
    assert( tr_amInEventThread( session ) );
    assert( (socket < 0) == (utp_socket != NULL) );
#ifndef WITH_UTP
    assert( socket >= 0 );
#endif

    if( socket >= 0 ) {
        tr_netSetTOS( socket, session->peerSocketTOS );
        maybeSetCongestionAlgorithm( socket, session->peer_congestion_algorithm );
    }

    io = tr_new0( tr_peerIo, 1 );
    io->magicNumber = PEER_IO_MAGIC_NUMBER;
    io->refCount = 1;
    tr_cryptoConstruct( &io->crypto, torrentHash, isIncoming );
    io->session = session;
    io->addr = *addr;
    io->isSeed = isSeed;
    io->port = port;
    io->socket = socket;
    io->utp_socket = utp_socket;
    io->isIncoming = isIncoming != 0;
    io->timeCreated = tr_time( );
    io->inbuf = evbuffer_new( );
    io->outbuf = evbuffer_new( );
    tr_bandwidthConstruct( &io->bandwidth, session, parent );
    tr_bandwidthSetPeer( &io->bandwidth, io );
    dbgmsg( io, "bandwidth is %p; its parent is %p", &io->bandwidth, parent );
    dbgmsg( io, "socket is %d, utp_socket is %p", socket, utp_socket );

    if( io->socket >= 0 ) {
        io->event_read = event_new( session->event_base,
                                    io->socket, EV_READ, event_read_cb, io );
        io->event_write = event_new( session->event_base,
                                     io->socket, EV_WRITE, event_write_cb, io );
    }
#ifdef WITH_UTP
    else {
        UTP_SetSockopt( utp_socket, SO_RCVBUF, UTP_READ_BUFFER_SIZE );
        dbgmsg( io, "%s", "calling UTP_SetCallbacks &utp_function_table" );
        UTP_SetCallbacks( utp_socket,
                          &utp_function_table,
                          io );
        if( !isIncoming ) {
            dbgmsg( io, "%s", "calling UTP_Connect" );
            UTP_Connect( utp_socket );
        }
    }
#endif

    return io;
}

tr_peerIo*
tr_peerIoNewIncoming( tr_session        * session,
                      tr_bandwidth      * parent,
                      const tr_address  * addr,
                      tr_port             port,
                      int                 fd,
                      struct UTPSocket  * utp_socket )
{
    assert( session );
    assert( tr_address_is_valid( addr ) );

    return tr_peerIoNew( session, parent, addr, port, NULL, true, false,
                         fd, utp_socket );
}

tr_peerIo*
tr_peerIoNewOutgoing( tr_session        * session,
                      tr_bandwidth      * parent,
                      const tr_address  * addr,
                      tr_port             port,
                      const uint8_t     * torrentHash,
                      bool                isSeed,
                      bool                utp )
{
    int fd = -1;
    struct UTPSocket * utp_socket = NULL;

    assert( session );
    assert( tr_address_is_valid( addr ) );
    assert( torrentHash );

    if( utp )
        utp_socket = tr_netOpenPeerUTPSocket( session, addr, port, isSeed );

    if( !utp_socket ) {
        fd = tr_netOpenPeerSocket( session, addr, port, isSeed );
        dbgmsg( NULL, "tr_netOpenPeerSocket returned fd %d", fd );
    }

    if( fd < 0 && utp_socket == NULL )
        return NULL;

    return tr_peerIoNew( session, parent, addr, port,
                         torrentHash, false, isSeed, fd, utp_socket );
}

/***
****
***/

static void
event_enable( tr_peerIo * io, short event )
{
    assert( tr_amInEventThread( io->session ) );
    assert( io->session != NULL );
    assert( io->session->events != NULL );

    if( io->socket < 0 )
        return;

    assert( io->session->events != NULL );
    assert( event_initialized( io->event_read ) );
    assert( event_initialized( io->event_write ) );

    if( ( event & EV_READ ) && ! ( io->pendingEvents & EV_READ ) )
    {
        dbgmsg( io, "enabling libevent ready-to-read polling" );
        event_add( io->event_read, NULL );
        io->pendingEvents |= EV_READ;
    }

    if( ( event & EV_WRITE ) && ! ( io->pendingEvents & EV_WRITE ) )
    {
        dbgmsg( io, "enabling libevent ready-to-write polling" );
        event_add( io->event_write, NULL );
        io->pendingEvents |= EV_WRITE;
    }
}

static void
event_disable( struct tr_peerIo * io, short event )
{
    assert( tr_amInEventThread( io->session ) );
    assert( io->session != NULL );

    if( io->socket < 0 )
        return;

    assert( io->session->events != NULL );
    assert( event_initialized( io->event_read ) );
    assert( event_initialized( io->event_write ) );

    if( ( event & EV_READ ) && ( io->pendingEvents & EV_READ ) )
    {
        dbgmsg( io, "disabling libevent ready-to-read polling" );
        event_del( io->event_read );
        io->pendingEvents &= ~EV_READ;
    }

    if( ( event & EV_WRITE ) && ( io->pendingEvents & EV_WRITE ) )
    {
        dbgmsg( io, "disabling libevent ready-to-write polling" );
        event_del( io->event_write );
        io->pendingEvents &= ~EV_WRITE;
    }
}

void
tr_peerIoSetEnabled( tr_peerIo    * io,
                     tr_direction   dir,
                     bool           isEnabled )
{
    const short event = dir == TR_UP ? EV_WRITE : EV_READ;

    assert( tr_isPeerIo( io ) );
    assert( tr_isDirection( dir ) );
    assert( tr_amInEventThread( io->session ) );
    assert( io->session->events != NULL );

    if( isEnabled )
        event_enable( io, event );
    else
        event_disable( io, event );
}

/***
****
***/
static void
io_close_socket( tr_peerIo * io )
{
    if( io->socket >= 0 ) {
        tr_netClose( io->session, io->socket );
        io->socket = -1;
    }

    if( io->event_read != NULL) {
        event_free( io->event_read );
        io->event_read = NULL;
    }

    if( io->event_write != NULL) {
        event_free( io->event_write );
        io->event_write = NULL;
    }

#ifdef WITH_UTP
    if( io->utp_socket ) {
        UTP_SetCallbacks( io->utp_socket,
                          &dummy_utp_function_table,
                          NULL );
        UTP_Close( io->utp_socket );

        io->utp_socket = NULL;
    }
#endif
}

static void
io_dtor( void * vio )
{
    tr_peerIo * io = vio;

    assert( tr_isPeerIo( io ) );
    assert( tr_amInEventThread( io->session ) );
    assert( io->session->events != NULL );

    dbgmsg( io, "in tr_peerIo destructor" );
    event_disable( io, EV_READ | EV_WRITE );
    tr_bandwidthDestruct( &io->bandwidth );
    evbuffer_free( io->outbuf );
    evbuffer_free( io->inbuf );
    if ( io->outbuf_pending )
        evbuffer_free( io->outbuf_pending );
    io_close_socket( io );
    tr_cryptoDestruct( &io->crypto );
    SSL_free( io->tls );

    while( io->outbuf_datatypes != NULL )
        peer_io_pull_datatype( io );

    memset( io, ~0, sizeof( tr_peerIo ) );
    tr_free( io );
}

static void
tr_peerIoFree( tr_peerIo * io )
{
    if( io )
    {
        dbgmsg( io, "in tr_peerIoFree" );
        io->canRead = NULL;
        io->didWrite = NULL;
        io->gotError = NULL;
        tr_runInEventThread( io->session, io_dtor, io );
    }
}

void
tr_peerIoRefImpl( const char * file, int line, tr_peerIo * io )
{
    assert( tr_isPeerIo( io ) );

    dbgmsg( io, "%s:%d is incrementing the IO's refcount from %d to %d",
                file, line, io->refCount, io->refCount+1 );

    ++io->refCount;
}

void
tr_peerIoUnrefImpl( const char * file, int line, tr_peerIo * io )
{
    assert( tr_isPeerIo( io ) );

    dbgmsg( io, "%s:%d is decrementing the IO's refcount from %d to %d",
                file, line, io->refCount, io->refCount-1 );

    if( !--io->refCount )
        tr_peerIoFree( io );
}

const tr_address*
tr_peerIoGetAddress( const tr_peerIo * io, tr_port   * port )
{
    assert( tr_isPeerIo( io ) );

    if( port )
        *port = io->port;

    return &io->addr;
}

const char*
tr_peerIoAddrStr( const tr_address * addr, tr_port port )
{
    static char buf[512];
    tr_snprintf( buf, sizeof( buf ), "[%s]:%u", tr_address_to_string( addr ), ntohs( port ) );
    return buf;
}

const char* tr_peerIoGetAddrStr( const tr_peerIo * io )
{
    return tr_isPeerIo( io ) ? tr_peerIoAddrStr( &io->addr, io->port ) : "error";
}

void
tr_peerIoSetIOFuncs( tr_peerIo        * io,
                     tr_can_read_cb     readcb,
                     tr_did_write_cb    writecb,
                     tr_net_error_cb    errcb,
                     void             * userData )
{
    io->canRead = readcb;
    io->didWrite = writecb;
    io->gotError = errcb;
    io->userData = userData;
}

void
tr_peerIoClear( tr_peerIo * io )
{
    tr_peerIoSetIOFuncs( io, NULL, NULL, NULL, NULL );
    tr_peerIoSetEnabled( io, TR_UP, false );
    tr_peerIoSetEnabled( io, TR_DOWN, false );
}

int
tr_peerIoReconnect( tr_peerIo * io )
{
    short int pendingEvents;
    tr_session * session;

    assert( tr_isPeerIo( io ) );
    assert( !tr_peerIoIsIncoming( io ) );

    session = tr_peerIoGetSession( io );

    pendingEvents = io->pendingEvents;
    event_disable( io, EV_READ | EV_WRITE );

    io_close_socket( io );

    io->socket = tr_netOpenPeerSocket( session, &io->addr, io->port, io->isSeed );
    io->event_read = event_new( session->event_base, io->socket, EV_READ, event_read_cb, io );
    io->event_write = event_new( session->event_base, io->socket, EV_WRITE, event_write_cb, io );

    if( io->socket >= 0 )
    {
        event_enable( io, pendingEvents );
        tr_netSetTOS( io->socket, session->peerSocketTOS );
        maybeSetCongestionAlgorithm( io->socket, session->peer_congestion_algorithm );
        return 0;
    }

    return -1;
}

/**
***
**/

void
tr_peerIoSetTorrentHash( tr_peerIo *     io,
                         const uint8_t * hash )
{
    assert( tr_isPeerIo( io ) );

    tr_cryptoSetTorrentHash( &io->crypto, hash );
}

const uint8_t*
tr_peerIoGetTorrentHash( tr_peerIo * io )
{
    assert( tr_isPeerIo( io ) );

    return tr_cryptoGetTorrentHash( &io->crypto );
}

int
tr_peerIoHasTorrentHash( const tr_peerIo * io )
{
    assert( tr_isPeerIo( io ) );

    return tr_cryptoHasTorrentHash( &io->crypto );
}

/**
***
**/

void
tr_peerIoSetPeersId( tr_peerIo * io, const uint8_t * peer_id )
{
    assert( tr_isPeerIo( io ) );

    if( ( io->peerIdIsSet = peer_id != NULL ) )
        memcpy( io->peerId, peer_id, 20 );
    else
        memset( io->peerId, 0, 20 );
}

bool tr_peerIoGetCreditId( const tr_peerIo * io, uint8_t * buf )
{
    X509 * peer_cert;

    if ( !io->tls )
        return false;

    peer_cert = SSL_get_peer_certificate( io->tls );
    X509_pubkey_digest(peer_cert, EVP_sha1(), buf, NULL);

    return true;
}

/**
***
**/

static unsigned int
getDesiredOutputBufferSize( const tr_peerIo * io, uint64_t now )
{
    /* this is all kind of arbitrary, but what seems to work well is
     * being large enough to hold the next 20 seconds' worth of input,
     * or a few blocks, whichever is bigger.
     * It's okay to tweak this as needed */
    const unsigned int currentSpeed_Bps = tr_bandwidthGetPieceSpeed_Bps( &io->bandwidth, now, TR_UP );
    const unsigned int period = 15u; /* arbitrary */
    /* the 3 is arbitrary; the .5 is to leave room for messages */
    static const unsigned int ceiling =  (unsigned int)( MAX_BLOCK_SIZE * 3.5 );
    return MAX( ceiling, currentSpeed_Bps*period );
}

size_t
tr_peerIoGetWriteBufferSpace( const tr_peerIo * io, uint64_t now )
{
    const size_t desiredLen = getDesiredOutputBufferSize( io, now );
    const size_t currentLen = evbuffer_get_length( io->outbuf );
    size_t freeSpace = 0;

    if( desiredLen > currentLen )
        freeSpace = desiredLen - currentLen;

    return freeSpace;
}

/**
***
**/

void
tr_peerIoSetEncryption( tr_peerIo * io, tr_encryption_type encryption_type )
{
    assert( tr_isPeerIo( io ) );
    assert( encryption_type == PEER_ENCRYPTION_NONE
         || encryption_type == PEER_ENCRYPTION_RC4 );

    io->encryption_type = encryption_type;

    if ( io->tls )
    {
        SSL_free( io->tls );
        io->tls = NULL;
    }
}

int
tr_peerIoSetTlsEncryption( tr_peerIo * io, SSL * tls )
{
    int res = 1;
    BIO * io_bio;

    assert( tr_isPeerIo( io ) );

    if ( io->tls )
    {
        SSL_free( io->tls );
    }

    io->encryption_type = PEER_ENCRYPTION_NONE;
    io->tls = tls;

    /* The TLS handshake has already been completed so any
       data currently in the inbuf is TLS records with application data.
       Use a memory BIO to feed the data to the TLS object. */
    if ( evbuffer_get_length( io->inbuf ) )
    {
        unsigned int howmuch = UINT_MAX;
        BIO * inbio = BIO_new( BIO_s_mem() );
        struct evbuffer_ptr pos;
        struct evbuffer_iovec iovec;

        evbuffer_ptr_set( io->inbuf, &pos, 0, EVBUFFER_PTR_SET );
        SSL_set_bio( tls, inbio, NULL );

        do {
            evbuffer_peek( io->inbuf, -1, &pos, &iovec, 1 );
            BIO_write( inbio, iovec.iov_base, iovec.iov_len );
        } while( !evbuffer_ptr_set( io->inbuf, &pos, iovec.iov_len, EVBUFFER_PTR_ADD ) );

        evbuffer_drain( io->inbuf, BIO_ctrl_pending( inbio ) );
        res = tlsDoRead( io, &howmuch );
    }

    io_bio = getBio( io );

    if ( !io->utp_socket )
    {
        SSL_set_bio( tls, NULL, io_bio );
        SSL_set_rfd( tls, io->socket );
    }
    else
        SSL_set_bio( tls, io_bio, io_bio );

    return res;
}

/**
***
**/

static void
maybeEncryptBuffer( tr_peerIo * io, struct evbuffer * buf )
{
    if( io->encryption_type == PEER_ENCRYPTION_RC4 )
    {
        struct evbuffer_ptr pos;
        struct evbuffer_iovec iovec;
        evbuffer_ptr_set( buf, &pos, 0, EVBUFFER_PTR_SET );
        do {
            evbuffer_peek( buf, -1, &pos, &iovec, 1 );
            tr_cryptoEncrypt( &io->crypto, iovec.iov_len, iovec.iov_base, iovec.iov_base );
        } while( !evbuffer_ptr_set( buf, &pos, iovec.iov_len, EVBUFFER_PTR_ADD ) );
    }
}

static size_t
tlsWriteBuffer( tr_peerIo * io, struct evbuffer * buf )
{
    struct evbuffer_ptr pos;
    struct evbuffer_iovec iovec;
    int res;
    int e;
    size_t bytesWritten = 0;

    evbuffer_ptr_set( buf, &pos, 0, EVBUFFER_PTR_SET );
    do {
        evbuffer_peek( buf, -1, &pos, &iovec, 1 );
        res = SSL_write( io->tls, iovec.iov_base, iovec.iov_len );
        e = SSL_get_error( io->tls, res );

        if ( e == SSL_ERROR_WANT_READ )
            tr_peerIoSetEnabled( io, TR_DOWN, true );
        if ( res > 0 )
            bytesWritten += res;
    } while( res > 0 && !evbuffer_ptr_set( buf, &pos, iovec.iov_len, EVBUFFER_PTR_ADD ) );

    return bytesWritten;
}

void
tr_peerIoWriteBuf( tr_peerIo * io, struct evbuffer * buf, bool isPieceData )
{
    const size_t byteCount = evbuffer_get_length( buf );
    size_t overhead = 0;

    if ( io->tls )
    {
        struct tr_datatype * datatype;
        size_t bytesWritten;

        if ( !io->outbuf_pending )
        {
            overhead = evbuffer_get_length( io->outbuf );
            bytesWritten = tlsWriteBuffer( io, buf );
            overhead = evbuffer_get_length( io->outbuf ) - overhead - bytesWritten;
            evbuffer_drain( buf, bytesWritten );
        }

        datatype = addDatatype( io, byteCount, overhead, isPieceData );

        if ( evbuffer_get_length( buf ) )
        {
            if ( !io->outbuf_pending )
            {
                io->outbuf_pending = evbuffer_new();
                io->outbuf_pending_datatype = datatype;
                io->outbuf_pending_datatype_bytes = byteCount - bytesWritten;
            }
            dbgmsg( io, "deferring write of %zu bytes", io->outbuf_pending_datatype_bytes );
            evbuffer_add_buffer( io->outbuf_pending, buf );
        }
    }
    else
    {
        maybeEncryptBuffer( io, buf );
        evbuffer_add_buffer( io->outbuf, buf );
        addDatatype( io, byteCount, overhead, isPieceData );
    }
}

void
tr_peerIoWriteBytes( tr_peerIo * io, const void * bytes, size_t byteCount, bool isPieceData )
{
    struct evbuffer_iovec iovec;
    size_t overhead = 0;

    if ( io->tls )
    {
        struct tr_datatype * datatype;
        int res;
        int e;
        overhead = evbuffer_get_length( io->outbuf );
        res = SSL_write(io->tls, bytes, byteCount);
        e = SSL_get_error( io->tls, res );
        overhead = evbuffer_get_length( io->outbuf ) - overhead - byteCount;

        datatype = addDatatype( io, byteCount, overhead, isPieceData );

        if ( e == SSL_ERROR_WANT_READ )
            tr_peerIoSetEnabled( io, TR_DOWN, true );

        if ( res > 0 && (unsigned)res < byteCount )
        {
            if ( !io->outbuf_pending )
            {
                io->outbuf_pending = evbuffer_new();
                io->outbuf_pending_datatype = datatype;
                io->outbuf_pending_datatype_bytes = byteCount - res;
            }
            evbuffer_add( io->outbuf_pending, (const unsigned char*)bytes + res, byteCount - res );
        }

    }
    else
    {
        evbuffer_reserve_space( io->outbuf, byteCount, &iovec, 1 );

        iovec.iov_len = byteCount;
        if( io->encryption_type == PEER_ENCRYPTION_RC4 )
            tr_cryptoEncrypt( &io->crypto, iovec.iov_len, bytes, iovec.iov_base );
        else
            memcpy( iovec.iov_base, bytes, iovec.iov_len );
        evbuffer_commit_space( io->outbuf, &iovec, 1 );
        addDatatype( io, byteCount, overhead, isPieceData );
    }
}

/***
****
***/

void
evbuffer_add_uint8( struct evbuffer * outbuf, uint8_t byte )
{
    evbuffer_add( outbuf, &byte, 1 );
}

void
evbuffer_add_uint16( struct evbuffer * outbuf, uint16_t addme_hs )
{
    const uint16_t ns = htons( addme_hs );
    evbuffer_add( outbuf, &ns, sizeof( ns ) );
}

void
evbuffer_add_uint32( struct evbuffer * outbuf, uint32_t addme_hl )
{
    const uint32_t nl = htonl( addme_hl );
    evbuffer_add( outbuf, &nl, sizeof( nl ) );
}

void
evbuffer_add_uint64( struct evbuffer * outbuf, uint64_t addme_hll )
{
    const uint64_t nll = tr_htonll( addme_hll );
    evbuffer_add( outbuf, &nll, sizeof( nll ) );
}

/***
****
***/

void
tr_peerIoReadBytesToBuf( tr_peerIo * io, struct evbuffer * inbuf, struct evbuffer * outbuf, size_t byteCount )
{
    struct evbuffer * tmp;
    const size_t old_length = evbuffer_get_length( outbuf );

    assert( tr_isPeerIo( io ) );
    assert( evbuffer_get_length( inbuf ) >= byteCount );

    /* append it to outbuf */
    tmp = evbuffer_new( );
    evbuffer_remove_buffer( inbuf, tmp, byteCount );
    evbuffer_add_buffer( outbuf, tmp );
    evbuffer_free( tmp );

    /* decrypt if needed */
    if( io->encryption_type == PEER_ENCRYPTION_RC4 ) {
        struct evbuffer_ptr pos;
        struct evbuffer_iovec iovec;
        evbuffer_ptr_set( outbuf, &pos, old_length, EVBUFFER_PTR_SET );
        do {
            evbuffer_peek( outbuf, byteCount, &pos, &iovec, 1 );
            tr_cryptoDecrypt( &io->crypto, iovec.iov_len, iovec.iov_base, iovec.iov_base );
            byteCount -= iovec.iov_len;
        } while( !evbuffer_ptr_set( outbuf, &pos, iovec.iov_len, EVBUFFER_PTR_ADD ) );
    }
}

void
tr_peerIoReadBytes( tr_peerIo * io, struct evbuffer * inbuf, void * bytes, size_t byteCount )
{
    assert( tr_isPeerIo( io ) );
    assert( evbuffer_get_length( inbuf )  >= byteCount );

    switch( io->encryption_type )
    {
        case PEER_ENCRYPTION_NONE:
            evbuffer_remove( inbuf, bytes, byteCount );
            break;

        case PEER_ENCRYPTION_RC4:
            evbuffer_remove( inbuf, bytes, byteCount );
            tr_cryptoDecrypt( &io->crypto, byteCount, bytes, bytes );
            break;

        default:
            assert( 0 );
    }
}

void
tr_peerIoReadUint16( tr_peerIo        * io,
                     struct evbuffer  * inbuf,
                     uint16_t         * setme )
{
    uint16_t tmp;
    tr_peerIoReadBytes( io, inbuf, &tmp, sizeof( uint16_t ) );
    *setme = ntohs( tmp );
}

void tr_peerIoReadUint32( tr_peerIo        * io,
                          struct evbuffer  * inbuf,
                          uint32_t         * setme )
{
    uint32_t tmp;
    tr_peerIoReadBytes( io, inbuf, &tmp, sizeof( uint32_t ) );
    *setme = ntohl( tmp );
}

void
tr_peerIoDrain( tr_peerIo       * io,
                struct evbuffer * inbuf,
                size_t            byteCount )
{
    char buf[4096];
    const size_t buflen = sizeof( buf );

    while( byteCount > 0 )
    {
        const size_t thisPass = MIN( byteCount, buflen );
        tr_peerIoReadBytes( io, inbuf, buf, thisPass );
        byteCount -= thisPass;
    }
}

/***
****
***/

static int
tr_peerIoTryRead( tr_peerIo * io, size_t howmuch )
{
    int res = 0;

    if(( howmuch = tr_bandwidthClamp( &io->bandwidth, TR_DOWN, howmuch )))
    {
        if( io->utp_socket != NULL ) /* utp peer connection */
        {
            /* UTP_RBDrained notifies libutp that your read buffer is emtpy.
             * It opens up the congestion window by sending an ACK (soonish)
             * if one was not going to be sent. */
            if( evbuffer_get_length( io->inbuf ) == 0 )
                UTP_RBDrained( io->utp_socket );
        }
        else if ( io->tls ) /* tls peer connection */
        {
            res = tlsCanRead( io, howmuch );
        }
        else /* tcp peer connection */
        {
            int e;

            EVUTIL_SET_SOCKET_ERROR( 0 );
            res = evbuffer_read( io->inbuf, io->socket, (int)howmuch );
            e = EVUTIL_SOCKET_ERROR( );

            dbgmsg( io, "read %d from peer (%s)", res, (res==-1?tr_strerror(e):"") );

            if( evbuffer_get_length( io->inbuf ) )
                canReadWrapper( io );

            if( ( res <= 0 ) && ( io->gotError ) && ( e != EAGAIN ) && ( e != EINTR ) && ( e != EINPROGRESS ) )
            {
                char errstr[512];
                short what = BEV_EVENT_READING | BEV_EVENT_ERROR;
                if( res == 0 )
                    what |= BEV_EVENT_EOF;
                dbgmsg( io, "tr_peerIoTryRead got an error. res is %d, what is %hd, errno is %d (%s)",
                        res, what, e, tr_net_strerror( errstr, sizeof( errstr ), e ) );
                io->gotError( io, what, io->userData );
            }
        }
    }

    return res;
}

static int
tr_peerIoTryWrite( tr_peerIo * io, size_t howmuch )
{
    int n = 0;
    const size_t old_len = evbuffer_get_length( io->outbuf );
    dbgmsg( io, "in tr_peerIoTryWrite %zu", howmuch );

    if( howmuch > old_len )
        howmuch = old_len;

    if(( howmuch = tr_bandwidthClamp( &io->bandwidth, TR_UP, howmuch )))
    {
        if( io->utp_socket != NULL ) /* utp peer connection */
        {
            const size_t old_len = evbuffer_get_length( io->outbuf );
            UTP_Write( io->utp_socket, howmuch );
            n = old_len - evbuffer_get_length( io->outbuf );
        }
        else
        {
            int e;

            EVUTIL_SET_SOCKET_ERROR( 0 );
            n = tr_evbuffer_write( io, io->socket, howmuch );
            e = EVUTIL_SOCKET_ERROR( );

            if( n > 0 )
                didWriteWrapper( io, n );

            if( ( n < 0 ) && ( io->gotError ) && e && ( e != EPIPE ) && ( e != EAGAIN ) && ( e != EINTR ) && ( e != EINPROGRESS ) )
            {
                char errstr[512];
                const short what = BEV_EVENT_WRITING | BEV_EVENT_ERROR;

                dbgmsg( io, "tr_peerIoTryWrite got an error. res is %d, what is %hd, errno is %d (%s)",
                        n, what, e, tr_net_strerror( errstr, sizeof( errstr ), e ) );

                if( io->gotError != NULL )
                    io->gotError( io, what, io->userData );
            }
        }
    }

    return n;
}

int
tr_peerIoFlush( tr_peerIo  * io, tr_direction dir, size_t limit )
{
    int bytesUsed = 0;

    assert( tr_isPeerIo( io ) );
    assert( tr_isDirection( dir ) );

    if( dir == TR_DOWN )
        bytesUsed = tr_peerIoTryRead( io, limit );
    else
        bytesUsed = tr_peerIoTryWrite( io, limit );

    dbgmsg( io, "flushing peer-io, direction %d, limit %zu, bytesUsed %d", (int)dir, limit, bytesUsed );
    return bytesUsed;
}

int
tr_peerIoFlushOutgoingProtocolMsgs( tr_peerIo * io )
{
    size_t byteCount = 0;
    const struct tr_datatype * it;

    /* count up how many bytes are used by non-piece-data messages
       at the front of our outbound queue */
    for( it=io->outbuf_datatypes; it!=NULL; it=it->next )
        if( it->isPieceData )
            break;
        else
            byteCount += it->length + it->overhead;

    return tr_peerIoFlush( io, TR_UP, byteCount );
}
