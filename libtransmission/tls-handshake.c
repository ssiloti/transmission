/*
 * Copyright (c) 2012 by Steven Siloti
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * $Id$
 */

#include <openssl/err.h>
#include <event2/buffer.h>

#include "tls-handshake.h"
#include "peer-io.h"
#include "session.h"
#include "utils.h"
#include "log.h"

struct tr_sslhandshake
{
    tr_peerIo           * io;
    SSL                 * tls;
    sslhandshakeDoneCB    doneCB;
    void                * doneUserData;
};

/**
***
**/

#define dbgmsg(io, ...) \
  do \
    { \
      if (tr_logGetDeepEnabled ()) \
        tr_logAddDeep (__FILE__, __LINE__, tr_peerIoGetAddrStr (io), __VA_ARGS__); \
    } \
  while (0)

/**
***
**/

/* BIO interface for tr_peerIo. */

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
    struct evbuffer *input;

    BIO_clear_retry_flags( b );

    if ( !out )
        return 0;
    if ( !b->ptr )
        return -1;

    input = tr_peerIoGetReadBuffer( b->ptr );
    r = evbuffer_get_length( input );
    if ( r == 0 )
    {
        /* If there's no data to read, say so. */
        BIO_set_retry_read( b );
        return -1;
    }
    else
    {
        r = MIN( r, outlen );
        tr_peerIoReadBytes( b->ptr, input, out, r );
    }

    return r;
}

/* Called to write data info the BIO */
static int
bio_peerio_write(BIO *b, const char *in, int inlen)
{
    BIO_clear_retry_flags( b );

    if ( !b->ptr )
        return -1;

    assert( inlen > 0 );
    tr_peerIoWriteBytes( b->ptr, in, inlen, false );
    return inlen;
}

/* Called to handle various requests */
static long
bio_peerio_ctrl(BIO *b, int cmd, long num, void *ptr UNUSED)
{
    struct tr_peerIo *io = b->ptr;
    long ret = 1;

    switch (cmd) {
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_PENDING:
        ret = evbuffer_get_length( tr_peerIoGetReadBuffer( io ) ) != 0;
        break;
    case BIO_CTRL_WPENDING:
        ret = evbuffer_get_length( tr_peerIoGetWriteBuffer( io ) ) != 0;
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

#define BIO_TYPE_TR_PEERIO 59

/* Method table for the peerio BIO */
static BIO_METHOD methods_peerio = {
    BIO_TYPE_TR_PEERIO, "tr_peerIo",
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
    b->ptr = io;
    b->init = 1;
    return b;
}

/**
***
**/

static ReadState
canRead( struct tr_peerIo * io,
         void             * user_data,
         size_t           * setme_piece_byte_count )
{
    tr_sslhandshake * handshake = user_data;
    int handshake_result = SSL_do_handshake( handshake->tls );

    dbgmsg( io, "Attempted to complete TLS handshake, got %d", handshake_result );

    *setme_piece_byte_count = 0;

    if (ERR_get_error())
    {
        ( *handshake->doneCB )( handshake, io, false, handshake->doneUserData );
        return READ_ERR;
    }

    if (handshake_result == 1)
    {
        handshake_result = tr_peerIoSetTlsEncryption( io, handshake->tls );
        handshake->tls = NULL;
        ( *handshake->doneCB )( handshake, io, handshake_result > 0, handshake->doneUserData );
    }

    return READ_NOW;
}

static void
gotError( struct tr_peerIo * io, short what UNUSED, void * userData )
{
    tr_sslhandshake * handshake = userData;
    ( *handshake->doneCB )( handshake, io, false, handshake->doneUserData );
}

tr_sslhandshake *
tr_sslhandshakeNew( struct tr_peerIo * io,
                    sslhandshakeDoneCB doneCB,
                    void *             doneUserData )
{
    tr_sslhandshake * h;
    BIO * b;

    h = tr_new0( tr_sslhandshake, 1 );
    h->io = io;
    h->doneCB = doneCB;
    h->doneUserData = doneUserData;

    h->tls = SSL_new( tr_sessionGetTlsContext( tr_peerIoGetSession( io ) ) );
    b = getBio( io );
    SSL_set_bio( h->tls, b, b );

    tr_peerIoSetIOFuncs( io, canRead, NULL, gotError, h );
    /* For now always send the TLS handshake in cleartext
       Support for obfuscated handshaking could be added via an option in
       the starttls message */
    tr_peerIoSetEncryption( io, PEER_ENCRYPTION_NONE );

    if ( tr_peerIoIsIncoming( io ) )
        SSL_accept( h->tls );
    else
        SSL_connect( h->tls );

    return h;
}

void tr_sslhandshakeFree( struct tr_sslhandshake * handshake )
{
    SSL_free( handshake->tls );
    tr_free( handshake );
}
