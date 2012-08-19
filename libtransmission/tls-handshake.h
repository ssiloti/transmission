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

#ifndef __TRANSMISSION__
#error only libtransmission should #include this header.
#endif

#ifndef TR_SSL_HANDSHAKE_H
#define TR_SSL_HANDSHAKE_H

#include "peer-common.h"

struct tr_peerIo;

typedef struct tr_sslhandshake tr_sslhandshake;

typedef void ( *sslhandshakeDoneCB )( struct tr_sslhandshake * handshake,
                                      struct tr_peerIo       * io,
                                      bool                     isOk,
                                      void                   * userData );

tr_sslhandshake *   tr_sslhandshakeNew( struct tr_peerIo * io,
                                        sslhandshakeDoneCB doneCB,
                                        void *             doneUserData );

void tr_sslhandshakeFree( struct tr_sslhandshake * handshake );

#endif
