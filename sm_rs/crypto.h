//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include "sha3/sha3.h"
#include "ed25519/ed25519.h"
#include "hkdf_sha3_512/hkdf_sha3_512.h"

typedef sha3_ctx_t hash_ctx;
#define MDSIZE  64

#define SIGNATURE_SIZE  64
#define PRIVATE_KEY_SIZE  64 // includes public key
#define PUBLIC_KEY_SIZE 32

typedef unsigned char byte;

#endif /* crypto.h */
