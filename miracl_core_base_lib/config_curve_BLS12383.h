/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file config_curve.h
 * @author Mike Scott
 * @brief Config Curve  Header File
 *
 */

#ifndef CONFIG_CURVE_BLS12383_H
#define CONFIG_CURVE_BLS12383_H

#include"core.h"
#include"config_field_BLS12383.h"

// ECP stuff

#define CURVETYPE_BLS12383 WEIERSTRASS          /**< Define Curve Type */
#define CURVE_A_BLS12383 0            /**< Curve A parameter */
#define PAIRING_FRIENDLY_BLS12383 BLS12_CURVE   /**< Is curve pairing-friendly */
#define CURVE_SECURITY_BLS12383 128     /**< Curve security level in AES bits */
#define HTC_ISO_BLS12383 0            /**< Use Isogenies for Hash to Curve */

// Permit alternate compression method if 3 spare top bits in field representation
// Must be set manually
//#define ALLOW_ALT_COMPRESS_BLS12383

#if PAIRING_FRIENDLY_BLS12383 != NOT_PF

#define HTC_ISO_G2_BLS12383 0        /**< Use Isogenies for G2 Hash to Curve */
#define USE_GLV_BLS12383     /**< Note this method is patented (GLV), so maybe you want to comment this out */
#define USE_GS_G2_BLS12383 /**< Well we didn't patent it :) But may be covered by GLV patent :( */
#define USE_GS_GT_BLS12383 /**< Not patented, so probably OK to always use this */

#define POSITIVEX 0
#define NEGATIVEX 1

#define SEXTIC_TWIST_BLS12383 M_TYPE       /**< Sextic Twist M or D type */
#define SIGN_OF_X_BLS12383 POSITIVEX          /**< Sign of curve parameter */ 

#define ATE_BITS_BLS12383 65           /**< Number of Bits in curve parameter */
#define G2_TABLE_BLS12383 68           /**< Size of table for pairing precomputation for fixed G2 */

#endif

#if CURVE_SECURITY_BLS12383 == 128
#define AESKEY_BLS12383 16 /**< Symmetric Key size - 128 bits */
#define HASH_TYPE_BLS12383 SHA256  /**< Hash type */
#endif

#if CURVE_SECURITY_BLS12383 == 192
#define AESKEY_BLS12383 24 /**< Symmetric Key size - 192 bits */
#define HASH_TYPE_BLS12383 SHA384  /**< Hash type */
#endif

#if CURVE_SECURITY_BLS12383 == 256
#define AESKEY_BLS12383 32 /**< Symmetric Key size - 256 bits */
#define HASH_TYPE_BLS12383 SHA512  /**< Hash type */
#endif



#endif
