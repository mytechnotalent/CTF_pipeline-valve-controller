// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/pipeline-valve-controller
// File:    control.c
// Desc:    Implements the sealed valve command path that opens, authorizes,
//          and applies remote SCADA commands with a guarded command set.
// Created: 2026

#include "control.h"
#include "valve_auth.h"
#include "valve.h"
#include "envelope.h"
#include "pipeline_valve.h"
#include "crypto_aead.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Derived field key used to open sealed command envelopes.
 */
static uint8_t g_control_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been installed.
 */
static bool g_control_key_ready;

/**
 * @brief Anti-replay authorization record for remote commands.
 */
static valve_auth_t g_control_auth;

/**
 * @brief Read one 32-bit little-endian value.
 *
 * @param p Pointer to four little-endian bytes.
 * @return uint32_t Decoded value.
 */
static uint32_t control_get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

/**
 * @brief Parse a recovered command body into sequence, tag, and command.
 *
 * The command byte is range checked against the guarded open and close
 * set so no raw angle or out-of-set value can reach the actuator.
 *
 * @param pt Pointer to the recovered command plaintext.
 * @param len Number of recovered plaintext bytes.
 * @param seq Pointer to store the little-endian sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param open Pointer to store the decoded open or close command.
 * @return bool true when the body is well formed and in the guarded set.
 */
static bool control_parse(const uint8_t *pt, size_t len, uint32_t *seq,
                          uint8_t tag[CRYPTO_AEAD_TAG_LEN], bool *open) {
    if (pt == NULL || seq == NULL || open == NULL || len < CONTROL_COMMAND_LEN) {
        return false;
    }
    if (pt[4] > VALVE_COMMAND_OPEN) {
        return false;
    }
    *seq = control_get_u32(pt);
    *open = (pt[4] == VALVE_COMMAND_OPEN);
    memcpy(tag, pt + 5u, CRYPTO_AEAD_TAG_LEN);
    return true;
}

/**
 * @brief Open one sealed command envelope under the field key.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param pt Pointer to the plaintext output buffer.
 * @param len Pointer to store the recovered plaintext length.
 * @return bool true when the envelope authenticated and opened.
 */
static bool control_open(const char *hex, uint8_t *pt, size_t *len) {
    uint8_t ad = (uint8_t)VALVE_NODE_ID;
    if (!g_control_key_ready || hex == NULL) {
        return false;
    }
    return envelope_open_hex(g_control_key, &ad, 1u, hex, pt,
                             ENVELOPE_MAX_PLAINTEXT, len);
}

/**
 * @brief Open and parse one sealed command envelope.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param seq Pointer to store the recovered sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param open Pointer to store the decoded open or close command.
 * @return bool true when the envelope opened and the body parsed.
 */
static bool control_decode(const char *hex, uint32_t *seq,
                           uint8_t tag[CRYPTO_AEAD_TAG_LEN], bool *open) {
    uint8_t pt[ENVELOPE_MAX_PLAINTEXT];
    size_t len;
    if (!control_open(hex, pt, &len)) {
        return false;
    }
    return control_parse(pt, len, seq, tag, open);
}

void control_init(void) {
    g_control_key_ready = false;
    memset(g_control_key, 0, sizeof(g_control_key));
    valve_auth_init(&g_control_auth);
    valve_auth_set_key(NULL);
}

void control_deinit(void) {
    g_control_key_ready = false;
    valve_auth_set_key(NULL);
}

bool control_set_key(const uint8_t key[CRYPTO_AEAD_KEY_LEN]) {
    if (key == NULL) {
        control_deinit();
        return false;
    }
    memcpy(g_control_key, key, CRYPTO_AEAD_KEY_LEN);
    g_control_key_ready = true;
    valve_auth_set_key(g_control_key);
    return true;
}

bool control_authorize(uint32_t seq, const uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    return valve_auth_apply(&g_control_auth, seq, tag);
}

bool control_handle_frame(const char *hex) {
    uint32_t seq;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    bool open;
    if (!control_decode(hex, &seq, tag, &open)) return false;
    if (!control_authorize(seq, tag)) return false;
    valve_apply_command(open, true);
    return true;
}
