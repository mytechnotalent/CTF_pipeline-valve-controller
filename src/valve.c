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
// File:    valve.c
// Desc:    Implements the pipeline valve state machine that sequences the
//          SG90 actuator and fails closed on loss of authority.
// Created: 2026

#include "pico/time.h"
#include "valve.h"
#include "servo.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Current valve position and health state.
 */
static valve_state_t g_valve_state;

/**
 * @brief Pending travel target, true when the valve is opening.
 */
static bool g_valve_target_open;

/**
 * @brief Absolute time in microseconds when the pending travel completes.
 */
static uint64_t g_valve_move_until_us;

/**
 * @brief Complete a pending travel by driving the actuator.
 *
 * @param void No parameters.
 * @return void
 */
static void valve_complete(void) {
    if (g_valve_target_open) {
        valve_open();
        g_valve_state = VALVE_STATE_OPEN;
        return;
    }
    valve_close();
    g_valve_state = VALVE_STATE_CLOSED;
}

void valve_init(void) {
    g_valve_target_open = false;
    g_valve_state = VALVE_STATE_CLOSED;
    valve_close();
}

valve_state_t valve_state(void) {
    return g_valve_state;
}

bool valve_is_open(void) {
    return g_valve_state == VALVE_STATE_OPEN;
}

void valve_apply_command(bool open, bool authorized) {
    if (!authorized) {
        return;
    }
    g_valve_target_open = open;
    g_valve_state = VALVE_STATE_MOVING;
    g_valve_move_until_us = time_us_64() + (uint64_t)VALVE_TRAVEL_MS * 1000u;
}

void valve_tick(void) {
    if (g_valve_state != VALVE_STATE_MOVING) {
        return;
    }
    if (time_us_64() < g_valve_move_until_us) {
        return;
    }
    valve_complete();
}

void valve_fail_closed(void) {
    valve_close();
    g_valve_target_open = false;
    g_valve_state = VALVE_STATE_FAULT;
}
