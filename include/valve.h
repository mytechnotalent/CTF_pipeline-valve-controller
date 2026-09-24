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
// File:    valve.h
// Desc:    Declares the pipeline valve state machine that sequences the
//          SG90 actuator and fails closed on loss of authority.
// Created: 2026

#ifndef VALVE_H
#define VALVE_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Bounded valve travel time in milliseconds.
 */
#define VALVE_TRAVEL_MS 1000u

/**
 * @brief Pipeline valve position and health states.
 */
typedef enum valve_state {
    /**
     * @brief Valve is seated closed, the safe line state.
     */
    VALVE_STATE_CLOSED = 0,
    /**
     * @brief Valve is held fully open.
     */
    VALVE_STATE_OPEN = 1,
    /**
     * @brief Valve has failed closed and is latched in fault.
     */
    VALVE_STATE_FAULT = 2,
    /**
     * @brief Valve actuator is travelling between positions.
     */
    VALVE_STATE_MOVING = 3,
} valve_state_t;

/**
 * @brief Initialize the valve state machine and seat the valve closed.
 *
 * @param void No parameters.
 * @return void
 */
void valve_init(void);

/**
 * @brief Return the current valve state.
 *
 * @param void No parameters.
 * @return valve_state_t Current valve state.
 */
valve_state_t valve_state(void);

/**
 * @brief Report whether the valve is currently fully open.
 *
 * @param void No parameters.
 * @return bool true when the valve is open.
 */
bool valve_is_open(void);

/**
 * @brief Apply an authorized open or close command to the valve.
 *
 * Unauthorized commands are refused. An authorized command starts a
 * bounded travel interval that valve_tick completes. This is the guarded
 * command path that replaces the unauthenticated angle injection.
 *
 * @param open True to drive the valve open, false to drive it closed.
 * @param authorized True when the caller has validated the command.
 * @return void
 */
void valve_apply_command(bool open, bool authorized);

/**
 * @brief Advance the valve state machine by one tick.
 *
 * Completes a pending travel once the bounded interval has elapsed.
 *
 * @param void No parameters.
 * @return void
 */
void valve_tick(void);

/**
 * @brief Force the valve closed and latch a fault.
 *
 * @param void No parameters.
 * @return void
 */
void valve_fail_closed(void);

#endif // VALVE_H
