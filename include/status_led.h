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
// File:    status_led.h
// Desc:    Declares the red, yellow, and green SCADA valve state annunciator.
// Created: 2026

#ifndef STATUS_LED_H
#define STATUS_LED_H

#include "pipeline_valve.h"
#include <stdbool.h>

/**
 * @brief Tri-color SCADA valve state annunciator states.
 */
typedef enum valve_led_state {
    /**
     * @brief All status LEDs dark.
     */
    VALVE_OFF = 0,
    /**
     * @brief Red LED lit for a valve fault or failed-closed latch.
     */
    VALVE_FAULT = 1,
    /**
     * @brief Yellow LED lit while a command is pending or the valve moves.
     */
    VALVE_PENDING = 2,
    /**
     * @brief Green LED lit while the valve is nominal.
     */
    VALVE_NOMINAL = 3,
} valve_led_state_t;

/**
 * @brief Initialize the tri-color status LED GPIO pins.
 *
 * @param void No parameters.
 * @return bool true when initialization completed.
 */
bool status_led_init(void);

/**
 * @brief Drive exactly one annunciator lamp for a valve state.
 *
 * @param state Desired annunciator state.
 * @return void
 */
void status_led_show(valve_led_state_t state);

#endif // STATUS_LED_H
