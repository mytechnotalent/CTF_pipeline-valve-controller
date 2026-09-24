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
// File:    monitor.h
// Desc:    Declares the SCADA valve controller state machine tying the
//          operator remote, sealed command path, process sensor, and
//          ESTOP input together.
// Created: 2026

#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Infrared operator remote command code that opens the valve.
 */
#define MONITOR_IR_OPEN 0x47u

/**
 * @brief Infrared operator remote command code that closes the valve.
 */
#define MONITOR_IR_CLOSE 0x45u

/**
 * @brief Infrared operator remote command code for emergency stop.
 */
#define MONITOR_IR_ESTOP 0x46u

/**
 * @brief Number of monitor ticks between onboard heartbeat toggles.
 */
#define MONITOR_HEARTBEAT_TICKS 4u

/**
 * @brief Initialize the SCADA valve controller state machine.
 *
 * Configures the I2C LCD, the DHT11 process sensor, the infrared operator
 * remote, the annunciator LEDs, the valve servo, the ESTOP button, the
 * RYLR998 radio, and derives the Argon2id field key.
 *
 * @param void No parameters.
 * @return bool true when all submodules initialized.
 */
bool monitor_init(void);

/**
 * @brief Clear the controller-ready flag and command path.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_deinit(void);

/**
 * @brief Clear the latched emergency stop so operation can resume.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_clear_estop(void);

/**
 * @brief Execute one SCADA valve controller tick.
 *
 * Polls the operator remote and the radio, applies the emergency stop
 * with highest priority, verifies and applies sealed valve commands,
 * drives the LEDs and valve, and renders the SCADA status.
 *
 * @param void No parameters.
 * @return bool true when the tick completed without a policy error.
 */
bool monitor_step(void);

#endif // MONITOR_H
