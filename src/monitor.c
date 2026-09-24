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
// File:    monitor.c
// Desc:    Implements the SCADA valve controller state machine that ties
//          the operator remote, the sealed command path, the process
//          sensor, the ESTOP input, and the RYLR998 gateway link together.
// Created: 2026

#include "pipeline_valve.h"
#include "monitor.h"
#include "sensor.h"
#include "display.h"
#include "radio.h"
#include "status_led.h"
#include "button.h"
#include "servo.h"
#include "ir_remote.h"
#include "valve.h"
#include "control.h"
#include "implant.h"
#include "crypto_aead.h"
#include "crypto_kdf.h"
#include "field_secrets.h"
#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "pico/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Module-ready flag.
 */
static bool g_ready;

/**
 * @brief Initialized I2C peripheral handle for the LCD backpack.
 */
static i2c_inst_t *g_i2c;

/**
 * @brief Initialized I2C backpack address for the LCD.
 */
static uint8_t g_i2c_addr;

/**
 * @brief Derived XChaCha20-Poly1305 field key for the gateway link.
 */
static uint8_t g_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been derived and installed.
 */
static bool g_key_ready;

/**
 * @brief True while the emergency stop is latched.
 */
static bool g_estop_latched;

/**
 * @brief True once a sealed gateway command has been accepted.
 */
static bool g_link_seen;

/**
 * @brief Absolute time in microseconds of the last accepted gateway command.
 */
static uint64_t g_last_rx_us;

/**
 * @brief Last observed process sensor in-range verdict.
 */
static bool g_proc_ok;

/**
 * @brief First LCD SCADA render line buffer.
 */
static char g_line1[DISPLAY_LINE_LEN];

/**
 * @brief Second LCD SCADA render line buffer.
 */
static char g_line2[DISPLAY_LINE_LEN];

/**
 * @brief Inbound radio line accumulator.
 */
static char g_rx_line[RADIO_LINE_BUF_LEN];

/**
 * @brief Number of bytes currently held in the inbound line accumulator.
 */
static size_t g_rx_len;

/**
 * @brief Count of monitor ticks since the last onboard heartbeat toggle.
 */
static uint32_t g_heartbeat_ticks;

/**
 * @brief Current onboard heartbeat LED level.
 */
static bool g_heartbeat_level;

/**
 * @brief Count of live status lines printed since boot.
 */
static uint32_t g_status_count;

/**
 * @brief Probe one I2C address and report whether it acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to probe.
 * @param addr The 7-bit address to probe.
 * @return bool true when the address acknowledged.
 */
static bool i2c_probe(i2c_inst_t *i2c, uint8_t addr) {
    uint8_t dummy = 0u;
    if (i2c_write_blocking(i2c, addr, &dummy, 1u, false) < 0) {
        return false;
    }
    printf("  found 0x%02X\n", (unsigned)addr);
    return true;
}

/**
 * @brief Probe the I2C bus and print every device that acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to scan.
 * @return void
 */
static void i2c_bus_scan(i2c_inst_t *i2c) {
    uint8_t addr;
    uint8_t found = 0u;
    printf("I2C scan:\n");
    for (addr = 0x08u; addr < 0x78u; ++addr) {
        found += i2c_probe(i2c, addr) ? 1u : 0u;
    }
    if (found == 0u) {
        printf("  no devices\n");
    }
}

/**
 * @brief Initialize the I2C bus pins and scan the bus.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_bus_init(void) {
    i2c_init(VALVE_I2C, VALVE_I2C_BAUD);
    gpio_set_function(VALVE_I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(VALVE_I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(VALVE_I2C_SDA);
    gpio_pull_up(VALVE_I2C_SCL);
    i2c_bus_scan(VALVE_I2C);
}

/**
 * @brief Configure the onboard heartbeat LED.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_gpio_init(void) {
    gpio_init(VALVE_LED_PIN);
    gpio_set_dir(VALVE_LED_PIN, GPIO_OUT);
    gpio_put(VALVE_LED_PIN, 0);
}

/**
 * @brief Toggle the onboard GP25 heartbeat LED on its interval.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_heartbeat(void) {
    g_heartbeat_ticks += 1u;
    if (g_heartbeat_ticks < MONITOR_HEARTBEAT_TICKS) {
        return;
    }
    g_heartbeat_ticks = 0u;
    g_heartbeat_level = !g_heartbeat_level;
    gpio_put(VALVE_LED_PIN, g_heartbeat_level);
}

/**
 * @brief Clear every latched controller state flag.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_clear_state(void) {
    g_estop_latched = false;
    g_link_seen = false;
    g_last_rx_us = 0u;
    g_proc_ok = false;
}

/**
 * @brief Initialize the LED, LCD handles, and controller state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init(void) {
    monitor_gpio_init();
    g_i2c = VALVE_I2C;
    g_i2c_addr = VALVE_LCD_ADDR;
    monitor_clear_state();
    valve_init();
    g_ready = true;
}

/**
 * @brief Initialize the human interface and actuator peripherals.
 *
 * @param void No parameters.
 * @return bool true when the LEDs, ESTOP, servo, and infrared eye ready.
 */
static bool monitor_peripherals_init(void) {
    return status_led_init() && estop_init() && servo_init() &&
           ir_remote_init();
}

/**
 * @brief Initialize the SANDBOX_ONLY implant when it is compiled in.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_implant_init(void) {
#ifdef SANDBOX_ONLY
    implant_init();
#endif
}

/**
 * @brief Derive the field key from the committed lab secret.
 *
 * LAB-ONLY: production must provision the field key through OTP rather
 * than deriving it from a committed passphrase and salt.
 *
 * @param void No parameters.
 * @return bool true when the field key was derived and installed.
 */
static bool monitor_derive_key(void) {
    bool ok = crypto_kdf_argon2id((const uint8_t *)FIELD_SECRET_PASSPHRASE,
                                  strlen(FIELD_SECRET_PASSPHRASE),
                                  FIELD_SECRET_SALT, 16u, g_key);
    g_key_ready = ok;
    control_set_key(ok ? g_key : NULL);
    return ok;
}

/**
 * @brief Print the boot banner and the interactive control hint.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_banner(void) {
    printf("=== OPERATION IRON VEIN // ACT III SCADA PIPELINE ===\n");
    printf("REMOTE: CH+ 0x47 open | CH- 0x45 close | CH 0x46 estop\n");
    printf("BUTTON: GP15 emergency stop\n");
}

/**
 * @brief Bring up the controller state and command path.
 *
 * @param void No parameters.
 * @return bool true when the field key was installed.
 */
static bool monitor_start(void) {
    bool ok;
    monitor_state_init();
    control_init();
    monitor_implant_init();
    ok = monitor_derive_key();
    if (ok) {
        monitor_banner();
    }
    return ok;
}

bool monitor_init(void) {
    monitor_bus_init();
    if (!monitor_peripherals_init() || !sensor_init() ||
        !radio_init(VALVE_UART) ||
        !display_init(VALVE_I2C, VALVE_LCD_ADDR)) {
        printf("INIT FAIL\n");
        return false;
    }
    return monitor_start();
}

void monitor_deinit(void) {
    g_ready = false;
    control_deinit();
}

void monitor_clear_estop(void) {
    g_estop_latched = false;
    estop_reset();
}

/**
 * @brief Map a valve state to its annunciator lamp.
 *
 * @param state Valve state to map.
 * @return valve_led_state_t Annunciator state for the valve.
 */
static valve_led_state_t monitor_led_for(valve_state_t state) {
    if (state == VALVE_STATE_FAULT) return VALVE_FAULT;
    if (state == VALVE_STATE_MOVING) return VALVE_PENDING;
    return VALVE_NOMINAL;
}

/**
 * @brief Render a valve state as a short SCADA label.
 *
 * @param state Valve state to render.
 * @return const char* NUL-terminated state label.
 */
static const char *monitor_state_text(valve_state_t state) {
    if (state == VALVE_STATE_OPEN) return "OPEN";
    if (state == VALVE_STATE_MOVING) return "MOVING";
    if (state == VALVE_STATE_FAULT) return "FAULT";
    return "CLOSED";
}

/**
 * @brief Print one live status line for the interactive console.
 *
 * @param reading Pointer to the decoded DHT11 process reading.
 * @return void
 */
static void monitor_log_reading(const dht_reading_t *reading) {
    g_status_count += 1u;
    printf("PROCESS t=%d h=%u ok=%d ST=%s n=%u\n",
           (int)reading->temperature_tenths, (unsigned)reading->humidity_tenths,
           (int)g_proc_ok, monitor_state_text(valve_state()),
           (unsigned)g_status_count);
}

/**
 * @brief Render the SCADA status and alarm lines to the 1602 LCD.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_render(void) {
    snprintf(g_line1, DISPLAY_LINE_LEN, "ST:%-6s",
             monitor_state_text(valve_state()));
    snprintf(g_line2, DISPLAY_LINE_LEN, "PROC:%s LNK:%s",
             g_proc_ok ? "OK" : "BAD", g_link_seen ? "UP" : "--");
    display_render_lines(g_i2c, g_i2c_addr, g_line1, g_line2);
}

/**
 * @brief Sample the DHT11 process sensor and classify it.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_refresh_process(void) {
    dht_reading_t reading;
    if (sensor_read(&reading) != SENSOR_RESULT_OK) {
        g_proc_ok = false;
        printf("SENSOR read failed -> WARNING\n");
        return;
    }
    g_proc_ok = process_ok(&reading);
    monitor_log_reading(&reading);
}

/**
 * @brief Consume one debounced ESTOP press and latch the fault.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_estop(void) {
    if (!estop_consume_press()) {
        return;
    }
    printf("BUTTON emergency stop -> valve fault\n");
    g_estop_latched = true;
    valve_fail_closed();
}

/**
 * @brief Latch the emergency stop and force the valve closed.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_trigger_estop(void) {
    g_estop_latched = true;
    valve_fail_closed();
}

/**
 * @brief Apply an infrared OPEN or CLOSE command to the valve.
 *
 * @param command Decoded infrared command code.
 * @return void
 */
static void monitor_apply_ir_valve(uint8_t command) {
    if (command == MONITOR_IR_OPEN) {
        valve_apply_command(true, true);
        return;
    }
    if (command == MONITOR_IR_CLOSE) {
        valve_apply_command(false, true);
    }
}

/**
 * @brief Map a decoded remote command to its name.
 *
 * @param command Decoded NEC command byte.
 * @return const char* Command name string.
 */
static const char *monitor_ir_name(uint8_t command) {
    if (command == MONITOR_IR_OPEN) return "OPEN";
    if (command == MONITOR_IR_CLOSE) return "CLOSE";
    if (command == MONITOR_IR_ESTOP) return "ESTOP";
    return "UNKNOWN";
}

/**
 * @brief Apply one decoded infrared operator command.
 *
 * @param cmd Pointer to the decoded infrared command.
 * @return void
 */
static void monitor_apply_ir_command(const ir_command_t *cmd) {
    printf("IR %s (0x%02X)\n", monitor_ir_name(cmd->command),
           (unsigned)cmd->command);
    if (g_estop_latched) {
        return;
    }
    if (cmd->command == MONITOR_IR_ESTOP) {
        monitor_trigger_estop();
        return;
    }
    monitor_apply_ir_valve(cmd->command);
}

/**
 * @brief Poll the infrared eye for an operator command.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_ir(void) {
    ir_command_t cmd;
    if (!ir_remote_poll(&cmd)) {
        return;
    }
    monitor_apply_ir_command(&cmd);
}

/**
 * @brief Feed an inbound frame to the SANDBOX_ONLY implant when compiled in.
 *
 * @param hex Pointer to the inbound frame text.
 * @param len Number of inbound frame bytes.
 * @return void
 */
static void monitor_implant_frame(const char *hex, size_t len) {
#ifdef SANDBOX_ONLY
    implant_handle_command((const uint8_t *)hex, len);
#else
    (void)hex;
    (void)len;
#endif
}

/**
 * @brief Verify and apply one inbound gateway frame.
 *
 * @param hex Pointer to the inbound frame text.
 * @param len Number of inbound frame bytes.
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_apply_frame(const char *hex, size_t len, uint64_t now_us) {
    monitor_implant_frame(hex, len);
    if (g_estop_latched) {
        return;
    }
    if (!control_handle_frame(hex)) {
        return;
    }
    g_link_seen = true;
    g_last_rx_us = now_us;
}

/**
 * @brief Drain inbound radio lines and apply any sealed command.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_rx_tick(uint64_t now_us) {
    radio_rcv_t rcv;
    while (radio_line_pump(VALVE_UART, g_rx_line, &g_rx_len)) {
        if (radio_parse_rcv(g_rx_line, &rcv) == RADIO_RESULT_OK) {
            printf("RX from 0x%04X, %u bytes\n", (unsigned)rcv.sender,
                   (unsigned)rcv.len);
            monitor_apply_frame(rcv.payload, rcv.len, now_us);
        }
    }
}

/**
 * @brief Fail the valve closed when the gateway link goes silent.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_check_link(uint64_t now_us) {
    if (!g_link_seen) {
        return;
    }
    if ((now_us - g_last_rx_us) <= (uint64_t)VALVE_ESTOP_WAIT_MS * 1000u) {
        return;
    }
    valve_fail_closed();
}

/**
 * @brief Service the ESTOP, operator remote, and gateway link inputs.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_service_inputs(uint64_t now_us) {
    monitor_heartbeat();
    monitor_handle_estop();
    if (g_estop_latched) {
        return;
    }
    monitor_handle_ir();
    monitor_rx_tick(now_us);
    monitor_check_link(now_us);
}

/**
 * @brief Advance the SANDBOX_ONLY implant when it is compiled in.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_implant_tick(void) {
#ifdef SANDBOX_ONLY
    implant_tick();
#endif
}

/**
 * @brief Drive exactly one annunciator lamp for the current valve state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_drive_leds(void) {
    if (g_estop_latched) {
        status_led_show(VALVE_FAULT);
        return;
    }
    status_led_show(monitor_led_for(valve_state()));
}

/**
 * @brief Drive the annunciator, valve, implant, and SCADA display.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_service_outputs(void) {
    monitor_implant_tick();
    valve_tick();
    monitor_drive_leds();
    monitor_render();
}

bool monitor_step(void) {
    uint64_t now_us;
    if (!g_ready) {
        return false;
    }
    now_us = time_us_64();
    monitor_refresh_process();
    monitor_service_inputs(now_us);
    monitor_service_outputs();
    return true;
}
