/**
 * FILE: test_pipeline_valve_and_security.c
 *
 * DESCRIPTION:
 * Comprehensive test suite for the RP2350 IRON VEIN pipeline valve
 * controller: provisioning constants, packet artifact, CRC, DHT11
 * process classification, display formatting, RYLR998 AT command
 * building, +RCV parsing, the valve state machine, the sealed command
 * path with its anti-replay window, the SCADA monitor state machine, and
 * the SANDBOX_ONLY FROSTLINE implant.
 *
 * BRIEF:
 * Native unit test runner for pipeline-valve-controller.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#include "harness.h"
#include "mock/pico/stdlib.h"
#include "mock/pico/time.h"
#include "mock/hardware/gpio.h"
#include "mock/hardware/i2c.h"
#include "mock/hardware/pwm.h"
#include "mock/hardware/uart.h"
#include "implant_host.h"
#include "pipeline_valve.h"
#include "button.h"
#include "crc.h"
#include "sensor.h"
#include "display.h"
#include "radio.h"
#include "valve.h"
#include "control.h"
#include "valve_auth.h"
#include "monitor.h"
#include "implant.h"
#include "crypto_aead.h"
#include "crypto_kdf.h"
#include "envelope.h"
#include "packet_artifact.h"
#include <stdio.h>
#include <string.h>

#undef SENSOR_HOST_PULSE_US
#define SENSOR_HOST_PULSE_US 0u

#include "../src/sensor.c"
#include "../src/crc.c"
#include "../src/display.c"
#include "../src/radio.c"
#include "../src/valve_auth.c"
#include "../src/valve.c"
#include "../src/control.c"
#include "../src/monitor.c"
#include "../src/implant.c"

/**
 * @brief Simulated DHT11 high-pulse widths for the canonical reading.
 */
static const uint16_t s_widths[SENSOR_BIT_COUNT] = {
    26u, 26u, 70u, 70u, 70u, 70u, 26u, 70u,
    26u, 26u, 26u, 26u, 26u, 26u, 26u, 26u,
    26u, 26u, 26u, 70u, 26u, 70u, 70u, 70u,
    26u, 26u, 26u, 26u, 26u, 26u, 26u, 26u,
    26u, 70u, 26u, 70u, 26u, 70u, 26u, 26u,
};

/**
 * @brief Fixed field key used by the authorization and command tests.
 */
static const uint8_t s_key[CRYPTO_AEAD_KEY_LEN] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
};

/**
 * @brief File-scope GPIO timeline offset scratch buffer.
 */
static uint32_t s_offsets[256];

/**
 * @brief File-scope GPIO timeline level scratch buffer.
 */
static int s_levels[256];

/**
 * @brief File-scope raw I2C log scratch buffer.
 */
static uint8_t s_raw[512];

/**
 * @brief File-scope decoded LCD scratch buffer.
 */
static char s_decoded[DISPLAY_LINE_LEN * 4];

/**
 * @brief File-scope first LCD render line buffer.
 */
static char s_line1[DISPLAY_LINE_LEN];

/**
 * @brief File-scope second LCD render line buffer.
 */
static char s_line2[DISPLAY_LINE_LEN];

/**
 * @brief File-scope decoded DHT11 reading.
 */
static dht_reading_t s_reading;

/**
 * @brief File-scope decoded inbound radio report.
 */
static radio_rcv_t s_rcv;

/**
 * @brief File-scope NEC pulse-duration scratch buffer.
 */
static uint16_t s_pulses[IR_REMOTE_MAX_PULSES];

/**
 * @brief File-scope NEC GPIO timeline offset scratch buffer.
 */
static uint32_t s_ir_off[IR_REMOTE_MAX_PULSES * 2u];

/**
 * @brief File-scope NEC GPIO timeline level scratch buffer.
 */
static int s_ir_lvl[IR_REMOTE_MAX_PULSES * 2u];

/**
 * @brief Reset the host mock peripherals.
 *
 * @param void No parameters.
 * @return void
 */
static void reset_mocks(void) {
    mock_timer_reset();
    mock_gpio_reset();
    mock_i2c_reset();
    mock_uart_reset();
    mock_pwm_reset();
}

/**
 * @brief Reset every host mock and owned module to a clean state.
 *
 * @param void No parameters.
 * @return void
 */
static void reset_all(void) {
    reset_mocks();
    estop_reset();
    mock_implant_reset();
    control_init();
    valve_init();
}

/**
 * @brief Append one timeline point and advance the entry count.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param level Level to record.
 * @param edge Absolute timestamp in microseconds.
 * @return size_t Updated entry count.
 */
static size_t timeline_pair(uint32_t *offsets, int *levels, size_t n,
                            int level, uint32_t edge) {
    offsets[n] = edge;
    levels[n] = level;
    return n + 1u;
}

/**
 * @brief Write the four leading DHT11 handshake timeline points.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @return size_t Number of timeline entries written.
 */
static size_t timeline_header(uint32_t *offsets, int *levels) {
    size_t n = 0u;
    n = timeline_pair(offsets, levels, n, 1, 0u);
    n = timeline_pair(offsets, levels, n, 0, 30u);
    n = timeline_pair(offsets, levels, n, 1, 110u);
    n = timeline_pair(offsets, levels, n, 0, 190u);
    return n;
}

/**
 * @brief Append the 40 data-bit timeline point pairs.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param widths Pointer to 40 high-pulse width values.
 * @return size_t Updated entry count.
 */
static size_t timeline_bits(uint32_t *offsets, int *levels, size_t n,
                            const uint16_t *widths) {
    uint32_t edge = 190u;
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        edge += 50u;
        n = timeline_pair(offsets, levels, n, 1, edge);
        edge += widths[i];
        n = timeline_pair(offsets, levels, n, 0, edge);
    }
    return n;
}

/**
 * @brief Build a DHT11 one-wire waveform timeline from bit widths.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param widths Pointer to 40 high-pulse width values.
 * @return size_t Number of timeline entries written.
 */
static size_t build_timeline(uint32_t *offsets, int *levels,
                             const uint16_t *widths) {
    size_t n = timeline_header(offsets, levels);
    return timeline_bits(offsets, levels, n, widths);
}

/**
 * @brief Combine the high nibbles of two I2C bytes into one display byte.
 *
 * @param hi First raw mock I2C byte.
 * @param lo Second raw mock I2C byte.
 * @return char Decoded display byte.
 */
static char decode_nibble(uint8_t hi, uint8_t lo) {
    uint8_t h = (uint8_t)((hi >> 4u) & 0x0Fu);
    uint8_t l = (uint8_t)((lo >> 4u) & 0x0Fu);
    return (char)((h << 4u) | l);
}

/**
 * @brief Decode 4-bit I2C LCD writes back into display bytes.
 *
 * @param buf Pointer to raw mock I2C byte log.
 * @param n Number of raw log bytes.
 * @param out Pointer to mutable decoded text buffer.
 * @param out_max Capacity of the decoded text buffer.
 * @return size_t Number of decoded display bytes.
 */
static size_t decode_lcd_bytes(const uint8_t *buf, size_t n, char *out,
                               size_t out_max) {
    size_t k = 0u;
    size_t i = 0u;
    while ((i + 4u <= n) && (k + 1u < out_max)) {
        out[k] = decode_nibble(buf[i], buf[i + 2u]);
        ++k;
        i += 4u;
    }
    out[k] = '\0';
    return k;
}

/**
 * @brief Build a 40-bit width array from five response bytes.
 *
 * @param bytes Pointer to five DHT11 response bytes.
 * @param out Pointer to mutable width array of SENSOR_BIT_COUNT entries.
 * @return void
 */
static void build_bits_from_bytes(const uint8_t bytes[SENSOR_BYTE_COUNT],
                                  uint16_t *out) {
    uint8_t b;
    uint8_t bit;
    size_t k = 0u;
    for (b = 0u; b < SENSOR_BYTE_COUNT; ++b) {
        for (bit = 0u; bit < 8u; ++bit) {
            out[k] = ((bytes[b] >> (7u - bit)) & 1u) ? 70u : 26u;
            k += 1u;
        }
    }
}

/**
 * @brief Copy the canonical high-pulse widths into a bit array.
 *
 * @param bits Pointer to mutable 40-entry width array.
 * @return void
 */
static void fill_widths(uint16_t *bits) {
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        bits[i] = s_widths[i];
    }
}

/**
 * @brief Arm a full DHT11 waveform timeline at a base timestamp.
 *
 * @param widths Pointer to 40 high-pulse width values.
 * @param base_us Absolute base timestamp in microseconds.
 * @return void
 */
static void mock_dht_timeline(const uint16_t *widths, uint64_t base_us) {
    size_t count = build_timeline(s_offsets, s_levels, widths);
    mock_gpio_timeline_begin_at(base_us, s_offsets, s_levels, count,
                                VALVE_DHT_PIN);
}

/**
 * @brief Assert the decoded LCD frame buffer contents.
 *
 * @param line1 Expected first-line text.
 * @param line2 Expected second-line text.
 * @return void
 */
static void assert_lcd_frame(const char *line1, const char *line2) {
    size_t count;
    count = mock_i2c_get_log(s_raw, sizeof(s_raw));
    TEST_ASSERT_EQUAL_UINT(136u, (unsigned)count);
    decode_lcd_bytes(s_raw, count, s_decoded, sizeof(s_decoded));
    TEST_ASSERT_EQUAL_UINT8(0x80u, (uint8_t)s_decoded[0]);
    TEST_ASSERT_TRUE(strncmp(line1, &s_decoded[1], strlen(line1)) == 0);
    TEST_ASSERT_EQUAL_UINT8(0xC0u, (uint8_t)s_decoded[17]);
    TEST_ASSERT_TRUE(strncmp(line2, &s_decoded[18], strlen(line2)) == 0);
}

/**
 * @brief Load a canonical valid reading into the fixture.
 *
 * @param void No parameters.
 * @return void
 */
static void load_reading(void) {
    s_reading.temperature_tenths = 230;
    s_reading.humidity_tenths = 610;
    s_reading.valid = true;
}

/**
 * @brief Assert the GPIO pin and bus provisioning constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_pin_constants(void) {
    TEST_ASSERT_EQUAL_UINT(25u, VALVE_LED_PIN);
    TEST_ASSERT_EQUAL_UINT(4u, VALVE_DHT_PIN);
    TEST_ASSERT_EQUAL_UINT(2u, VALVE_I2C_SDA);
    TEST_ASSERT_EQUAL_UINT(3u, VALVE_I2C_SCL);
    TEST_ASSERT_EQUAL_UINT(100000u, VALVE_I2C_BAUD);
    TEST_ASSERT_EQUAL_UINT(8u, VALVE_UART_TX);
    TEST_ASSERT_EQUAL_UINT(9u, VALVE_UART_RX);
}

/**
 * @brief Assert the UART, frame, and valve provisioning constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_frame_constants(void) {
    TEST_ASSERT_EQUAL_UINT(115200u, VALVE_UART_BAUD);
    TEST_ASSERT_EQUAL_UINT(48u, VALVE_FRAME_SIZE);
    TEST_ASSERT_EQUAL_UINT(5000u, VALVE_ESTOP_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(PACKET_LCD_I2C_ADDRESS, VALVE_LCD_ADDR);
    TEST_ASSERT_EQUAL_UINT(500u, VALVE_SERVO_CLOSE_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(1500u, VALVE_SERVO_OPEN_PULSE_US);
}

/**
 * @brief Assert the process band and operator remote constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_band_constants(void) {
    TEST_ASSERT_EQUAL_INT(-50, VALVE_TEMP_MIN_TENTHS);
    TEST_ASSERT_EQUAL_INT(100, VALVE_TEMP_MAX_TENTHS);
    TEST_ASSERT_EQUAL_UINT(0x47u, MONITOR_IR_OPEN);
    TEST_ASSERT_EQUAL_UINT(0x45u, MONITOR_IR_CLOSE);
    TEST_ASSERT_EQUAL_UINT(0x46u, MONITOR_IR_ESTOP);
}

/**
 * @brief Assert the packet artifact identity constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_artifact_ids(void) {
    TEST_ASSERT_EQUAL_STRING("pipeline-valve-packets-demo-v1",
                             PACKET_ARTIFACT_FORMAT);
    TEST_ASSERT_EQUAL_UINT(1u, PACKET_FRAME_VERSION);
    TEST_ASSERT_EQUAL_UINT(7u, PACKET_NODE_ID);
    TEST_ASSERT_EQUAL_HEX16(0x0001u, PACKET_HUB_ADDRESS);
    TEST_ASSERT_EQUAL_UINT(48u, PACKET_FRAME_SIZE);
    TEST_ASSERT_EQUAL_UINT(5000u, PACKET_ESTOP_WAIT_MS);
}

/**
 * @brief Assert the packet artifact frame constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_artifact_frame(void) {
    TEST_ASSERT_EQUAL_UINT(500u, PACKET_SERVO_CLOSE_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(1500u, PACKET_SERVO_OPEN_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(240u, PACKET_DHT_TIMEOUT_US);
    TEST_ASSERT_EQUAL_UINT(0x27u, PACKET_LCD_I2C_ADDRESS);
    TEST_ASSERT_EQUAL_UINT(256u, PACKET_MAX_RCV_LEN);
    TEST_ASSERT_EQUAL_UINT(48u, (unsigned)sizeof(PACKET_EXAMPLE_FRAME));
    TEST_ASSERT_EQUAL_UINT8(0x7Bu, PACKET_EXAMPLE_FRAME[0]);
}

/**
 * @brief Assert the formatted frame text and zero padding.
 *
 * @param frame Pointer to the formatted frame buffer.
 * @param n Length of the JSON body.
 * @param cap Capacity of the frame buffer.
 * @return void
 */
static void assert_frame_padding(const char *frame, size_t n, size_t cap) {
    static const char zeros[VALVE_FRAME_SIZE] = {0};
    TEST_ASSERT_EQUAL_UINT(29u, (unsigned)n);
    TEST_ASSERT_EQUAL_STRING("{\"n\":7,\"s\":0,\"t\":230,\"h\":610}", frame);
    TEST_ASSERT_EQUAL_MEMORY(zeros, &frame[n], cap - n);
}

/**
 * @brief Assert frame-builder rejection of null arguments.
 *
 * @param frame Pointer to a frame buffer.
 * @param cap Capacity of the frame buffer.
 * @return void
 */
static void assert_frame_rejects(char *frame, size_t cap) {
    TEST_ASSERT_EQUAL_UINT(0u,
                           (unsigned)sensor_build_frame(&s_reading, 0u, NULL, 0u));
    TEST_ASSERT_EQUAL_UINT(0u,
                           (unsigned)sensor_build_frame(NULL, 0u, frame, cap));
}

/**
 * @brief Assert command-builder rejection paths.
 *
 * @param cmd Pointer to a command buffer.
 * @param cap Capacity of the command buffer.
 * @return void
 */
static void assert_build_rejects(char *cmd, size_t cap) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_build_send_cmd(0x0001u, (const uint8_t *)"abc",
                                           257u, cmd, cap));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_build_send_cmd(0x0001u, NULL, 3u, cmd, cap));
}

/**
 * @brief Parse the canonical comma-laden JSON +RCV line.
 *
 * @param void No parameters.
 * @return radio_result_t Parsed result code.
 */
static radio_result_t parse_json_rcv(void) {
    return radio_parse_rcv("+RCV=0007,29,{\"n\":7,\"s\":0,\"t\":230,\"h\":610}"
                           ",-78,5", &s_rcv);
}

/**
 * @brief Assert +RCV parsing of a comma-laden JSON payload.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_json(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, parse_json_rcv());
    TEST_ASSERT_EQUAL_HEX16(0x0007u, s_rcv.sender);
    TEST_ASSERT_EQUAL_UINT(29u, (unsigned)s_rcv.len);
    TEST_ASSERT_EQUAL_STRING("{\"n\":7,\"s\":0,\"t\":230,\"h\":610}",
                             s_rcv.payload);
    TEST_ASSERT_EQUAL_INT(-78, s_rcv.rssi);
    TEST_ASSERT_EQUAL_INT(5, s_rcv.snr);
}

/**
 * @brief Assert +RCV parsing of a short comma-bearing payload.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_comma(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=0008,9,{\"a\",\"b\"},-60,3", &s_rcv));
    TEST_ASSERT_EQUAL_HEX16(0x0008u, s_rcv.sender);
    TEST_ASSERT_EQUAL_STRING("{\"a\",\"b\"}", s_rcv.payload);
}

/**
 * @brief Assert +RCV parsing of a frame with no RSSI/SNR tail.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_no_tail(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=0007,2,ok", &s_rcv));
    TEST_ASSERT_EQUAL_INT(0, s_rcv.rssi);
    TEST_ASSERT_EQUAL_INT(0, s_rcv.snr);
}

/**
 * @brief Assert +RCV rejection of null arguments.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_null(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR, radio_parse_rcv(NULL, &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0001,1,a", NULL));
}

/**
 * @brief Assert +RCV rejection of malformed and oversized lines.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_rejects(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("AT+SEND=0001,3,abc", &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_parse_rcv("+RCV=0001,300,abcdef", &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0001,5,abc", &s_rcv));
    assert_rcv_null();
}

/**
 * @brief Assert the inbound line pump consumes two CRLF-terminated lines.
 *
 * @param line Pointer to line buffer.
 * @param len Pointer to accumulated length.
 * @return void
 */
static void assert_pump_lines(char *line, size_t *len) {
    TEST_ASSERT_TRUE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_STRING("ab", line);
    TEST_ASSERT_TRUE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_STRING("cd", line);
    TEST_ASSERT_FALSE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)*len);
}

/**
 * @brief Assert the positive display formatting path.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_format_ok(void) {
    s_reading.temperature_tenths = 230;
    s_reading.humidity_tenths = 610;
    s_reading.valid = true;
    display_format_lines(&s_reading, 42u, true, s_line1, s_line2);
    TEST_ASSERT_EQUAL_STRING("T:23.0C H:61.0%", s_line1);
    TEST_ASSERT_EQUAL_STRING("N:07 S:0042 OK", s_line2);
}

/**
 * @brief Assert the negative display formatting path.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_format_fail(void) {
    s_reading.temperature_tenths = -53;
    display_format_lines(&s_reading, 0u, false, s_line1, s_line2);
    TEST_ASSERT_EQUAL_STRING("T:-5.3C H:61.0%", s_line1);
    TEST_ASSERT_EQUAL_STRING("N:07 S:0000 !!", s_line2);
}

/**
 * @brief Build the NEC frame word for address zero and a command.
 *
 * @param command Eight-bit remote command code.
 * @return uint32_t LSB-first frame word with inverse bytes.
 */
static uint32_t nec_word(uint8_t command) {
    return 0x0000FF00u | ((uint32_t)command << 16u) |
           ((uint32_t)(uint8_t)~command << 24u);
}

/**
 * @brief Fill the thirty-two LSB-first mark and space durations.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param word LSB-first NEC frame word.
 * @return void
 */
static void nec_bits(uint16_t *pulses, uint32_t word) {
    uint8_t i;
    for (i = 0u; i < 32u; ++i) {
        pulses[2u + 2u * i] = 560u;
        pulses[3u + 2u * i] = ((word >> i) & 1u) ? 1690u : 560u;
    }
}

/**
 * @brief Fill a complete NEC pulse train for a command.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param command Eight-bit remote command code.
 * @return void
 */
static void nec_fill(uint16_t *pulses, uint8_t command) {
    pulses[0] = 9000u;
    pulses[1] = 4500u;
    nec_bits(pulses, nec_word(command));
    pulses[66] = 560u;
    pulses[67] = 560u;
}

/**
 * @brief Append one NEC timeline point and advance the entry count.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param at Absolute offset in microseconds.
 * @param level Level to record.
 * @return size_t Updated entry count.
 */
static size_t nec_append(uint32_t *offsets, int *levels, size_t n,
                         uint32_t at, int level) {
    offsets[n] = at;
    levels[n] = level;
    return n + 1u;
}

/**
 * @brief Lay a NEC pulse train onto a mock GPIO timeline.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @return size_t Number of timeline entries written.
 */
static size_t nec_place(const uint16_t *pulses, uint32_t *offsets,
                        int *levels) {
    size_t i;
    size_t n = 0u;
    uint32_t t = 0u;
    for (i = 0u; i < IR_REMOTE_MAX_PULSES; ++i) {
        n = nec_append(offsets, levels, n, t, (i % 2u == 0u) ? 0 : 1);
        t += pulses[i];
    }
    n = nec_append(offsets, levels, n, t, 0);
    return n;
}

/**
 * @brief Arm the mock GPIO timeline with a NEC frame.
 *
 * @param command Eight-bit remote command code.
 * @return void
 */
static void nec_arm(uint8_t command) {
    size_t count;
    nec_fill(s_pulses, command);
    count = nec_place(s_pulses, s_ir_off, s_ir_lvl);
    mock_gpio_timeline_begin_at(mock_timer_now_us(), s_ir_off, s_ir_lvl,
                                count, VALVE_IR_PIN);
}

/**
 * @brief Arm a full valid DHT11 process waveform at the current time.
 *
 * @param void No parameters.
 * @return void
 */
static void arm_climate(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    const uint8_t cold[SENSOR_BYTE_COUNT] = {50u, 0u, 0u, 0u, 0x32u};
    build_bits_from_bytes(cold, bits);
    mock_dht_timeline(bits, mock_timer_now_us());
}

/**
 * @brief Arm an out-of-band hot DHT11 process waveform.
 *
 * @param void No parameters.
 * @return void
 */
static void arm_bad_climate(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    const uint8_t hot[SENSOR_BYTE_COUNT] = {0u, 0u, 0x0Bu, 0u, 0x0Bu};
    build_bits_from_bytes(hot, bits);
    mock_dht_timeline(bits, mock_timer_now_us());
}

/**
 * @brief Write one 32-bit little-endian value into a buffer.
 *
 * @param body Pointer to the four-byte output.
 * @param value Value to serialize.
 * @return void
 */
static void put_le32(uint8_t *body, uint32_t value) {
    body[0] = (uint8_t)(value & 0xFFu);
    body[1] = (uint8_t)((value >> 8u) & 0xFFu);
    body[2] = (uint8_t)((value >> 16u) & 0xFFu);
    body[3] = (uint8_t)((value >> 24u) & 0xFFu);
}

/**
 * @brief Fill a candidate valve authorization record for a sequence.
 *
 * @param auth Pointer to the record to fill.
 * @param seq Sequence number to bind.
 * @return void
 */
static void fill_auth(valve_auth_t *auth, uint32_t seq) {
    valve_auth_init(auth);
    auth->granted = true;
    auth->seq = seq;
    auth->last_seq = seq;
}

/**
 * @brief Compute and store the state tag for a record.
 *
 * @param auth Pointer to the record to sign.
 * @return void
 */
static void sign_auth(valve_auth_t *auth) {
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    TEST_ASSERT_TRUE(valve_auth_state_tag(auth, tag));
    memcpy(auth->tag, tag, CRYPTO_AEAD_TAG_LEN);
}

/**
 * @brief Compute the state tag for a candidate grant sequence.
 *
 * @param seq Sequence number carried by the command.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @return bool true when the tag was computed.
 */
static bool command_tag(uint32_t seq, uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    valve_auth_t candidate;
    valve_auth_candidate(seq, &candidate);
    return valve_auth_state_tag(&candidate, tag);
}

/**
 * @brief Build the signed body of a sealed valve command.
 *
 * @param seq Sequence number carried by the command.
 * @param cmd Open or close command byte.
 * @param body Pointer to the CONTROL_COMMAND_LEN output buffer.
 * @return bool true when the body was signed.
 */
static bool build_command_body(uint32_t seq, uint8_t cmd,
                               uint8_t body[CONTROL_COMMAND_LEN]) {
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    if (!command_tag(seq, tag)) {
        return false;
    }
    put_le32(body, seq);
    body[4] = cmd;
    memcpy(body + 5u, tag, CRYPTO_AEAD_TAG_LEN);
    return true;
}

/**
 * @brief Seal a valve command body into a hex envelope under a key.
 *
 * @param key Pointer to a 32-byte field key.
 * @param seq Sequence number carried by the command.
 * @param cmd Open or close command byte.
 * @param hex Pointer to the NUL-terminated hex output buffer.
 * @param hex_len Capacity of the hex output buffer in bytes.
 * @return bool true when the command was sealed.
 */
static bool seal_command(const uint8_t key[CRYPTO_AEAD_KEY_LEN], uint32_t seq,
                         uint8_t cmd, char *hex, size_t hex_len) {
    uint8_t body[CONTROL_COMMAND_LEN];
    uint8_t nonce[ENVELOPE_NONCE_LEN];
    uint8_t ad = (uint8_t)VALVE_NODE_ID;
    if (!build_command_body(seq, cmd, body)) {
        return false;
    }
    envelope_fill_nonce(nonce);
    return envelope_seal_hex(key, nonce, &ad, 1u, body, sizeof(body), hex,
                             hex_len);
}

/**
 * @brief Seal an arbitrary plaintext into a hex envelope under a key.
 *
 * @param key Pointer to a 32-byte field key.
 * @param pt Pointer to the plaintext bytes.
 * @param pt_len Number of plaintext bytes.
 * @param hex Pointer to the NUL-terminated hex output buffer.
 * @param hex_len Capacity of the hex output buffer in bytes.
 * @return bool true when the plaintext was sealed.
 */
static bool seal_raw(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                     const uint8_t *pt, size_t pt_len, char *hex,
                     size_t hex_len) {
    uint8_t nonce[ENVELOPE_NONCE_LEN];
    uint8_t ad = (uint8_t)VALVE_NODE_ID;
    envelope_fill_nonce(nonce);
    return envelope_seal_hex(key, nonce, &ad, 1u, pt, pt_len, hex, hex_len);
}

/**
 * @brief Queue one sealed hex envelope as an inbound +RCV line.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @return void
 */
static void queue_frame(const char *hex) {
    char line[RADIO_LINE_BUF_LEN];
    snprintf(line, sizeof(line), "+RCV=0001,%u,%s,-40,5\r\n",
             (unsigned)strlen(hex), hex);
    mock_uart_set_rx(line, strlen(line));
}

/**
 * @brief Reset mocks and initialize a ready controller with a clean log.
 *
 * @param void No parameters.
 * @return void
 */
static void init_monitor(void) {
    reset_all();
    TEST_ASSERT_TRUE(monitor_init());
    gpio_put(VALVE_BUTTON_PIN, true);
    mock_i2c_reset();
}

/**
 * @brief Seal, queue, and apply a command through the control path.
 *
 * @param key Pointer to a 32-byte field key.
 * @param seq Sequence number carried by the command.
 * @param cmd Open or close command byte.
 * @return bool true when the command was applied.
 */
static bool apply_control(const uint8_t key[CRYPTO_AEAD_KEY_LEN], uint32_t seq,
                          uint8_t cmd) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    if (!seal_command(key, seq, cmd, hex, sizeof(hex))) {
        return false;
    }
    return control_handle_frame(hex);
}

/**
 * @brief Seal, queue, and apply a command through the monitor tick.
 *
 * @param key Pointer to a 32-byte field key.
 * @param seq Sequence number carried by the command.
 * @param cmd Open or close command byte.
 * @return bool true when the monitor tick completed.
 */
static bool apply_sealed(const uint8_t key[CRYPTO_AEAD_KEY_LEN], uint32_t seq,
                         uint8_t cmd) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    if (!seal_command(key, seq, cmd, hex, sizeof(hex))) {
        return false;
    }
    queue_frame(hex);
    return monitor_step();
}

/**
 * @brief Assert the exact annunciator lamp pattern.
 *
 * @param red Expected red lamp level.
 * @param yellow Expected yellow lamp level.
 * @param green Expected green lamp level.
 * @return void
 */
static void assert_lamps(int red, int yellow, int green) {
    TEST_ASSERT_EQUAL_INT(red, mock_gpio_get(VALVE_RED_LED_PIN));
    TEST_ASSERT_EQUAL_INT(yellow, mock_gpio_get(VALVE_YELLOW_LED_PIN));
    TEST_ASSERT_EQUAL_INT(green, mock_gpio_get(VALVE_GREEN_LED_PIN));
}

/**
 * @brief Press and latch the emergency stop button.
 *
 * @param void No parameters.
 * @return void
 */
static void press_estop(void) {
    estop_reset();
    gpio_put(VALVE_BUTTON_PIN, false);
}

/**
 * @brief Advance the mock clock past the valve travel interval.
 *
 * @param void No parameters.
 * @return void
 */
static void advance_travel(void) {
    mock_timer_set_us(mock_timer_now_us() + (uint64_t)VALVE_TRAVEL_MS * 1000u +
                      1u);
}

/**
 * @brief Report whether a byte appears in the mock UART transmit buffer.
 *
 * @param value Byte value to search for.
 * @return bool true when the byte was transmitted.
 */
static bool tx_contains_byte(uint8_t value) {
    size_t i;
    for (i = 0u; i < s_mock_tx_len; ++i) {
        if ((uint8_t)s_mock_tx_buf[i] == value) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Run the implant tick a fixed number of times.
 *
 * @param count Number of ticks to run.
 * @return void
 */
static void implant_tick_n(uint8_t count) {
    uint8_t i;
    for (i = 0u; i < count; ++i) {
        implant_tick();
    }
}

/**
 * @brief Enable every implant action gate for the active-path tests.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_test_enable_all(void) {
    g_implant_beacon_enabled = true;
    g_implant_arm_enabled = true;
    g_implant_persist_enabled = true;
}

/**
 * @brief Reset and initialize the servo and valve state machine.
 *
 * @param void No parameters.
 * @return void
 */
static void init_valve(void) {
    reset_all();
    servo_init();
    valve_init();
}

/**
 * @brief Assert the current valve state.
 *
 * @param state Expected valve state.
 * @return void
 */
static void assert_valve_state(valve_state_t state) {
    TEST_ASSERT_EQUAL_INT(state, valve_state());
}

/**
 * @brief Assert the valve is commanded closed.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_servo_close(void) {
    TEST_ASSERT_EQUAL_UINT(VALVE_SERVO_CLOSE_PULSE_US,
                           mock_pwm_get_level(VALVE_SERVO_PIN));
}

/**
 * @brief Assert the valve is fully open and driven open.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_valve_open(void) {
    assert_valve_state(VALVE_STATE_OPEN);
    TEST_ASSERT_TRUE(valve_is_open());
    TEST_ASSERT_EQUAL_UINT(VALVE_SERVO_OPEN_PULSE_US,
                           mock_pwm_get_level(VALVE_SERVO_PIN));
}

/**
 * @brief Reset and initialize the sealed command path with the test key.
 *
 * @param void No parameters.
 * @return void
 */
static void init_control(void) {
    reset_all();
    control_init();
    control_set_key(s_key);
}

/**
 * @brief Arm the implant and run it to the trigger.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_arm_and_trigger(void) {
    implant_handle_command(IMPLANT_ARM_MAGIC, IMPLANT_ARM_MAGIC_LEN);
    implant_tick_n(IMPLANT_TRIGGER_DELAY_TICKS);
}

/**
 * @brief Assert the implant detonated the valve and wrote the marker.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_implant_detonated(void) {
    TEST_ASSERT_FALSE(implant_armed());
    TEST_ASSERT_EQUAL_UINT(VALVE_SERVO_CLOSE_PULSE_US,
                           mock_pwm_get_level(VALVE_SERVO_PIN));
    TEST_ASSERT_EQUAL_UINT(IMPLANT_MARKER_BYTE, g_mock_implant_flash);
}

void test_config_constants(void) {
    assert_pin_constants();
    assert_frame_constants();
    assert_band_constants();
}

void test_packet_artifact_constants(void) {
    assert_artifact_ids();
    assert_artifact_frame();
}

void test_crc16_ccitt(void) {
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, crc16_ccitt((const uint8_t *)"", 0u));
    TEST_ASSERT_EQUAL_HEX16(0x29B1u,
                            crc16_ccitt((const uint8_t *)"123456789", 9u));
}

void test_dht_parse_bits_valid(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    fill_widths(bits);
    TEST_ASSERT_TRUE(dht_parse_bits(bits, &s_reading));
    TEST_ASSERT_TRUE(s_reading.valid);
    TEST_ASSERT_EQUAL_INT(230, s_reading.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(610u, s_reading.humidity_tenths);
}

void test_dht_parse_bits_checksum_fail(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        bits[i] = s_widths[i];
    }
    bits[39] = 70u;
    TEST_ASSERT_FALSE(dht_parse_bits(bits, &r));
}

void test_dht_parse_bits_null(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    TEST_ASSERT_FALSE(dht_parse_bits(NULL, &r));
    TEST_ASSERT_FALSE(dht_parse_bits(bits, NULL));
}

void test_sensor_build_frame(void) {
    char frame[VALVE_FRAME_SIZE];
    size_t n;
    load_reading();
    n = sensor_build_frame(&s_reading, 0u, frame, sizeof(frame));
    assert_frame_padding(frame, n, sizeof(frame));
    assert_frame_rejects(frame, sizeof(frame));
}

void test_process_ok(void) {
    dht_reading_t r;
    r.valid = true;
    r.temperature_tenths = 0;
    TEST_ASSERT_TRUE(process_ok(&r));
    r.temperature_tenths = VALVE_TEMP_MIN_TENTHS;
    TEST_ASSERT_TRUE(process_ok(&r));
    r.temperature_tenths = VALVE_TEMP_MAX_TENTHS;
    TEST_ASSERT_TRUE(process_ok(&r));
}

void test_process_rejects(void) {
    dht_reading_t r;
    r.valid = true;
    r.temperature_tenths = VALVE_TEMP_MIN_TENTHS - 1;
    TEST_ASSERT_FALSE(process_ok(&r));
    r.temperature_tenths = VALVE_TEMP_MAX_TENTHS + 1;
    TEST_ASSERT_FALSE(process_ok(&r));
    TEST_ASSERT_FALSE(process_ok(NULL));
}

void test_process_invalid(void) {
    dht_reading_t r;
    r.valid = false;
    r.temperature_tenths = 0;
    TEST_ASSERT_FALSE(process_ok(&r));
}

void test_sensor_read_dht_waveform(void) {
    sensor_init();
    mock_dht_timeline(s_widths, 0u);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_OK, sensor_read(&s_reading));
    TEST_ASSERT_TRUE(s_reading.valid);
    TEST_ASSERT_EQUAL_INT(230, s_reading.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(610u, s_reading.humidity_tenths);
}

void test_sensor_read_timeout(void) {
    dht_reading_t r;
    sensor_init();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_radio_build_send_cmd(void) {
    char cmd[64];
    radio_result_t rc;
    rc = radio_build_send_cmd(0x0001u, (const uint8_t *)"abc", 3u, cmd,
                              sizeof(cmd));
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, rc);
    TEST_ASSERT_EQUAL_STRING("AT+SEND=0001,3,abc\r\n", cmd);
    assert_build_rejects(cmd, sizeof(cmd));
}

void test_radio_parse_rcv(void) {
    assert_rcv_json();
    assert_rcv_comma();
    assert_rcv_no_tail();
}

void test_radio_parse_rcv_rejects(void) {
    assert_rcv_rejects();
}

void test_radio_line_pump(void) {
    char line[32];
    size_t len = 0u;
    mock_uart_reset();
    mock_uart_set_rx("ab\r\ncd\r\n", 8u);
    assert_pump_lines(line, &len);
}

void test_radio_spoofed_sender_attribution(void) {
    radio_rcv_t rcv;
    radio_result_t rc;
    rc = radio_parse_rcv("+RCV=0007,7,{\"a\",1},-90,3", &rcv);
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, rc);
    TEST_ASSERT_TRUE(radio_frame_is_from(&rcv, 0x0007u));
    TEST_ASSERT_FALSE(radio_frame_is_from(&rcv, 0x0008u));
}

void test_display_format_lines(void) {
    assert_format_ok();
    assert_format_fail();
}

void test_display_render_lines(void) {
    strcpy(s_line1, "T:23.0C H:61.0%");
    strcpy(s_line2, "N:07 S:0042 OK");
    mock_i2c_reset();
    display_render_lines(i2c1, VALVE_LCD_ADDR, s_line1, s_line2);
    assert_lcd_frame("T:23.0C H:61.0%", "N:07 S:0042 OK");
}

void test_valve_init(void) {
    init_valve();
    assert_valve_state(VALVE_STATE_CLOSED);
    TEST_ASSERT_FALSE(valve_is_open());
    assert_servo_close();
}

void test_valve_reject_unauthorized(void) {
    init_valve();
    valve_apply_command(true, false);
    assert_valve_state(VALVE_STATE_CLOSED);
    assert_servo_close();
}

void test_valve_open_travel(void) {
    init_valve();
    valve_apply_command(true, true);
    assert_valve_state(VALVE_STATE_MOVING);
    valve_tick();
    assert_valve_state(VALVE_STATE_MOVING);
    advance_travel();
    valve_tick();
    assert_valve_open();
}

void test_valve_close_travel(void) {
    init_valve();
    valve_apply_command(false, true);
    advance_travel();
    valve_tick();
    assert_valve_state(VALVE_STATE_CLOSED);
    assert_servo_close();
}

void test_valve_fail_closed(void) {
    init_valve();
    valve_apply_command(true, true);
    advance_travel();
    valve_tick();
    valve_fail_closed();
    assert_valve_state(VALVE_STATE_FAULT);
    assert_servo_close();
}

void test_valve_auth_state_tag(void) {
    valve_auth_t auth;
    valve_auth_set_key(s_key);
    fill_auth(&auth, 3u);
    sign_auth(&auth);
    TEST_ASSERT_TRUE(valve_auth_state_ok(&auth));
    auth.granted = false;
    TEST_ASSERT_FALSE(valve_auth_state_ok(&auth));
}

void test_valve_auth_apply_window(void) {
    valve_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    valve_auth_set_key(s_key);
    valve_auth_init(&auth);
    TEST_ASSERT_TRUE(command_tag(1u, tag));
    TEST_ASSERT_TRUE(valve_auth_apply(&auth, 1u, tag));
    TEST_ASSERT_FALSE(valve_auth_apply(&auth, 1u, tag));
    TEST_ASSERT_FALSE(valve_auth_apply(&auth, 0u, tag));
}

void test_valve_auth_apply_advance(void) {
    valve_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    valve_auth_set_key(s_key);
    valve_auth_init(&auth);
    TEST_ASSERT_TRUE(command_tag(2u, tag));
    TEST_ASSERT_TRUE(valve_auth_apply(&auth, 2u, tag));
    TEST_ASSERT_EQUAL_UINT(2u, auth.last_seq);
}

void test_valve_auth_bad_tag(void) {
    valve_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    valve_auth_set_key(s_key);
    valve_auth_init(&auth);
    TEST_ASSERT_FALSE(valve_auth_apply(&auth, 5u, tag));
}

void test_valve_auth_null_guards(void) {
    valve_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    valve_auth_init(&auth);
    TEST_ASSERT_FALSE(valve_auth_apply(NULL, 1u, tag));
    TEST_ASSERT_FALSE(valve_auth_apply(&auth, 1u, NULL));
    TEST_ASSERT_FALSE(valve_auth_state_tag(&auth, NULL));
    valve_auth_init(NULL);
}

void test_valve_auth_key_guards(void) {
    valve_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    valve_auth_init(&auth);
    valve_auth_set_key(NULL);
    TEST_ASSERT_FALSE(valve_auth_state_tag(&auth, tag));
    TEST_ASSERT_FALSE(valve_auth_state_ok(&auth));
    TEST_ASSERT_FALSE(valve_auth_apply(&auth, 1u, tag));
}

void test_valve_auth_tag_guard(void) {
    valve_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    valve_auth_set_key(s_key);
    valve_auth_init(&auth);
    TEST_ASSERT_FALSE(valve_auth_state_tag(NULL, tag));
}

void test_control_key_guards(void) {
    reset_all();
    TEST_ASSERT_FALSE(control_handle_frame("00"));
    TEST_ASSERT_FALSE(control_set_key(NULL));
    TEST_ASSERT_FALSE(control_handle_frame(NULL));
}

void test_control_handle_success(void) {
    init_control();
    TEST_ASSERT_TRUE(apply_control(s_key, 1u, VALVE_COMMAND_OPEN));
    assert_valve_state(VALVE_STATE_MOVING);
}

void test_control_replay(void) {
    init_control();
    TEST_ASSERT_TRUE(apply_control(s_key, 1u, VALVE_COMMAND_OPEN));
    TEST_ASSERT_FALSE(apply_control(s_key, 1u, VALVE_COMMAND_OPEN));
}

void test_control_bad_tag(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    init_control();
    TEST_ASSERT_TRUE(seal_command(s_key, 1u, VALVE_COMMAND_OPEN, hex,
                                  sizeof(hex)));
    hex[46] = (hex[46] == '0') ? '1' : '0';
    TEST_ASSERT_FALSE(control_handle_frame(hex));
}

void test_control_bad_command(void) {
    init_control();
    TEST_ASSERT_FALSE(apply_control(s_key, 1u, 0x09u));
    assert_valve_state(VALVE_STATE_CLOSED);
}

void test_control_short_body(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    uint8_t body[5] = {1u, 0u, 0u, 0u, VALVE_COMMAND_OPEN};
    init_control();
    TEST_ASSERT_TRUE(seal_raw(s_key, body, sizeof(body), hex, sizeof(hex)));
    TEST_ASSERT_FALSE(control_handle_frame(hex));
}

void test_control_authorize(void) {
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    init_control();
    TEST_ASSERT_TRUE(command_tag(1u, tag));
    TEST_ASSERT_TRUE(control_authorize(1u, tag));
    TEST_ASSERT_FALSE(control_authorize(1u, tag));
    control_deinit();
    TEST_ASSERT_FALSE(control_authorize(2u, tag));
}

void test_monitor_init(void) {
    reset_all();
    TEST_ASSERT_TRUE(monitor_init());
    TEST_ASSERT_EQUAL_UINT(115200u, s_mock_uart_baud);
    TEST_ASSERT_TRUE(s_mock_gpio_dirs[VALVE_LED_PIN]);
    TEST_ASSERT(mock_i2c_log_count() > 0u);
}

void test_monitor_init_lcd_fail(void) {
    reset_all();
    mock_i2c_set_write_fail(true);
    TEST_ASSERT_FALSE(monitor_init());
}

void test_monitor_not_ready(void) {
    reset_all();
    monitor_deinit();
    TEST_ASSERT_FALSE(monitor_step());
}

void test_monitor_step_idle(void) {
    init_monitor();
    TEST_ASSERT_TRUE(monitor_step());
    assert_lcd_frame("ST:CLOSED", "PROC:BAD LNK:--");
}

void test_monitor_heartbeat(void) {
    init_monitor();
    g_heartbeat_ticks = 0u;
    g_heartbeat_level = false;
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(1, mock_gpio_get(VALVE_LED_PIN));
}

void test_monitor_render_status(void) {
    init_monitor();
    g_proc_ok = true;
    g_link_seen = true;
    mock_i2c_reset();
    monitor_render();
    assert_lcd_frame("ST:CLOSED", "PROC:OK LNK:UP");
}

void test_monitor_state_text(void) {
    TEST_ASSERT_EQUAL_STRING("CLOSED", monitor_state_text(VALVE_STATE_CLOSED));
    TEST_ASSERT_EQUAL_STRING("OPEN", monitor_state_text(VALVE_STATE_OPEN));
    TEST_ASSERT_EQUAL_STRING("MOVING", monitor_state_text(VALVE_STATE_MOVING));
    TEST_ASSERT_EQUAL_STRING("FAULT", monitor_state_text(VALVE_STATE_FAULT));
}

void test_monitor_led_map(void) {
    TEST_ASSERT_EQUAL_INT(VALVE_FAULT, monitor_led_for(VALVE_STATE_FAULT));
    TEST_ASSERT_EQUAL_INT(VALVE_PENDING, monitor_led_for(VALVE_STATE_MOVING));
    TEST_ASSERT_EQUAL_INT(VALVE_NOMINAL, monitor_led_for(VALVE_STATE_CLOSED));
    TEST_ASSERT_EQUAL_INT(VALVE_NOMINAL, monitor_led_for(VALVE_STATE_OPEN));
}

void test_monitor_process_ok(void) {
    init_monitor();
    arm_climate();
    TEST_ASSERT_TRUE(monitor_step());
    assert_lcd_frame("ST:CLOSED", "PROC:OK LNK:--");
    arm_bad_climate();
    TEST_ASSERT_TRUE(monitor_step());
}

void test_monitor_estop_button(void) {
    init_monitor();
    press_estop();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_FAULT, valve_state());
    assert_lamps(1, 0, 0);
}

void test_monitor_estop_priority(void) {
    init_monitor();
    press_estop();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, VALVE_COMMAND_OPEN));
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_FAULT, valve_state());
}

void test_monitor_clear_estop(void) {
    init_monitor();
    press_estop();
    monitor_step();
    gpio_put(VALVE_BUTTON_PIN, true);
    monitor_clear_estop();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, VALVE_COMMAND_OPEN));
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_MOVING, valve_state());
}

void test_monitor_ir_open(void) {
    init_monitor();
    nec_arm(MONITOR_IR_OPEN);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_MOVING, valve_state());
    advance_travel();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(valve_is_open());
    assert_lamps(0, 0, 1);
}

void test_monitor_ir_close(void) {
    init_monitor();
    nec_arm(MONITOR_IR_CLOSE);
    TEST_ASSERT_TRUE(monitor_step());
    advance_travel();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_ir_estop(void) {
    init_monitor();
    nec_arm(MONITOR_IR_ESTOP);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_FAULT, valve_state());
    assert_lamps(1, 0, 0);
}

void test_monitor_ir_other(void) {
    ir_command_t cmd;
    init_monitor();
    nec_arm(0x00u);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
    cmd.command = 0x00u;
    monitor_apply_ir_command(&cmd);
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_ir_estop_latched(void) {
    ir_command_t cmd;
    init_monitor();
    g_estop_latched = true;
    cmd.command = MONITOR_IR_OPEN;
    monitor_apply_ir_command(&cmd);
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_remote_open(void) {
    init_monitor();
    arm_climate();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, VALVE_COMMAND_OPEN));
    assert_valve_state(VALVE_STATE_MOVING);
    advance_travel();
    TEST_ASSERT_TRUE(monitor_step());
    assert_valve_open();
    assert_lamps(0, 0, 1);
}

void test_monitor_remote_close(void) {
    init_monitor();
    apply_sealed(g_key, 1u, VALVE_COMMAND_OPEN);
    advance_travel();
    monitor_step();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 2u, VALVE_COMMAND_CLOSE));
    advance_travel();
    monitor_step();
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_remote_replay(void) {
    init_monitor();
    apply_sealed(g_key, 1u, VALVE_COMMAND_OPEN);
    advance_travel();
    monitor_step();
    TEST_ASSERT_TRUE(valve_is_open());
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, VALVE_COMMAND_OPEN));
    TEST_ASSERT_TRUE(valve_is_open());
}

void test_monitor_remote_bad_tag(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    init_monitor();
    TEST_ASSERT_TRUE(seal_command(g_key, 1u, VALVE_COMMAND_OPEN, hex,
                                  sizeof(hex)));
    hex[46] = (hex[46] == '0') ? '1' : '0';
    queue_frame(hex);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_remote_bad_command(void) {
    init_monitor();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, 0x09u));
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_remote_malformed(void) {
    init_monitor();
    queue_frame("00");
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_link_loss(void) {
    init_monitor();
    apply_sealed(g_key, 1u, VALVE_COMMAND_OPEN);
    mock_timer_set_us(mock_timer_now_us() +
                      (uint64_t)VALVE_ESTOP_WAIT_MS * 1000u + 1u);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_FAULT, valve_state());
    assert_lamps(1, 0, 0);
}

void test_monitor_link_within(void) {
    init_monitor();
    apply_sealed(g_key, 1u, VALVE_COMMAND_OPEN);
    advance_travel();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(valve_is_open());
    assert_lamps(0, 0, 1);
}

void test_monitor_link_unseen(void) {
    init_monitor();
    monitor_check_link(mock_timer_now_us() + 1000000u);
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_apply_frame_estop(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    init_monitor();
    seal_command(g_key, 1u, VALVE_COMMAND_OPEN, hex, sizeof(hex));
    g_estop_latched = true;
    monitor_apply_frame(hex, strlen(hex), 0u);
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_rx_non_rcv(void) {
    init_monitor();
    mock_uart_set_rx("hello\r\n", 7u);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(VALVE_STATE_CLOSED, valve_state());
}

void test_monitor_deinit(void) {
    init_monitor();
    monitor_deinit();
    TEST_ASSERT_FALSE(monitor_step());
}

void test_implant_init(void) {
    mock_implant_reset();
    implant_init();
    TEST_ASSERT_FALSE(implant_armed());
    TEST_ASSERT_FALSE(implant_debug_attached());
}

void test_implant_debug_attached(void) {
    g_mock_implant_dhcsr = IMPLANT_DHCSR_DEBUGEN;
    TEST_ASSERT_TRUE(implant_debug_attached());
    g_mock_implant_dhcsr = IMPLANT_DHCSR_HALT;
    TEST_ASSERT_TRUE(implant_debug_attached());
    g_mock_implant_dhcsr = 0u;
    TEST_ASSERT_FALSE(implant_debug_attached());
}

void test_implant_handle_command(void) {
    uint8_t bad[IMPLANT_ARM_MAGIC_LEN] = {0u};
    implant_init(); implant_handle_command(IMPLANT_ARM_MAGIC, IMPLANT_ARM_MAGIC_LEN);
    TEST_ASSERT_FALSE(implant_armed()); implant_test_enable_all();
    implant_handle_command(NULL, IMPLANT_ARM_MAGIC_LEN);
    implant_handle_command(bad, IMPLANT_ARM_MAGIC_LEN);
    implant_handle_command(IMPLANT_ARM_MAGIC, 2u);
    implant_handle_command(IMPLANT_ARM_MAGIC, IMPLANT_ARM_MAGIC_LEN);
    TEST_ASSERT_TRUE(implant_armed());
}

void test_implant_beacon(void) {
    implant_init(); mock_uart_reset();
    g_mock_implant_dhcsr = 0u;
    implant_tick_n(IMPLANT_BEACON_INTERVAL_TICKS);
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)s_mock_tx_len);
    implant_test_enable_all();
    implant_tick_n(IMPLANT_BEACON_INTERVAL_TICKS);
    TEST_ASSERT_TRUE(tx_contains_byte(IMPLANT_BEACON_MAGIC[0]));
    TEST_ASSERT_TRUE(tx_contains_byte(IMPLANT_BEACON_MAGIC[3]));
}

void test_implant_anti_debug(void) {
    implant_init();
    mock_uart_reset();
    g_mock_implant_dhcsr = IMPLANT_DHCSR_DEBUGEN;
    implant_tick_n(IMPLANT_BEACON_INTERVAL_TICKS);
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)s_mock_tx_len);
}

void test_implant_logic_bomb(void) {
    implant_init(); g_mock_implant_dhcsr = 0u;
    servo_init();
    valve_open();
    implant_arm_and_trigger();
    TEST_ASSERT_FALSE(implant_armed()); TEST_ASSERT_EQUAL_UINT(VALVE_SERVO_OPEN_PULSE_US, mock_pwm_get_level(VALVE_SERVO_PIN));
    implant_test_enable_all();
    implant_arm_and_trigger();
    assert_implant_detonated();
}

void test_implant_persist_once(void) {
    implant_init();
    g_mock_implant_dhcsr = 0u;
    g_implant_arm_enabled = true;
    implant_arm_and_trigger();
    TEST_ASSERT_EQUAL_UINT(0u, g_mock_implant_flash);
    implant_test_enable_all(); implant_arm_and_trigger();
    g_mock_implant_flash = 0x11u; implant_arm_and_trigger();
    TEST_ASSERT_EQUAL_UINT(0x11u, g_mock_implant_flash);
}

void test_sensor_policy_not_ready(void) {
    dht_reading_t r;
    sensor_deinit();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_POLICY_ERROR, sensor_read(&r));
}

void test_sensor_policy_null_out(void) {
    sensor_init();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_POLICY_ERROR, sensor_read(NULL));
}

void test_sensor_dht_negative_temp(void) {
    const uint8_t bytes[SENSOR_BYTE_COUNT] = {0u, 0u, 0x82u, 3u, 0x85u};
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    build_bits_from_bytes(bytes, bits);
    TEST_ASSERT_TRUE(dht_parse_bits(bits, &r));
    TEST_ASSERT_TRUE(r.valid);
    TEST_ASSERT_EQUAL_INT(-17, r.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(0u, r.humidity_tenths);
}

void test_sensor_read_timeout_response_low(void) {
    uint32_t offsets[4] = {0u, 30u};
    int levels[4] = {1, 0};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 2u, VALVE_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_timeout_response_high(void) {
    uint32_t offsets[4] = {0u, 30u, 110u};
    int levels[4] = {1, 0, 1};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 3u, VALVE_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_timeout_bit_low(void) {
    uint32_t offsets[4] = {0u, 30u, 110u, 190u};
    int levels[4] = {1, 0, 1, 0};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 4u, VALVE_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_measure_timeout(void) {
    uint32_t offsets[8] = {0u, 30u, 110u, 190u, 240u};
    int levels[8] = {1, 0, 1, 0, 1};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 5u, VALVE_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_radio_hex_digits(void) {
    radio_rcv_t rcv;
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=00a7,2,ok,-3,2", &rcv));
    TEST_ASSERT_EQUAL_HEX16(0x00A7u, rcv.sender);
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=00FE,2,ok,-3,2", &rcv));
    TEST_ASSERT_EQUAL_HEX16(0x00FEu, rcv.sender);
}

void test_radio_build_send_cmd_oversize_cmd(void) {
    const uint8_t payload[30] = "{\"n\":7,\"s\":0,\"t\":230,\"h\":610}";
    char tiny[16];
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_build_send_cmd(0x0001u, payload, 29u, tiny,
                                           sizeof(tiny)));
}

void test_radio_send_frame_oversize(void) {
    const uint8_t payload[30] = "{\"n\":7,\"s\":0,\"t\":230,\"h\":610}";
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_send_frame(uart0, payload, 257u));
}

void test_radio_parse_missing_commas(void) {
    radio_rcv_t rcv;
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=007ZX,3,hi,-1,1", &rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0007,9Z,hi,-1,1", &rcv));
}

void setUp(void) {
    reset_all();
}

void tearDown(void) {
}

/**
 * @brief Run the provisioning, artifact, and display tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_basic_tests(void) {
    RUN_TEST(test_config_constants);
    RUN_TEST(test_packet_artifact_constants);
    RUN_TEST(test_crc16_ccitt);
    RUN_TEST(test_display_format_lines);
    RUN_TEST(test_display_render_lines);
}

/**
 * @brief Run the sensor sampling and process tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_sensor_tests(void) {
    RUN_TEST(test_dht_parse_bits_valid);
    RUN_TEST(test_dht_parse_bits_checksum_fail);
    RUN_TEST(test_dht_parse_bits_null);
    RUN_TEST(test_sensor_build_frame);
    RUN_TEST(test_process_ok);
    RUN_TEST(test_process_rejects);
    RUN_TEST(test_process_invalid);
    RUN_TEST(test_sensor_read_dht_waveform);
}

/**
 * @brief Run the sensor timeout and policy tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_policy_tests(void) {
    RUN_TEST(test_sensor_read_timeout);
    RUN_TEST(test_sensor_policy_not_ready);
    RUN_TEST(test_sensor_policy_null_out);
    RUN_TEST(test_sensor_dht_negative_temp);
    RUN_TEST(test_sensor_read_timeout_response_low);
    RUN_TEST(test_sensor_read_timeout_response_high);
    RUN_TEST(test_sensor_read_timeout_bit_low);
    RUN_TEST(test_sensor_read_measure_timeout);
}

/**
 * @brief Run the radio protocol tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_radio_tests(void) {
    RUN_TEST(test_radio_build_send_cmd);
    RUN_TEST(test_radio_parse_rcv);
    RUN_TEST(test_radio_parse_rcv_rejects);
    RUN_TEST(test_radio_line_pump);
    RUN_TEST(test_radio_spoofed_sender_attribution);
    RUN_TEST(test_radio_hex_digits);
}

/**
 * @brief Run the radio edge-case tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_radio_edge_tests(void) {
    RUN_TEST(test_radio_build_send_cmd_oversize_cmd);
    RUN_TEST(test_radio_send_frame_oversize);
    RUN_TEST(test_radio_parse_missing_commas);
}

/**
 * @brief Run the valve state machine tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_valve_tests(void) {
    RUN_TEST(test_valve_init);
    RUN_TEST(test_valve_reject_unauthorized);
    RUN_TEST(test_valve_open_travel);
    RUN_TEST(test_valve_close_travel);
    RUN_TEST(test_valve_fail_closed);
}

/**
 * @brief Run the valve authorization record tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_auth_tests(void) {
    RUN_TEST(test_valve_auth_state_tag);
    RUN_TEST(test_valve_auth_apply_window);
    RUN_TEST(test_valve_auth_apply_advance);
    RUN_TEST(test_valve_auth_bad_tag);
    RUN_TEST(test_valve_auth_null_guards);
    RUN_TEST(test_valve_auth_key_guards);
    RUN_TEST(test_valve_auth_tag_guard);
}

/**
 * @brief Run the sealed command path tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_control_tests(void) {
    RUN_TEST(test_control_key_guards);
    RUN_TEST(test_control_handle_success);
    RUN_TEST(test_control_replay);
    RUN_TEST(test_control_bad_tag);
    RUN_TEST(test_control_bad_command);
    RUN_TEST(test_control_short_body);
    RUN_TEST(test_control_authorize);
}

/**
 * @brief Run the SCADA monitor initialization and render tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_basic_tests(void) {
    RUN_TEST(test_monitor_init);
    RUN_TEST(test_monitor_init_lcd_fail);
    RUN_TEST(test_monitor_not_ready);
    RUN_TEST(test_monitor_step_idle);
    RUN_TEST(test_monitor_render_status);
    RUN_TEST(test_monitor_state_text);
    RUN_TEST(test_monitor_led_map);
    RUN_TEST(test_monitor_process_ok);
}

/**
 * @brief Run the SCADA monitor ESTOP and operator remote tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_input_tests(void) {
    RUN_TEST(test_monitor_estop_button);
    RUN_TEST(test_monitor_estop_priority);
    RUN_TEST(test_monitor_clear_estop);
    RUN_TEST(test_monitor_ir_open);
    RUN_TEST(test_monitor_ir_close);
    RUN_TEST(test_monitor_ir_estop);
    RUN_TEST(test_monitor_ir_other);
    RUN_TEST(test_monitor_ir_estop_latched);
}

/**
 * @brief Run the SCADA monitor remote command and link tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_remote_tests(void) {
    RUN_TEST(test_monitor_remote_open);
    RUN_TEST(test_monitor_remote_close);
    RUN_TEST(test_monitor_remote_replay);
    RUN_TEST(test_monitor_remote_bad_tag);
    RUN_TEST(test_monitor_remote_bad_command);
    RUN_TEST(test_monitor_remote_malformed);
    RUN_TEST(test_monitor_link_loss);
    RUN_TEST(test_monitor_link_within);
}

/**
 * @brief Run the remaining SCADA monitor guard tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_guard_tests(void) {
    RUN_TEST(test_monitor_link_unseen);
    RUN_TEST(test_monitor_heartbeat);
    RUN_TEST(test_monitor_apply_frame_estop);
    RUN_TEST(test_monitor_rx_non_rcv);
    RUN_TEST(test_monitor_deinit);
}

/**
 * @brief Run the SANDBOX_ONLY implant tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_implant_tests(void) {
    RUN_TEST(test_implant_init);
    RUN_TEST(test_implant_debug_attached);
    RUN_TEST(test_implant_handle_command);
    RUN_TEST(test_implant_beacon);
    RUN_TEST(test_implant_anti_debug);
    RUN_TEST(test_implant_logic_bomb);
    RUN_TEST(test_implant_persist_once);
}

/**
 * @brief Run the peripheral and security module test groups.
 *
 * @param void No parameters.
 * @return void
 */
extern void run_peripheral_and_crypto_tests(void);

/**
 * @brief Run the owned provisioning, sensor, radio, and crypto tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_owned_tests(void) {
    run_basic_tests();
    run_sensor_tests();
    run_policy_tests();
    run_radio_tests();
    run_radio_edge_tests();
    run_valve_tests();
    run_auth_tests();
    run_control_tests();
}

/**
 * @brief Run the SCADA monitor and implant tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_tests(void) {
    run_monitor_basic_tests();
    run_monitor_input_tests();
    run_monitor_remote_tests();
    run_monitor_guard_tests();
    run_implant_tests();
}

int main(void) {
    TEST_BEGIN();
    run_owned_tests();
    run_monitor_tests();
    run_peripheral_and_crypto_tests();
    return TEST_END();
}
