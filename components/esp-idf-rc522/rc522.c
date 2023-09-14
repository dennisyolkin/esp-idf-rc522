#include <freertos/FreeRTOS.h>
#include "freertos/timers.h"
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_log.h>
#include <esp_check.h>
#include <string.h>

#include "rc522.h"

static const char* TAG = "rc522";

typedef struct {
    bool calc_success;
    uint8_t crc0;
    uint8_t crc1;
} rc522_crc_t;

typedef struct {
    uint8_t bytes[6];
} rc522_key_t;

typedef enum {
    REG_COMMAND             = 0x01, // starts and stops command execution (table 23)
    REG_COMPL_EN            = 0x02, // enable and disable interrupt request control bits (table 25)
    REG_COM_IRQ             = 0x04, // interrupt request bits (table 29)
    REG_DIV_IRQ             = 0x05, // interrupt request bits (table 31)
    REG_ERROR               = 0x06, // error bits showing the error status of the last command executed (table 33)
    REG_STATUS              = 0x07, // communication status bits (table 35)
    REG_STATUS2             = 0x08, // receiver and transmitter status bits (table 37)
    REG_FIFO_DATA           = 0x09, // input and output of 64 byte FIFO buffer (table 39)
    REG_FIFO_LEVEL          = 0x0A, // number of bytes stored in the FIFO buffer (table 41)
    REG_CONTROL             = 0x0C, // miscellaneous control registers (table 45)
    REG_BIT_FRAMING         = 0x0D, // adjustments for bit-oriented frames (table 47)
    REG_MODE                = 0x11, // defines general modes for transmitting and receiving (table 55)
    REG_TX_CONTROL          = 0x14, // controls the logical behavior of the antenna driver pins TX1 and TX2 (table 61)
    REG_TX_ASK              = 0x15, // controls the setting of the transmission modulation (table 63)
    REG_CRC_RESULT_MSB      = 0x21, // shows the MSB and LSB values of the CRC calculation (table 87)
    REG_CRC_RESULT_LSB      = 0x22, // shows the MSB and LSB values of the CRC calculation (table 89)
    REG_MOD_WIDTH           = 0x24, // controls the modulation width setting (table 93)
    REG_RF_CFG              = 0x26, // configures the receiver gain (table 97)
    REG_TIMER_MODE_REG      = 0x2A, // defines settings for the internal timer (table 105)
    REG_TIMER_PRESCALER_REG = 0x2B, // defines settings for the internal timer (table 107)
    REG_TIMER_RELOAD_L      = 0x2C, // defines the 16-bit timer reload value (table 109)
    REG_TIMER_RELOAD_H      = 0x2D, // defines the 16-bit timer reload value (table 111)
    REG_VERSION             = 0x37, // hows the software version (table 131)

} rc522_register_t;

typedef enum {
	CMD_IDLE            = 0b0000, // 0x00, no action, cancels current command execution
	CMD_MEM             = 0b0001, // 0x01, stores 25 bytes into the internal buffer
	CMD_GEN_RND_ID      = 0b0010, // 0x02, generates a 10-byte random ID number
	CMD_CALC_CRC        = 0b0011, // 0x03, activates the CRC coprocessor or performs a self test
	CMD_TRANSMIT        = 0b0100, // 0x04, transmits data from the FIFO buffer
	CMD_NO_CMD_CHANGE   = 0b0111, // 0x07, no command change
	CMD_RECEIVE         = 0b1000, // 0x08, activates the receiver circuits
	CMD_TRANSCEIVE      = 0b1100, // 0x0C, transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission
	CMD_RESERVED        = 0b1101, // 0x0D, reserved for future use
	CMD_MF_AUTHENT      = 0b1110, // 0x0E, performs the MIFARE standard authentication as a reader
	CMD_SOFT_RESET      = 0b1111, // 0x0F, resets the MFRC522
} rc522_pcd_cmd_t;

typedef enum {
    PICC_CMD_REQUEST             = 0x26,
    PICC_CMD_WAKEUP              = 0x52,
    PICC_CMD_HALT                = 0x50,
    PICC_CMD_ANTICOL_SEL_CL1     = 0x93,
    PICC_CMD_ANTICOL_SEL_CL2     = 0x95,
    PICC_CMD_ANTICOL_SEL_CL3     = 0x97,
    PICC_CMD_AUTH_KEYA           = 0x60,
    PICC_CMD_AUTH_KEYB           = 0x61,
    PICC_CMD_READ                = 0x30,
    PICC_CMD_WRITE               = 0xA0,   
    PICC_CMD_DECREMENT           = 0xC0,
    PICC_CMD_INCREMENT           = 0xC1,
    PICC_CMD_RESTORE             = 0xC2,
    PICC_CMD_TRANSFER            = 0xB0,
    PICC_CMD_GET_VERSION         = 0x60,
} rc522_picc_cmd_t;

typedef enum {
    CER_TIMER_IR_EN       = 1<<0,
    CER_ERR_IR_EN         = 1<<1,
    CER_LOW_ALERT_IR_EN   = 1<<2,
    CER_HIGH_ALERT_IR_EN  = 1<<3,
    CER_IDLE_IR_EN        = 1<<4,
    CER_RX_IR_EN          = 1<<5,
    CER_TX_IR_EN          = 1<<6,
    CER_IR_INV            = 1<<7,
} rc522_coml_en_reg_t; // Control bits to enable and disable the passing of interrupt requests. (table 25/26)

typedef enum {
    IR_TIMER_DEC_TO_ZERO = 1<<0, // the timer decrements the timer value in register TCounterValReg to zero
    IR_ERROR             = 1<<1, // any error bit in the ErrorReg register is set
    IR_LOW_ALERT         = 1<<2, // Status1Reg register’s LoAlert bit is set
    IR_HIGH_ALERT        = 1<<3, // Status1Reg register’s HiAlert bit is set
    IR_IDLE              = 1<<4, // Idle
    IR_RX_EOS            = 1<<5, // receiver has detected the end of a valid data stream
    IR_TX_DONE           = 1<<6, // set immediately after the last bit of the transmitted data was sent out
    IR_SET               = 1<<7, //  indicates that the marked bits in the ComIrqReg register are set (1) / cleared (0)
} rc522_com_irq_reg_t; // Interrupt request bits (table 29/30)

typedef enum {
    ERR_PROTOCOL        = 1<<0,
    ERR_PARITY          = 1<<1,
    ERR_INVALID_CRC     = 1<<2,
    ERR_COLL            = 1<<3,
    ERR_BUFF_OVFL       = 1<<4,
    ERR_RESERVED        = 1<<5,
    ERR_TEMPERATURE     = 1<<6,
    ERR_WRITE           = 1<<7,
} rc522_errors_t;

typedef enum {
    RES_OK,
    RES_IR_ERROR,
    RES_NO_RESPONSE,
    RES_PROTOCOL_ERR,
    RES_PARITY_ERR,
    RES_COLLISION,
    RES_BUFF_OVERFLOW,
    RES_OUTPUT_BUFF_SMALL,
    RES_WRITE_FAIL,
    RES_BAD_RESP_LEN,
    RES_BAD_CRC,
    RES_UNEXPECTED_VAL,
    RES_CRYPTO_ERR,
    RES_TRANSPORT_ERR,
    RES_NO_CARD_PRESENT,
    RES_GENERAL_FAILURE,
    RES_TAG_TYPE_NOT_SUPPORTED,
    RES_NACK,
} rc522_res_t;

typedef enum {
    ST2_MF_CRYPTO1_ON  = 1<<3,
} rc522_status2reg_bits_t;

#define RC522_DEFAULT_SCAN_INTERVAL_MS (125)
#define RC522_DEFAULT_TASK_STACK_SIZE (4 * 1024)
#define RC522_DEFAULT_TASK_STACK_PRIORITY (4)
#define RC522_DEFAULT_SPI_CLOCK_SPEED_HZ (5000000)
#define RC522_DEFAULT_I2C_RW_TIMEOUT_MS (1000)
#define RC522_DEFAULT_I2C_CLOCK_SPEED_HZ (100000)

#define TX_CONTROL_REG_BOTH_RF_EN 0x03 // 0b11 which means Tx1RFEn & Tx2RFEn (Table 62)
#define RF_CFG_43db_GAIN 0x60
#define DIV_IRQ_CALC_CRC_ACTIVE 0x4 // 0b100 - the CalcCRC command is active and all data is processed (table 31/32)
#define FIFO_FLUSH_BUFFER 0x80 // table 41/42
#define BIT_FRAMING_START_SEND 0x80 // table 47/48
#define BIT_FRAMING_ALL_BITS_IN_LAST_BYTE 0x00  // table 47/48
#define REG_CONTROL_LAST_BITS_MASK 0b111
#define REG_MOD_WIDTH_RESET_VAL 0x26
#define TX_ASK_REG_FORCE_100_PERCENT_ASK 0x40
#define SEL_CASCADE_MASK 0x04
#define CASCADE_TAG 0x88
#define CARD_READ_MAX_DELAY_MS 40
#define CALC_CRC_MAX_DELAY_MS 90
#define WRITE_N_BUFFER_SIZE 48
#define VER_FIXED_HEADER 0x00
#define VER_PRODUCT_NTAG 0x04
#define VER_PROD_SUBTYPE_NTAG 0x02
#define MIFARE_ACK 0x0A

static rc522_key_t RC522_FACTORY_KEY = { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };

// clone of ESP_GOTO_ON_FALSE but without err_code
#define GOTO_ON_FALSE(a, goto_tag, log_tag, format, ...) do {                                   \
        if (unlikely(!(a))) {                                                                   \
            ESP_LOGE(log_tag, "%s(%d): " format, __FUNCTION__, __LINE__, ##__VA_ARGS__);        \
            goto goto_tag;                                                                      \
        }                                                                                       \
    } while (0)

#define CHECK_RES(x) do {                                                                                                   \
        rc522_res_t err_rc_ = (x);                                                                                          \
        if (unlikely(err_rc_ != RES_OK)) {                                                                                  \
            ESP_LOGE(TAG, "%s(%d) card_write err=%u %s", __FUNCTION__, __LINE__, err_rc_, rc522_res_to_str(err_rc_));       \
            return err_rc_;                                                                                                 \
        }                                                                                                                   \
    } while(0)


struct rc522 {
    bool running;                          /*<! Indicates whether rc522 task is running or not */
    rc522_config_t* config;                /*<! Configuration */
    TaskHandle_t task_handle;              /*<! Handle of task */
    esp_event_loop_handle_t event_handle;  /*<! Handle of event loop */
    spi_device_handle_t spi_handle;
    bool initialized;                      /*<! Set on the first start() when configuration is sent to rc522 */
    bool scanning;                         /*<! Whether the rc522 is in scanning or idle mode */
    bool tag_was_present_last_time;
    bool bus_initialized_by_user;          /*<! Whether the bus has been initialized manually by the user, before calling rc522_create function */
};

ESP_EVENT_DEFINE_BASE(RC522_EVENTS);

static esp_err_t rc522_spi_send(rc522_handle_t rc522, uint8_t* buffer, uint8_t length);
static esp_err_t rc522_spi_receive(rc522_handle_t rc522, uint8_t* buffer, uint8_t length, uint8_t addr);
static esp_err_t rc522_i2c_send(rc522_handle_t rc522, uint8_t* buffer, uint8_t length);
static esp_err_t rc522_i2c_receive(rc522_handle_t rc522, uint8_t* buffer, uint8_t length, uint8_t addr);

static void rc522_task(void* arg);

static esp_err_t rc522_write_n(rc522_handle_t rc522, uint8_t addr, uint8_t* data, uint8_t data_len) {
    uint8_t buffer[WRITE_N_BUFFER_SIZE];
    buffer[0] = addr;
    memcpy(buffer + 1, data, data_len);
    switch(rc522->config->transport) {
        case RC522_TRANSPORT_SPI:
            ESP_RETURN_ON_ERROR( rc522_spi_send(rc522, buffer, data_len + 1), TAG, "SPI send failed" );
            break;
        case RC522_TRANSPORT_I2C:
            ESP_RETURN_ON_ERROR( rc522_i2c_send(rc522, buffer, data_len + 1), TAG, "I2C send failed" );
            break;
        default:
            ESP_RETURN_ON_ERROR( ESP_ERR_INVALID_STATE, TAG, "unknown transport" );
    }
    return ESP_OK;
}

static inline esp_err_t rc522_write(rc522_handle_t rc522, uint8_t addr, uint8_t val) {
    return rc522_write_n(rc522, addr, &val, 1);
}

static uint8_t* rc522_read_to_buff(rc522_handle_t rc522, uint8_t addr, uint8_t* buffer, uint8_t len) {
    esp_err_t ret;
    switch(rc522->config->transport) {
        case RC522_TRANSPORT_SPI:
            ret = rc522_spi_receive(rc522, buffer, len, addr);
            break;
        case RC522_TRANSPORT_I2C:
            ret = rc522_i2c_receive(rc522, buffer, len, addr);
            break;
        default:
            ESP_LOGE(TAG, "read: Unknown transport");
            ret = ESP_ERR_INVALID_STATE; // unknown transport
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read data (err: %s)", esp_err_to_name(ret));
        return NULL;
    }
    return buffer;
}

// NOTE :: errors are ignored
static inline uint8_t rc522_read(rc522_handle_t rc522, uint8_t addr) {
    uint8_t res;
    rc522_read_to_buff(rc522, addr, &res, 1);
    return res;
}

static inline esp_err_t rc522_set_bitmask(rc522_handle_t rc522, uint8_t addr, uint8_t mask) {
    return rc522_write(rc522, addr, rc522_read(rc522, addr) | mask);
}

static inline esp_err_t rc522_clear_bitmask(rc522_handle_t rc522, uint8_t addr, uint8_t mask) {
    return rc522_write(rc522, addr, rc522_read(rc522, addr) & ~mask);
}

static inline uint8_t rc522_firmware(rc522_handle_t rc522) {
    return rc522_read(rc522, REG_VERSION);
}

static esp_err_t rc522_antenna_on(rc522_handle_t rc522) {
    esp_err_t err;
    if (~(rc522_read(rc522, REG_TX_CONTROL) & TX_CONTROL_REG_BOTH_RF_EN)) {
        err = rc522_set_bitmask(rc522, REG_TX_CONTROL, TX_CONTROL_REG_BOTH_RF_EN);
        if(err != ESP_OK) {
            return err;
        }
    }
    return rc522_write(rc522, REG_RF_CFG, RF_CFG_43db_GAIN);
}

rc522_config_t* rc522_clone_config(rc522_config_t* config)
{
    rc522_config_t* new_config = calloc(1, sizeof(rc522_config_t)); // FIXME: memcheck
    memcpy(new_config, config, sizeof(rc522_config_t));

    // defaults
    new_config->scan_interval_ms = config->scan_interval_ms < 50 ? RC522_DEFAULT_SCAN_INTERVAL_MS : config->scan_interval_ms;
    new_config->task_stack_size = config->task_stack_size == 0 ? RC522_DEFAULT_TASK_STACK_SIZE : config->task_stack_size;
    new_config->task_priority = config->task_priority == 0 ? RC522_DEFAULT_TASK_STACK_PRIORITY : config->task_priority;
    new_config->spi.clock_speed_hz = config->spi.clock_speed_hz == 0 ? RC522_DEFAULT_SPI_CLOCK_SPEED_HZ : config->spi.clock_speed_hz;
    new_config->i2c.rw_timeout_ms = config->i2c.rw_timeout_ms == 0 ? RC522_DEFAULT_I2C_RW_TIMEOUT_MS : config->i2c.rw_timeout_ms;
    new_config->i2c.clock_speed_hz = config->i2c.clock_speed_hz == 0 ? RC522_DEFAULT_I2C_CLOCK_SPEED_HZ : config->i2c.clock_speed_hz;

    return new_config;
}

static esp_err_t rc522_create_transport(rc522_handle_t rc522) {
    esp_err_t ret;

    switch(rc522->config->transport) {
        case RC522_TRANSPORT_SPI: {
                spi_device_interface_config_t devcfg = {
                    .clock_speed_hz = rc522->config->spi.clock_speed_hz,
                    .mode = 0,
                    .spics_io_num = rc522->config->spi.sda_gpio,
                    .queue_size = 7,
                    .flags = rc522->config->spi.device_flags,
                };

                rc522->bus_initialized_by_user = rc522->config->spi.bus_is_initialized;

                if(! rc522->bus_initialized_by_user) {
                    spi_bus_config_t buscfg = {
                        .miso_io_num = rc522->config->spi.miso_gpio,
                        .mosi_io_num = rc522->config->spi.mosi_gpio,
                        .sclk_io_num = rc522->config->spi.sck_gpio,
                        .quadwp_io_num = -1,
                        .quadhd_io_num = -1,
                    };

                    if(ESP_OK != (ret = spi_bus_initialize(rc522->config->spi.host, &buscfg, 0))) {
                        break;
                    }
                }

                ret = spi_bus_add_device(rc522->config->spi.host, &devcfg, &rc522->spi_handle);
            }
            break;
        case RC522_TRANSPORT_I2C: {
                i2c_config_t conf = {
                    .mode = I2C_MODE_MASTER,
                    .sda_io_num = rc522->config->i2c.sda_gpio,
                    .scl_io_num = rc522->config->i2c.scl_gpio,
                    .sda_pullup_en = GPIO_PULLUP_ENABLE,
                    .scl_pullup_en = GPIO_PULLUP_ENABLE,
                    .master.clk_speed = rc522->config->i2c.clock_speed_hz,
                };

                if(ESP_OK != (ret = i2c_param_config(rc522->config->i2c.port, &conf))) {
                    break;
                }

                ret = i2c_driver_install(rc522->config->i2c.port, conf.mode, false, false, 0x00);
            }
            break;
        default:
            ESP_LOGE(TAG, "create_transport: Unknown transport");
            ret = ESP_ERR_INVALID_STATE; // unknown transport
            break;
    }

    return ret;
}

esp_err_t rc522_create(rc522_config_t* config, rc522_handle_t* out_rc522) {
    ESP_RETURN_ON_FALSE(config && out_rc522, ESP_ERR_INVALID_ARG, TAG, "invalid config/handle");
    esp_err_t ret;

    rc522_handle_t rc522 = calloc(1, sizeof(struct rc522)); // FIXME: memcheck
    rc522->config = rc522_clone_config(config);

    if(ESP_OK != (ret = rc522_create_transport(rc522))) {
        ESP_LOGE(TAG, "Cannot create transport");
        rc522_destroy(rc522);
        return ret;
    }

    esp_event_loop_args_t event_args = {
        .queue_size = 1,
        .task_name = NULL, // no task will be created
    };

    if(ESP_OK != (ret = esp_event_loop_create(&event_args, &rc522->event_handle))) {
        ESP_LOGE(TAG, "Cannot create event loop");
        rc522_destroy(rc522);
        return ret;
    }

    rc522->running = true;
    if (xTaskCreate(rc522_task, "rc522_task", rc522->config->task_stack_size, rc522, rc522->config->task_priority, &rc522->task_handle) != pdTRUE) {
        ESP_LOGE(TAG, "Cannot create task");
        rc522_destroy(rc522);
        return ret;
    }

    *out_rc522 = rc522;
    return ESP_OK;
}

esp_err_t rc522_register_events(rc522_handle_t rc522, rc522_event_t event, esp_event_handler_t event_handler, void* event_handler_arg) {
    ESP_RETURN_ON_FALSE(rc522, ESP_ERR_INVALID_ARG, TAG, "no rc522 handle");
    return esp_event_handler_register_with(rc522->event_handle, RC522_EVENTS, event, event_handler, event_handler_arg);
}

esp_err_t rc522_unregister_events(rc522_handle_t rc522, rc522_event_t event, esp_event_handler_t event_handler) {
    ESP_RETURN_ON_FALSE(rc522, ESP_ERR_INVALID_ARG, TAG, "no rc522 handle");
    return esp_event_handler_unregister_with(rc522->event_handle, RC522_EVENTS, event, event_handler);
}

static const char* rc522_tag_type_str(rc522_tag_type_t tag_type) {
    switch (tag_type) {
		case TAG_TYPE_ISO_14443_4:		return "PICC compliant with ISO/IEC 14443-4";
		case TAG_TYPE_ISO_18092:		return "PICC compliant with ISO/IEC 18092 (NFC)";
		case TAG_TYPE_MIFARE_MINI:		return "MIFARE Mini, 320 bytes";
		case TAG_TYPE_MIFARE_1K:		return "MIFARE 1KB";
		case TAG_TYPE_MIFARE_4K:		return "MIFARE 4KB";
		case TAG_TYPE_MIFARE_UL:		return "MIFARE Ultralight or Ultralight C";
		case TAG_TYPE_MIFARE_PLUS:		return "MIFARE Plus";
		case TAG_TYPE_MIFARE_DESFIRE:	return "MIFARE DESFire";
		case TAG_TYPE_TNP3XXX:			return "MIFARE TNP3XXX";
		case TAG_TYPE_NOT_COMPLETE:	    return "SAK indicates UID is not complete.";
        case TAG_TYPE_NTAG213:          return "NTAG213";
        case TAG_TYPE_NTAG215:          return "NTAG215";
        case TAG_TYPE_NTAG216:          return "NTAG216";
		case TAG_TYPE_UNKNOWN:
		default:						return "Unknown type";
    }
}

static const char* rc522_res_to_str(rc522_res_t res) {
    switch (res) {
        case RES_OK: return "(ok)";
        case RES_IR_ERROR: return "interrupt error bit";
        case RES_NO_RESPONSE: return "no response / timeout";
        case RES_PROTOCOL_ERR: return "protocol error";
        case RES_PARITY_ERR: return "parity check failed";
        case RES_COLLISION: return "collision";
        case RES_BUFF_OVERFLOW: return "buffer overflow";
        case RES_OUTPUT_BUFF_SMALL: return "output buffer too small";
        case RES_WRITE_FAIL: return "write fail";
        case RES_BAD_RESP_LEN: return "bad response len";
        case RES_BAD_CRC: return "bad crc";
        case RES_UNEXPECTED_VAL: return "unexpected value";
        case RES_CRYPTO_ERR: return "crypt error";
        case RES_NO_CARD_PRESENT: return "no card present";
        case RES_GENERAL_FAILURE: return "general failure";
        case RES_TAG_TYPE_NOT_SUPPORTED: return "tag not supported";
        case RES_NACK: return "NACK";
        default: return "(unknown)";
    }
}

static rc522_crc_t rc522_calculate_crc(rc522_handle_t rc522, uint8_t *data, uint8_t data_len) {
    rc522_write(rc522, REG_COMMAND, CMD_IDLE); // stop any running command
    rc522_clear_bitmask(rc522, REG_DIV_IRQ, DIV_IRQ_CALC_CRC_ACTIVE);
    rc522_set_bitmask(rc522, REG_FIFO_LEVEL, FIFO_FLUSH_BUFFER); 
    rc522_write_n(rc522, REG_FIFO_DATA, data, data_len);
    rc522_write(rc522, REG_COMMAND, CMD_CALC_CRC);

    rc522_crc_t crc = { false, 0, 0 };

    uint64_t deadline = esp_timer_get_time() + CALC_CRC_MAX_DELAY_MS * 1000;
    vTaskDelay(pdMS_TO_TICKS(5));
    do {
        uint8_t nn = rc522_read(rc522, REG_DIV_IRQ);
        if (nn & DIV_IRQ_CALC_CRC_ACTIVE) {
            crc.calc_success = true;
            break;
        }
    } while (esp_timer_get_time() < deadline);

    rc522_write(rc522, REG_COMMAND, CMD_IDLE); // stop CRC calculation
    if (crc.calc_success) {
        crc.crc0 = rc522_read(rc522, REG_CRC_RESULT_LSB);
        crc.crc1 = rc522_read(rc522, REG_CRC_RESULT_MSB);
    }
    return crc;
}

static bool rc522_validate_crc(rc522_handle_t rc522, uint8_t *data, uint8_t len, uint8_t* crc) {
    rc522_crc_t calculated_crc = rc522_calculate_crc(rc522, data, len);
    ESP_RETURN_ON_FALSE( calculated_crc.calc_success, false, TAG, "failed to calc CRC" );
    return calculated_crc.crc0 == crc[0] && calculated_crc.crc1 == crc[1];
}

// buffer should be 2 bytes longer than data_len
static rc522_res_t rc522_append_crc(rc522_handle_t rc522, uint8_t *data, uint8_t data_len) {
    rc522_crc_t crc = rc522_calculate_crc(rc522, data, data_len);
    ESP_RETURN_ON_FALSE(crc.calc_success, RES_BAD_CRC, TAG, "failed to calc CRC");
    data[data_len] = crc.crc0;
    data[data_len + 1] = crc.crc1;
    return RES_OK;
}

static rc522_res_t rc522_card_write_ex(rc522_handle_t rc522, uint8_t cmd, uint8_t* data, uint8_t data_len, uint8_t* res_buff_out, uint8_t* res_len_out, uint8_t* last_byte_valid_bits_out) {
    esp_err_t ret = ESP_FAIL;
    //uint8_t irq = 0x00;
    uint8_t irq_wait = 0x00;

    if (cmd == CMD_MF_AUTHENT) {
        //irq = CER_ERR_IR_EN | CER_IDLE_IR_EN | CER_IR_INV;
        irq_wait = 0x10; //  receiver has detected the end of a valid data stream
    }
    else if (cmd == CMD_TRANSCEIVE) {
        //irq = CER_TIMER_IR_EN | CER_ERR_IR_EN | CER_LOW_ALERT_IR_EN | CER_IDLE_IR_EN | CER_RX_IR_EN | CER_TX_IR_EN | CER_IR_INV;
        irq_wait = 0x30; //  receiver has detected the end of a valid data stream (RxIRq) + (IdleIRq) 
    }

    //ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_COMPL_EN, irq), err, TAG, "REG_COMPL_EN failed" ); 
    ESP_GOTO_ON_ERROR( rc522_clear_bitmask(rc522, REG_COM_IRQ, IR_SET), err, TAG, "REG_COM_IRQ failed" );
    ESP_GOTO_ON_ERROR( rc522_set_bitmask(rc522, REG_FIFO_LEVEL, FIFO_FLUSH_BUFFER), err, TAG, "REG_FIFO_LEVEL failed" );
    ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_COMMAND, CMD_IDLE), err, TAG, "REG_COMMAND failed" );
    ESP_GOTO_ON_ERROR( rc522_write_n(rc522, REG_FIFO_DATA, data, data_len), err, TAG, "REG_FIFO_DATA failed" ); // FIFODataReg (input and output of 64 byte FIFO buffer)
    ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_COMMAND, cmd), err, TAG, "REG_COMMAND failed" );

    if (cmd == CMD_TRANSCEIVE) {
        ESP_GOTO_ON_ERROR( rc522_set_bitmask(rc522, REG_BIT_FRAMING, BIT_FRAMING_START_SEND), err, TAG, "REG_BIT_FRAMING failed" );
    }

    uint64_t deadline = esp_timer_get_time() + CARD_READ_MAX_DELAY_MS * 1000;
    vTaskDelay(pdMS_TO_TICKS(5));
    bool ir_success = false;
    do {
        uint8_t ir_bits = rc522_read(rc522, REG_COM_IRQ);
        if (ir_bits & IR_ERROR) {
            return RES_IR_ERROR;
        }
        if (ir_bits & IR_TIMER_DEC_TO_ZERO) {
            return RES_NO_RESPONSE;
        }
        ir_success = ir_bits & irq_wait;
        if (ir_success) {
            break;
        }
    } while (esp_timer_get_time() < deadline);
    ESP_GOTO_ON_ERROR( rc522_clear_bitmask(rc522, REG_BIT_FRAMING, BIT_FRAMING_START_SEND), err, TAG, "REG_BIT_FRAMING failed" );
    if (!ir_success) {
        return RES_NO_RESPONSE;
    }

    uint8_t err_reg = rc522_read(rc522, REG_ERROR);
    if (err_reg) {
        if (err_reg & ERR_PROTOCOL) return RES_PROTOCOL_ERR;
        if (err_reg & ERR_PARITY) return RES_PARITY_ERR;
        if (err_reg & ERR_COLL) return RES_COLLISION;
        if (err_reg & ERR_BUFF_OVFL) return RES_BUFF_OVERFLOW;
    }

    if (cmd == CMD_TRANSCEIVE) {
        uint8_t fifo_bytes = rc522_read(rc522, REG_FIFO_LEVEL);
        uint8_t bits_in_last_byte = rc522_read(rc522, REG_CONTROL) & REG_CONTROL_LAST_BITS_MASK;
        uint8_t actual_res_len = fifo_bytes;
        if (res_len_out && res_buff_out) {
            if (*res_len_out < actual_res_len) {
                ESP_LOGE(TAG, "rc522_card_write_ex: output buffer too small (%u < %u)", *res_len_out, actual_res_len);
                return RES_OUTPUT_BUFF_SMALL;
            }
            *res_len_out = actual_res_len;
            if (last_byte_valid_bits_out) {
                *last_byte_valid_bits_out = bits_in_last_byte;
            }

            for (uint8_t i = 0; i < *res_len_out; i++) {
                res_buff_out[i] = rc522_read(rc522, REG_FIFO_DATA);
            }
        }
    }
    return RES_OK;
err:
    ESP_LOGE(TAG, "rc522_card_write_ex: generic error %u", ret);
    return RES_GENERAL_FAILURE;
}

static rc522_res_t rc522_request(rc522_handle_t rc522, uint16_t* atqa_out) {
    rc522_write(rc522, REG_BIT_FRAMING, 0x07); // REQA cmd only 7 bits
    uint8_t cmd = PICC_CMD_REQUEST;
    uint8_t buff_out[2];
    uint8_t res_len = 2;
    rc522_res_t resp = rc522_card_write_ex(rc522, CMD_TRANSCEIVE, &cmd, 1, buff_out, &res_len, NULL);
    if (resp != RES_OK && resp != RES_NO_RESPONSE) {
        ESP_LOGE(TAG, "card write failed: %u (%s)", resp, rc522_res_to_str(resp));
        return resp;
    }
    if (resp == RES_NO_RESPONSE || res_len == 0) {
        return RES_NO_CARD_PRESENT;
    } else if (res_len == 2) {
        *atqa_out = (((uint16_t)buff_out[1]) << 8) | buff_out[0];
        return RES_OK;
    } else {
        ESP_LOGE(TAG, "rc522_request: unexpected result len (%u)", res_len);
        return RES_BAD_RESP_LEN;
    }
    return RES_GENERAL_FAILURE;
}

static rc522_res_t rc522_anticoll(rc522_handle_t rc522, uint8_t cascade_lvl, uint8_t* uid_out) {
    ESP_RETURN_ON_FALSE( rc522_write(rc522, REG_BIT_FRAMING, BIT_FRAMING_ALL_BITS_IN_LAST_BYTE) == ESP_OK, RES_WRITE_FAIL, TAG, "bit framing write failed" );
    uint8_t cmd = PICC_CMD_ANTICOL_SEL_CL1 + 2 * cascade_lvl;

    uint8_t res_len = 5;
    CHECK_RES( rc522_card_write_ex(rc522, CMD_TRANSCEIVE, (uint8_t[]) { cmd, 0x20 }, 2, uid_out, &res_len, NULL) );
    ESP_RETURN_ON_FALSE( res_len == 5, RES_BAD_RESP_LEN, TAG, "unexpected response length: %u", res_len );
    uint8_t crc = uid_out[0] ^ uid_out[1] ^ uid_out[2] ^ uid_out[3];
    ESP_RETURN_ON_FALSE( crc == uid_out[4], RES_BAD_CRC, TAG, "response crc invalid" );
    return RES_OK;
}

static rc522_res_t rc522_select_tag(rc522_handle_t rc522, uint8_t cascade_lvl, uint8_t* uid, uint8_t* sak_out) {
    uint8_t cmd = PICC_CMD_ANTICOL_SEL_CL1 + 2 * cascade_lvl;
    uint8_t buf[] = { cmd, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    for (uint8_t i = 0; i < 5; i++) {
      buf[i + 2] = uid[i];
    }
    CHECK_RES( rc522_append_crc(rc522, buf, 7) );

    uint8_t buff_out[3];
    uint8_t res_data_len = 3;
    CHECK_RES( rc522_card_write_ex(rc522, CMD_TRANSCEIVE, buf, 9, buff_out, &res_data_len, NULL) );

    ESP_RETURN_ON_FALSE( res_data_len == 3, RES_BAD_RESP_LEN, TAG, "unexpected result data len (%u)", res_data_len ); // SAK (1 byte) + CRC (2 bytes)
    ESP_RETURN_ON_FALSE( rc522_validate_crc(rc522, buff_out, 1, buff_out + 1), RES_BAD_CRC, TAG, "invalid CRC" );
    *sak_out = buff_out[0];

    return RES_OK;
}

static rc522_res_t rc522_anticoll_and_select(rc522_handle_t rc522, rc522_tag_t* tag_out) {
    tag_out->uid_complete = false;
    tag_out->uid_len = 0;
    tag_out->type = TAG_TYPE_NOT_COMPLETE;
    uint8_t buff[5];
    for (uint8_t cascade_lvl = 0; cascade_lvl < 3; ++cascade_lvl) {
        CHECK_RES( rc522_anticoll(rc522, cascade_lvl, buff) );

        uint8_t uid_part_start = (buff[0] == CASCADE_TAG)? 1 : 0;
        for (uint8_t i = uid_part_start; i < 4; ++i) {
            tag_out->uid[tag_out->uid_len++] = buff[i];
        }
        rc522_res_t select_res = rc522_select_tag(rc522, cascade_lvl, buff, &(tag_out->sak));
        if (select_res != RES_OK) {
            ESP_LOGE(TAG, "select failed on level %u, error: %u-%s", cascade_lvl, select_res, rc522_res_to_str(select_res) );
            return select_res;
        }
        if (buff[0] != CASCADE_TAG) {
            bool sak_uid_complete = (tag_out->sak & SEL_CASCADE_MASK) == 0;
            ESP_RETURN_ON_FALSE( sak_uid_complete, RES_UNEXPECTED_VAL, TAG, "sak: uid not complete" );
            tag_out->uid_complete = true;
            break;
        }
    }
    return RES_OK;
} 

static rc522_res_t rc522_auth(rc522_handle_t rc522, uint8_t auth_cmd, uint8_t block_addr, rc522_key_t* key, rc522_tag_t* tag) {
    uint8_t buf[12] = { auth_cmd, block_addr, 0}; // cmd, blockAddr, key*6, uid*4 (uid last 4 bytes)
    memcpy(buf + 2, key->bytes, 6);
    memcpy(buf + 8, tag->uid + tag->uid_len - 4, 4);

    uint8_t res_data_len = 0;
    CHECK_RES( rc522_card_write_ex(rc522, CMD_MF_AUTHENT, buf, 12, NULL, &res_data_len, NULL) );

    uint8_t status2 = rc522_read(rc522, REG_STATUS2);
    if ((status2 & ST2_MF_CRYPTO1_ON) == 0) {
        ESP_LOGE(TAG, "rc522_auth failed. Invalid key?");
        return RES_CRYPTO_ERR;
    }
    return RES_OK;
}

static rc522_res_t rc522_read_block(rc522_handle_t rc522, uint8_t block_addr, uint8_t* buff_out) {
    uint8_t buff[4] = { PICC_CMD_READ, block_addr, 0x00, 0x00 }; // cmd, blockAddr, crc0, crc1
    CHECK_RES( rc522_append_crc(rc522, buff, 2) );
    uint8_t response[18]; // 16 + 2 (crc)
    uint8_t res_data_len = sizeof(response);
    CHECK_RES( rc522_card_write_ex(rc522, CMD_TRANSCEIVE, buff, 4, response, &res_data_len, NULL) );
    ESP_RETURN_ON_FALSE(res_data_len == sizeof(response), RES_BAD_RESP_LEN, TAG, "unexpected result len: %u", res_data_len);
    ESP_RETURN_ON_FALSE( rc522_validate_crc(rc522, response, 16, response + 16), RES_BAD_CRC, TAG, "invalid CRC" );

    memcpy(buff_out, response, 16);
    return RES_OK;
}

static rc522_res_t rc522_mifare_transceive(rc522_handle_t rc522, uint8_t* data, uint8_t len, bool accept_timeout) {
    uint8_t buff[18];
    memcpy(buff, data, len);
    CHECK_RES( rc522_append_crc(rc522, buff, len) );
    uint8_t resp_len = 4;
    uint8_t resp[resp_len];
    uint8_t valid_bits = 0;
    rc522_res_t write_res = rc522_card_write_ex(rc522, CMD_TRANSCEIVE, buff, len + 2, resp, &resp_len, &valid_bits);
    bool success = write_res == RES_OK || (accept_timeout && write_res == RES_NO_RESPONSE);
    ESP_RETURN_ON_FALSE( success, write_res, TAG, "card write failed" );
    ESP_RETURN_ON_FALSE( resp_len == 1 && valid_bits == 4, RES_BAD_RESP_LEN, TAG, "unexpected response len" );
    ESP_RETURN_ON_FALSE( resp[0] == MIFARE_ACK, RES_NACK, TAG, "NACK=%u", resp[0] );
    return RES_OK;
}

// writes 16 bytes to Mifare Classic
static rc522_res_t rc522_write_block(rc522_handle_t rc522, uint8_t block_addr, uint8_t* data) {
    uint8_t cmd_buff[2] = { PICC_CMD_WRITE, block_addr };
    CHECK_RES( rc522_mifare_transceive(rc522, cmd_buff, 2, false) );
    CHECK_RES( rc522_mifare_transceive(rc522, data, 16, false) );
    return RES_OK;
}

esp_err_t rc522_start(rc522_handle_t rc522) {
    if (!rc522) {
        return ESP_ERR_INVALID_ARG;
    }
    if (rc522->scanning) {
        return ESP_OK;
    }

    esp_err_t ret = ESP_FAIL;
    if (!rc522->initialized) {
        // Read / write test
        const uint8_t test_addr = REG_MOD_WIDTH, test_val = REG_MOD_WIDTH_RESET_VAL - 1;
        for (uint8_t i = test_val; i < test_val + 2; i++) {
            ESP_GOTO_ON_ERROR( rc522_write(rc522, test_addr, i), err, TAG, "write test failed: %d", ret );
            ESP_GOTO_ON_FALSE( rc522_read(rc522, test_addr) == i, ESP_FAIL, err, TAG, "read test failed" );
        }

        ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_COMMAND, CMD_SOFT_RESET), err, TAG, "fail" );
        ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_TIMER_MODE_REG, 0x8D), err, TAG, "fail" ); // 0x8D = 0b10001101 = [timer starts automatically] + [1101 as high buts for prescaler]
        ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_TIMER_PRESCALER_REG, 0x3E), err, TAG, "fail" ); // prescaler - lower 8 bits
        ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_TIMER_RELOAD_H, 0x1E), err, TAG, "fail" );
        ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_TIMER_RELOAD_L, 0x00), err, TAG, "fail" );
        ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_TX_ASK, TX_ASK_REG_FORCE_100_PERCENT_ASK), err, TAG, "fail" );
        ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_MODE, 0x3D), err, TAG, "fail" ); // table 56; 0x3d = CRCPreset(01, 6363h); pin polarity; TxWaitRF

        ESP_GOTO_ON_ERROR( rc522_antenna_on(rc522), err, TAG, "antenna_on failed" );
        ESP_GOTO_ON_ERROR( rc522_write(rc522, REG_COMPL_EN, 0x00), err, TAG, "REG_COMPL_EN failed" ); 

        rc522->initialized = true;
        ESP_LOGI(TAG, "Initialized (firmware v%d.0)", (rc522_firmware(rc522) & 0x03));
    }
    rc522->scanning = true;
    return ESP_OK;
err:
    rc522_destroy(rc522);
    return ret;
}

esp_err_t rc522_pause(rc522_handle_t rc522) {
    if (!rc522) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!rc522->scanning) {
        return ESP_OK;
    }
    rc522->scanning = false;

    return ESP_OK;
}

static void rc522_destroy_transport(rc522_handle_t rc522) {
    switch(rc522->config->transport) {
        case RC522_TRANSPORT_SPI:
            spi_bus_remove_device(rc522->spi_handle);
            if (rc522->bus_initialized_by_user) {
                spi_bus_free(rc522->config->spi.host);
            }
            break;
        case RC522_TRANSPORT_I2C:
            i2c_driver_delete(rc522->config->i2c.port);
            break;
        default:
            ESP_LOGE(TAG, "destroy_transport: Unknown transport");
    }
}

void rc522_destroy(rc522_handle_t rc522) {
    if (!rc522) {
        return;
    }

    if (xTaskGetCurrentTaskHandle() == rc522->task_handle) {
        ESP_LOGE(TAG, "Cannot destroy rc522 from event handler");
        return;
    }

    rc522_pause(rc522); // stop task
    rc522->running = false; // task will delete himself
    // FIXME: Wait for task to exit
    rc522_destroy_transport(rc522);
    if (rc522->event_handle) {
        esp_event_loop_delete(rc522->event_handle);
        rc522->event_handle = NULL;
    }
    free(rc522->config);
    rc522->config = NULL;
    free(rc522);
    rc522 = NULL;
}

static esp_err_t rc522_dispatch_event(rc522_handle_t rc522, rc522_event_t event, void* data) {
    if (!rc522) {
        return ESP_ERR_INVALID_ARG;
    }

    rc522_event_data_t e_data = {
        .rc522 = rc522,
        .ptr = data,
    };
    esp_err_t err;
    if (ESP_OK != (err = esp_event_post_to(rc522->event_handle, RC522_EVENTS, event, &e_data, sizeof(rc522_event_data_t), portMAX_DELAY))) {
        return err;
    }

    return esp_event_loop_run(rc522->event_handle, 0);
}

static esp_err_t rc522_spi_send(rc522_handle_t rc522, uint8_t* buffer, uint8_t length) {
    // MSB = 0 (write); LSB is always 0
    buffer[0] = (buffer[0] << 1) & 0x7E;

    return spi_device_transmit(rc522->spi_handle, &(spi_transaction_t){
        .length = 8 * length,
        .tx_buffer = buffer,
    });
}

static esp_err_t rc522_spi_receive(rc522_handle_t rc522, uint8_t* buffer, uint8_t length, uint8_t addr) {
    // MSB = 1 (read); LSB is always 0
    addr = ((addr << 1) & 0x7E) | 0x80;

    esp_err_t ret;

    if (SPI_DEVICE_HALFDUPLEX & rc522->config->spi.device_flags) {
        ret = spi_device_transmit(rc522->spi_handle, &(spi_transaction_t){
            .flags = SPI_TRANS_USE_TXDATA,
            .length = 8,
            .tx_data[0] = addr,
            .rxlength = 8 * length,
            .rx_buffer = buffer,
        });
    } else { // Fullduplex
        if (ESP_OK != (ret = spi_device_transmit(rc522->spi_handle, &(spi_transaction_t){
            .flags = SPI_TRANS_USE_TXDATA,
            .length = 8,
            .tx_data[0] = addr,
        }))) {
            return ret;
        };

        ret = spi_device_transmit(rc522->spi_handle, &(spi_transaction_t){
            .flags = 0x00,
            .length = 8,
            .rxlength = 8 * length,
            .rx_buffer = buffer,
        });
    }

    return ret;
}

static esp_err_t rc522_i2c_send(rc522_handle_t rc522, uint8_t* buffer, uint8_t length) {
    return i2c_master_write(rc522, buffer, length, true);
}

static esp_err_t rc522_i2c_receive(rc522_handle_t rc522, uint8_t* buffer, uint8_t length, uint8_t addr) {
    i2c_master_write(rc522, buffer, length, true);
    return i2c_master_read(rc522, &addr, length, I2C_MASTER_LAST_NACK);
}

rc522_res_t rc522_ntag_pwd_auth(rc522_handle_t rc522) {
    uint8_t buf[] = { 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
    CHECK_RES( rc522_append_crc(rc522, buf, 5) );
    uint8_t buff_out[16];
    uint8_t res_data_n = 16;
    CHECK_RES( rc522_card_write_ex(rc522, CMD_TRANSCEIVE, buf, 7, buff_out, &res_data_n, NULL) );
    ESP_LOGI(TAG, "rc522_ntag_pwd_auth: response len=%u, data:", res_data_n);
    ESP_LOG_BUFFER_HEX(TAG, buff_out, res_data_n);
    ESP_LOG_BUFFER_HEX(TAG, buf, 7);
    return RES_OK;
}

static rc522_res_t rc522_get_version(rc522_handle_t rc522, uint8_t* res_out) {
    uint8_t buf[] = { PICC_CMD_GET_VERSION, 0x00, 0x00 }; // 60h crc0 crc1
    CHECK_RES( rc522_append_crc(rc522, buf, 1) );
    uint8_t buff_out[10];
    uint8_t res_data_n = 10;
    CHECK_RES( rc522_card_write_ex(rc522, CMD_TRANSCEIVE, buf, 3, buff_out, &res_data_n, NULL) );
    ESP_RETURN_ON_FALSE( res_data_n == 10, RES_BAD_RESP_LEN, TAG, "unexpected length of GET_VERSION response" );
    memcpy(res_out, buff_out, 8);
    return RES_OK;
}

static rc522_res_t rc522_halt(rc522_handle_t rc522) {
    uint8_t buf[] = { PICC_CMD_HALT, 0x00, 0x00, 0x00 }; // 50h 00h crc0 crc1
    CHECK_RES( rc522_append_crc(rc522, buf, 2) );
    rc522_res_t res = rc522_card_write_ex(rc522, CMD_TRANSCEIVE, buf, 4, NULL, NULL, NULL);
    rc522_clear_bitmask(rc522, 0x08, 0x08);
    // according to datasheet, HALT should never return any response
    if (res == RES_NO_RESPONSE) {
        return RES_OK;
    } else {
        return RES_GENERAL_FAILURE;
    }
}

static int rc522_sprint_buff(char* str, uint8_t* buff, uint8_t len) {
    uint8_t pos = 0;
    for (int i = 0; i < len; ++i) {
        pos += sprintf(str + pos, "%02x ", buff[i]);
    }
    return pos;
}

static int rc522_sprint_buff_ascii(char* str, uint8_t* buff, uint8_t len) {
    uint8_t pos = 0;
    str[pos++] = '|';
    for (int i = 0; i < len; ++i) {
        str[pos++] = (buff[i] >= 32 && buff[i] <= 126)? buff[i] : '.';
    }
    pos += sprintf(str + pos, "|");
    return pos;
}

static rc522_res_t rc522_read_mf_block(rc522_handle_t rc522, rc522_tag_t* tag, uint8_t sector, uint8_t block, uint8_t* data_out) {
    uint8_t block_addr = sector * 4 + block;
    CHECK_RES( rc522_auth(rc522, PICC_CMD_AUTH_KEYA, block_addr, &RC522_FACTORY_KEY, tag) );
    CHECK_RES( rc522_read_block(rc522, block_addr, data_out) );
    return RES_OK;
}

static void rc522_print_mf_block(uint8_t sector, uint8_t block, bool sec_trailer, uint8_t* data, uint8_t access_bits) {
    char print_buff[100];
    int pos = 0;
    if (sec_trailer) {
        pos += sprintf(print_buff, "%3u *%2u |", sector, block);
    } else {
        pos += sprintf(print_buff, "%3u %3u |", sector, block);
    }
    pos += rc522_sprint_buff(print_buff + pos, data, 16);
    pos += rc522_sprint_buff_ascii(print_buff + pos, data, 16);
    pos += sprintf(print_buff + pos, " %u %u %u  |", (access_bits >> 2) & 1, (access_bits >> 1) & 1, (access_bits >> 0) & 1);
    ESP_LOGI(TAG, "%s", print_buff);
}

static rc522_res_t rc522_mf_extract_acces_bits(uint8_t* sec_trailer_data, uint8_t* acc_bits_out) {
    uint8_t c1  = sec_trailer_data[7] >> 4;
    uint8_t c2  = sec_trailer_data[8] & 0xF;
    uint8_t c3  = sec_trailer_data[8] >> 4;
    uint8_t c1_ = sec_trailer_data[6] & 0xF;
    uint8_t c2_ = sec_trailer_data[6] >> 4;
    uint8_t c3_ = sec_trailer_data[7] & 0xF;
    bool invertedError = (c1 != (~c1_ & 0xF)) || (c2 != (~c2_ & 0xF)) || (c3 != (~c3_ & 0xF));
    ESP_RETURN_ON_FALSE( !invertedError, RES_BAD_CRC, TAG, "inverted bits check failed" );
    acc_bits_out[0] = ((c1 & 1) << 2) | ((c2 & 1) << 1) | ((c3 & 1) << 0); // block 0 (for sectors 0-31) or blocks 0-4 (for sectors 32-39)
    acc_bits_out[1] = ((c1 & 2) << 1) | ((c2 & 2) << 0) | ((c3 & 2) >> 1); // block 1 (for sectors 0-31) or blocks 5-9 (for sectors 32-39)
    acc_bits_out[2] = ((c1 & 4) << 0) | ((c2 & 4) >> 1) | ((c3 & 4) >> 2); // block 2 (for sectors 0-31) or blocks 10-14 (for sectors 32-39)
    acc_bits_out[3] = ((c1 & 8) >> 1) | ((c2 & 8) >> 2) | ((c3 & 8) >> 3); // sector trailer, block 3 (for sectors 0-31) or block 15 (for sectors 32-39)
    return RES_OK;
}

static rc522_res_t rc522_dump_mf_classic(rc522_handle_t rc522, rc522_tag_t* tag, uint8_t sectors_cnt) {
    ESP_LOGI(TAG, "SEC BLK | 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F |      ASCII     | Access |");
    uint8_t block_data[16];
    uint8_t sec_trailer_data[16];
    uint8_t access_bits[4]; // first 3 bits of each element are access bits; 4 groups - 1 per block for MF1k or for ranges for MF4K
    for (uint8_t sector = 0; sector < sectors_cnt; ++sector) {
        uint8_t blocks_cnt = (sector < 32)? 4 : 16;
        uint8_t trailer_secrod_idx = (sector < 32)? 3 : 15;
        CHECK_RES( rc522_read_mf_block(rc522, tag, sector, trailer_secrod_idx, sec_trailer_data) );
        CHECK_RES( rc522_mf_extract_acces_bits(sec_trailer_data, access_bits) );
        for (uint8_t block = 0; block < blocks_cnt - 1; ++block) {
            CHECK_RES( rc522_read_mf_block(rc522, tag, sector, block, block_data) );
            uint8_t access_group = (blocks_cnt == 4)? block : (block / 5);
            rc522_print_mf_block(sector, block, false, block_data, access_bits[access_group]);
        }
        rc522_print_mf_block(sector, trailer_secrod_idx, true, sec_trailer_data, access_bits[3]);
    }
    return RES_OK;
}

static rc522_res_t rc522_dump_pages(rc522_handle_t rc522, uint8_t pages_cnt) {
    ESP_LOGI(TAG, "Page | 0  1  2  3  |ASCI|");
    uint8_t block_data[16];
    char buff[48];
    for (uint8_t page = 0; page < pages_cnt; page += 4) {
        CHECK_RES( rc522_read_block(rc522, page, block_data) );
        for (uint8_t pp = 0; pp < 4; ++pp) {
            int pos = sprintf(buff, "%4u | ", page + pp);
            pos += rc522_sprint_buff(buff + pos, block_data + pp * 4, 4);
            pos += rc522_sprint_buff_ascii(buff + pos, block_data + pp * 4, 4);
            ESP_LOGI(TAG, "%s", buff);
        }
    }
    return RES_OK;
}

static rc522_res_t rc522_dump_tag(rc522_handle_t rc522, rc522_tag_t* tag) {
    switch (tag->type) {
    case TAG_TYPE_MIFARE_1K: return rc522_dump_mf_classic(rc522, tag, 16);
    case TAG_TYPE_MIFARE_4K: return rc522_dump_mf_classic(rc522, tag, 40);
    case TAG_TYPE_MIFARE_UL: return rc522_dump_pages(rc522, 16);
    case TAG_TYPE_NTAG213:   return rc522_dump_pages(rc522, 45);
    case TAG_TYPE_NTAG215:   return rc522_dump_pages(rc522, 135);
    case TAG_TYPE_NTAG216:   return rc522_dump_pages(rc522, 231);
    default:
        ESP_LOGW(TAG, "Dump is not possible - tag type %s not supported", rc522_tag_type_str(tag->type));
        return RES_TAG_TYPE_NOT_SUPPORTED;
    }
}

// doc: https://www.nxp.com/docs/en/application-note/AN10833.pdf
static rc522_res_t rc522_calc_tag_type(rc522_handle_t rc522, rc522_tag_t* tag) {
    tag->type = TAG_TYPE_UNKNOWN;
    uint8_t sak = (tag->sak & 0x7F);

    // first, check for non-ambiguous sak values
    if (sak == 0x04) tag->type = TAG_TYPE_NOT_COMPLETE;
    else if (sak == 0x09) tag->type = TAG_TYPE_MIFARE_MINI;
    else if (sak == 0x09) tag->type = TAG_TYPE_MIFARE_MINI;
    else if (sak == 0x08) tag->type = TAG_TYPE_MIFARE_1K;
    else if (sak == 0x18) tag->type = TAG_TYPE_MIFARE_4K;
    else if (sak == 0x10 || sak == 0x11) tag->type = TAG_TYPE_MIFARE_PLUS;
    else if (sak == 0x01) tag->type = TAG_TYPE_TNP3XXX;
    else if (sak == 0x20) tag->type = TAG_TYPE_ISO_14443_4;
    else if (sak == 0x40) tag->type = TAG_TYPE_ISO_18092;

    if (tag->type != TAG_TYPE_UNKNOWN) {
        return RES_OK;
    }

    // try GET_VERSION. If card does not support it, it will go to HALT state (currently it's not properly handled)
    uint8_t ver_resp[8];
    CHECK_RES( rc522_get_version(rc522, ver_resp) );
    // check for NTAG213/215/216
    if (ver_resp[0] == VER_FIXED_HEADER && ver_resp[2] == VER_PRODUCT_NTAG && ver_resp[3] == VER_PROD_SUBTYPE_NTAG) {
        switch (ver_resp[6]) {
            case 0x0F: tag->type = TAG_TYPE_NTAG213; return RES_OK;
            case 0x11: tag->type = TAG_TYPE_NTAG215; return RES_OK;
            case 0x13: tag->type = TAG_TYPE_NTAG216; return RES_OK; 
            default: return RES_UNEXPECTED_VAL;
        }
    }
    return RES_UNEXPECTED_VAL;
}

rc522_res_t test_write(rc522_handle_t rc522, rc522_tag_t* tag) {
    uint8_t buff[16] = "From Denis :) :)";
    uint8_t addr = 13;
    CHECK_RES( rc522_auth(rc522, PICC_CMD_AUTH_KEYA, addr, &RC522_FACTORY_KEY, tag) );
    CHECK_RES( rc522_write_block(rc522, addr, buff) );
    return RES_OK;
}

static void rc522_task(void* arg) {
    rc522_handle_t rc522 = (rc522_handle_t) arg;

    uint8_t last_uid[10];
    uint8_t last_uid_len = 0;
    while (rc522->running) {
        if (!rc522->scanning) {
            vTaskDelay(100 / portTICK_PERIOD_MS);
            continue;
        }

        bool dump_success = false;
        rc522_tag_t tag;
        if (rc522_request(rc522, &(tag.atqa)) == RES_OK) {
            bool select_success = rc522_anticoll_and_select(rc522, &tag) == RES_OK;
            if (!select_success) {
                rc522->tag_was_present_last_time = false;
            } else {
                rc522_calc_tag_type(rc522, &tag); // for now allowed to fail

                ESP_LOGI(TAG, "Tag scanned! UID len: %u, tag type: %s", tag.uid_len, rc522_tag_type_str(tag.type));
                ESP_LOG_BUFFER_HEX(TAG, tag.uid, tag.uid_len);

                dump_success = rc522_dump_tag(rc522, &tag) == RES_OK;
                //test_write(rc522, &tag);

                if (last_uid_len != tag.uid_len || memcmp(last_uid, tag.uid, last_uid_len) != 0) {
                    last_uid_len = tag.uid_len;
                    memcpy(last_uid, tag.uid, tag.uid_len);
                    rc522_dispatch_event(rc522, RC522_EVENT_TAG_SCANNED, &tag);
                    rc522->tag_was_present_last_time = true;
                } else {
                    rc522->tag_was_present_last_time = false;
                }
            }
            rc522_halt(rc522);
        }

        int delay_interval_ms = rc522->config->scan_interval_ms;

        if(rc522->tag_was_present_last_time) {
            delay_interval_ms *= 2; // extra scan-bursting prevention
        }

        if (dump_success) {
            delay_interval_ms = 3000;
        }

        vTaskDelay(delay_interval_ms / portTICK_PERIOD_MS);
    }

    vTaskDelete(NULL);
}
