#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <esp_event.h>
#include <driver/spi_master.h>
#include <driver/i2c.h>

#define RC522_I2C_ADDRESS (0x28)

ESP_EVENT_DECLARE_BASE(RC522_EVENTS);

typedef struct rc522* rc522_handle_t;

typedef enum {
    RC522_TRANSPORT_SPI,
    RC522_TRANSPORT_I2C,
} rc522_transport_t;

typedef struct {
    uint16_t scan_interval_ms;         /*<! How fast will ESP32 scan for nearby tags, in miliseconds */
    size_t task_stack_size;            /*<! Stack size of rc522 task */
    uint8_t task_priority;             /*<! Priority of rc522 task */
    rc522_transport_t transport;       /*<! Transport that will be used. Defaults to SPI */
    union {
        struct {
            spi_host_device_t host;
            int miso_gpio;
            int mosi_gpio;
            int sck_gpio;
            int sda_gpio;
            int clock_speed_hz;
            uint32_t device_flags;     /*<! Bitwise OR of SPI_DEVICE_* flags */
            bool bus_is_initialized; // Set to true if the bus is already initialized. Will be removed in future, once when https://github.com/espressif/esp-idf/issues/8745 is resolved
        } spi;
        struct {
            i2c_port_t port;
            int sda_gpio;
            int scl_gpio;
            int rw_timeout_ms;
            uint32_t clock_speed_hz;
        } i2c;
    };
} rc522_config_t;

typedef enum {
    RC522_EVENT_ANY = ESP_EVENT_ANY_ID,
    RC522_EVENT_NONE,
    RC522_EVENT_TAG_REQUESTED,  /*<! Tag requested */
    RC522_EVENT_TAG_SCANNED,    /*<! Tag scanned */
} rc522_event_t;

typedef struct {
    rc522_handle_t rc522;
    void* ptr;
} rc522_event_data_t;


typedef enum {
    TAG_TYPE_NOT_COMPLETE,
    TAG_TYPE_MIFARE_MINI,
    TAG_TYPE_MIFARE_1K,
    TAG_TYPE_MIFARE_4K,
    TAG_TYPE_MIFARE_UL,
    TAG_TYPE_MIFARE_PLUS,
    TAG_TYPE_MIFARE_DESFIRE,
    TAG_TYPE_TNP3XXX,
    TAG_TYPE_ISO_14443_4,
    TAG_TYPE_ISO_18092,
    TAG_TYPE_NTAG213,
    TAG_TYPE_NTAG215,
    TAG_TYPE_NTAG216,
    TAG_TYPE_UNKNOWN,
} rc522_tag_type_t;

typedef struct {
    uint8_t uid[10];
    uint8_t uid_len;
    bool uid_complete;
    uint8_t sak;
    uint16_t atqa;
    rc522_tag_type_t type;
} rc522_tag_t;

/**
 * @brief Create RC522 scanner handle.
 *        To start scanning tags call the rc522_start function.
 * @param config Configuration
 * @param out_rc522 Pointer to resulting new handle
 * @return ESP_OK on success
 */
esp_err_t rc522_create(rc522_config_t* config, rc522_handle_t* out_rc522);

esp_err_t rc522_register_events(rc522_handle_t rc522, rc522_event_t event, esp_event_handler_t event_handler, void* event_handler_arg);

esp_err_t rc522_unregister_events(rc522_handle_t rc522, rc522_event_t event, esp_event_handler_t event_handler);

/**
 * @brief Start to scan tags. If already started, ESP_OK will just be returned. Initialization function had to be
 *        called before this one.
 * @param rc522 Handle
 * @return ESP_OK on success
 */
esp_err_t rc522_start(rc522_handle_t rc522);

/**
 * @brief Start to scan tags. If already started, ESP_OK will just be returned.
 * @param rc522 Handle
 * @return ESP_OK on success
 */
#define rc522_resume(rc522) rc522_start(rc522)

/**
 * @brief Pause scan tags. If already paused, ESP_OK will just be returned.
 * @param rc522 Handle
 * @return ESP_OK on success
 */
esp_err_t rc522_pause(rc522_handle_t rc522);

/**
 * @brief Destroy RC522 and free all resources. Cannot be called from event handler.
 * @param rc522 Handle
 */
void rc522_destroy(rc522_handle_t rc522);

#ifdef __cplusplus
}
#endif