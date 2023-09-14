#include <esp_log.h>
#include <inttypes.h>
#include "rc522.h"

static const char* TAG = "rc522-demo";
static rc522_handle_t scanner;

static void rc522_handler(void* arg, esp_event_base_t base, int32_t event_id, void* event_data)
{
    rc522_event_data_t* data = (rc522_event_data_t*) event_data;
    switch(event_id) {
        case RC522_EVENT_TAG_SCANNED:
            rc522_tag_t* tag = (rc522_tag_t*) data->ptr;
            ESP_LOGI(TAG, "Tag scanned!");
            ESP_LOG_BUFFER_HEX(TAG, tag->uid, tag->uid_len);
            break;
    }
}

void app_main() {
    // temporary, needed because LOG_LOCAL_LEVEL does not work (https://github.com/espressif/esp-idf/issues/8570)
    esp_log_level_set("rc522", ESP_LOG_DEBUG);

    rc522_config_t config = {
        .transport = RC522_TRANSPORT_SPI,

        .spi.host = VSPI_HOST,
        .spi.miso_gpio = 25,
        .spi.mosi_gpio = 23,
        .spi.sck_gpio = 19,
        .spi.sda_gpio = 22,
    };

    // NOT TESTED
    // rc522_config_t config = {
    //     .transport = RC522_TRANSPORT_I2C,
    //     .i2c.sda_gpio = 18,
    //     .i2c.scl_gpio = 19,
    // };

    rc522_create(&config, &scanner);
    rc522_register_events(scanner, RC522_EVENT_ANY, rc522_handler, NULL);
    rc522_start(scanner);
}
