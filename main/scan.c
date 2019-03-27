/*
 * For more info:
 *  - https://mrncciew.com/2014/10/27/cwap-802-11-probe-requestresponse/
 *  - https://github.com/kalanda/esp8266-sniffer/blob/master/src/main.cpp
 *  - https://github.com/espressif/esp-idf/blob/master/examples/wifi/simple_sniffer/main/cmd_sniffer.c
*/
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"

#include "scan.h"

#define LOG_TAG "bigbro"

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
            ESP_LOGI(LOG_TAG, "SYSTEM_EVENT_STA_START");
            ESP_ERROR_CHECK(esp_wifi_connect());
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            ESP_LOGI(LOG_TAG, "SYSTEM_EVENT_STA_GOT_IP");
            ESP_LOGI(LOG_TAG, "Got IP: %s\n",
                     ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            ESP_LOGI(LOG_TAG, "SYSTEM_EVENT_STA_DISCONNECTED");
            ESP_ERROR_CHECK(esp_wifi_connect());
            break;
        default:
            break;
    }
    return ESP_OK;
}

static void extract_macaddr(char *addr, uint8_t* data, uint16_t offset)
{
    sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            data[offset+0],
            data[offset+1],
            data[offset+2],
            data[offset+3],
            data[offset+4],
            data[offset+5]);
}

static void wifi_monitor_cb(void *recv_buf, wifi_promiscuous_pkt_type_t type)
{
    if(type != WIFI_PKT_MGMT) return; // We only play with Management frames
    wifi_promiscuous_pkt_t *recv_pkt = (wifi_promiscuous_pkt_t *)recv_buf;

    // Read 80211 frame control info
    unsigned int frame_ctrl = ((unsigned int)recv_pkt->payload[1] << 8) + recv_pkt->payload[0];
    uint8_t frame_subtype = (uint8_t) ((frame_ctrl & 0b0000000011110000) >> 4);

    if(frame_subtype != PKT_SUBTYPE_PROBE_REQUEST) return; // We only needs probe requests from a station (i.e. client)

    // Extract MAC address and print out the result
    char addr[] = "00:00:00:00:00:00";
    extract_macaddr(addr, recv_pkt->payload, 10);

    ESP_LOGI(LOG_TAG, "Got a device: %s, RSSI: %d", addr, recv_pkt->rx_ctrl.rssi);
}

/* Initialize Wi-Fi as sta and set scan method */
static void wifi_init()
{
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_monitor_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true)); // Go for big bro mode
}

void app_main()
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    
    wifi_init();
}
