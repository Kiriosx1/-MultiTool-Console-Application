#include <iostream>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <limits>
#include <fstream>
#include <windows.h>
#include <direct.h>
#include <urlmon.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")


bool CreateDirectoryRecursive(const std::string& path) {
    char buffer[MAX_PATH];
    strncpy(buffer, path.c_str(), MAX_PATH);
    buffer[MAX_PATH-1] = '\0';
    
    char* p = buffer;
    while (*p != '\0') {
        p = strchr(p, '\\');
        if (!p) break;
        *p = '\0';
        _mkdir(buffer);
        *p = '\\';
        p++;
    }
    return _mkdir(path.c_str()) == 0 || errno == EEXIST;
}

void calculator();
void temperatureConverter();
void numberGuessingGame();
void bmiCalculator();
void currencyConverter();
void createRestorePoint();
void checkDiskSpace();
void systemInfo();
void listProcesses();
void shutdownPC();
void createTextFile();
void readTextFile();
void checkInternetConnection();
void pingWebsite();
void downloadFile();
void primeChecker();
void factorialCalculator();
void baseConverter();
void pause();
void passwordGenerator();
void clipboardHistory();
void quickNotes();
void shutdownTimer();
void systemRestorePoint();
void wifiManager();
void uninstaller();
void updateChecker();
void commandPromptShortcut();
void textToSpeech();
HRESULT downloadTemplate(const std::string& link, const std::string& path);

// Helper function declarations for menus
int showMainMenu();
int showCalculatorMenu();
int showSystemUtilitiesMenu();
int showNetworkToolsMenu();
int showFileUtilitiesMenu();
int showMiscellaneousMenu();

int main() {
    int mainChoice;
    do {
        mainChoice = showMainMenu();
        switch (mainChoice) {
            case 1: {
                int calcChoice;
                do {
                    calcChoice = showCalculatorMenu();
                    switch (calcChoice) {
                        case 1: calculator(); break;
                        case 2: temperatureConverter(); break;
                        case 3: bmiCalculator(); break;
                        case 4: primeChecker(); break;
                        case 5: factorialCalculator(); break;
                        case 6: baseConverter(); break;
                        case 7: break; // Back to main menu
                        default: std::cout << "Invalid choice! Try again.\n";
                    }
                } while (calcChoice != 7);
                break;
            }
            case 2: {
                int sysChoice;
                do {
                    sysChoice = showSystemUtilitiesMenu();
                    switch (sysChoice) {
                        case 1: createRestorePoint(); break;
                        case 2: systemRestorePoint(); break;
                        case 3: checkDiskSpace(); break;
                        case 4: systemInfo(); break;
                        case 5: listProcesses(); break;
                        case 6: shutdownPC(); break;
                        case 7: shutdownTimer(); break;
                        case 8: wifiManager(); break;
                        case 9: uninstaller(); break;
                        case 10: updateChecker(); break;
                        case 11: commandPromptShortcut(); break;
                        case 12: break; // Back to main menu
                        default: std::cout << "Invalid choice! Try again.\n";
                    }
                } while (sysChoice != 12);
                break;
            }
            case 3: {
                int netChoice;
                do {
                    netChoice = showNetworkToolsMenu();
                    switch (netChoice) {
                        case 1: checkInternetConnection(); break;
                        case 2: pingWebsite(); break;
                        case 3: downloadFile(); break;
                        case 4: break; // Back to main menu
                        default: std::cout << "Invalid choice! Try again.\n";
                    }
                } while (netChoice != 4);
                break;
            }
            case 4: {
                int fileChoice;
                do {
                    fileChoice = showFileUtilitiesMenu();
                    switch (fileChoice) {
                        case 1: createTextFile(); break;
                        case 2: readTextFile(); break;
                        case 3: clipboardHistory(); break;
                        case 4: quickNotes(); break;
                        case 5: break; // Back to main menu
                        default: std::cout << "Invalid choice! Try again.\n";
                    }
                } while (fileChoice != 5);
                break;
            }
            case 5: {
                int miscChoice;
                do {
                    miscChoice = showMiscellaneousMenu();
                    switch (miscChoice) {
                        case 1: numberGuessingGame(); break;
                        case 2: currencyConverter(); break;
                        case 3: passwordGenerator(); break;
                        case 4: textToSpeech(); break;
                        case 5: break; // Back to main menu
                        default: std::cout << "Invalid choice! Try again.\n";
                    }
                } while (miscChoice != 5);
                break;
            }
            case 6: std::cout << "Exiting...\n"; break;
            default: std::cout << "Invalid choice! Try again.\n";
        }
    } while (mainChoice != 6);
    return 0;
}

int showMainMenu() {
    system("cls");
    std::cout << "\nSelect a category:\n";
    std::cout << "1. Calculators\n";
    std::cout << "2. System Utilities\n";
    std::cout << "3. Network Tools\n";
    std::cout << "4. File Utilities\n";
    std::cout << "5. Miscellaneous\n";
    std::cout << "6. Exit\n";
    std::cout << "Enter choice: ";
    int choice;
    std::cin >> choice;
    return choice;
}

int showCalculatorMenu() {
    system("cls");
    std::cout << "\nCalculators:\n";
    std::cout << "1. Calculator\n";
    std::cout << "2. Temperature Converter\n";
    std::cout << "3. BMI Calculator\n";
    std::cout << "4. Prime Number Checker\n";
    std::cout << "5. Factorial Calculator\n";
    std::cout << "6. Base Converter\n";
    std::cout << "7. Back to Main Menu\n";
    std::cout << "Enter choice: ";
    int choice;
    std::cin >> choice;
    return choice;
}

int showSystemUtilitiesMenu() {
    system("cls");
    std::cout << "\nSystem Utilities:\n";
    std::cout << "1. Create Windows Restore Point\n";
    std::cout << "2. System Restore Point\n";
    std::cout << "3. Check Disk Space\n";
    std::cout << "4. Show System Information\n";
    std::cout << "5. List Running Processes\n";
    std::cout << "6. Shutdown PC\n";
    std::cout << "7. Shutdown Timer\n";
    std::cout << "8. Wi-Fi Manager\n";
    std::cout << "9. Uninstaller\n";
    std::cout << "10. Update Checker\n";
    std::cout << "11. Command Prompt Shortcut\n";
    std::cout << "12. Back to Main Menu\n";
    std::cout << "Enter choice: ";
    int choice;
    std::cin >> choice;
    return choice;
}

int showNetworkToolsMenu() {
    system("cls");
    std::cout << "\nNetwork Tools:\n";
    std::cout << "1. Check Internet Connection\n";
    std::cout << "2. Ping a Website\n";
    std::cout << "3. Download a File\n";
    std::cout << "4. Back to Main Menu\n";
    std::cout << "Enter choice: ";
    int choice;
    std::cin >> choice;
    return choice;
}

int showFileUtilitiesMenu() {
    system("cls");
    std::cout << "\nFile Utilities:\n";
    std::cout << "1. Create a Text File\n";
    std::cout << "2. Read a File\n";
    std::cout << "3. Clipboard History\n";
    std::cout << "4. Quick Notes\n";
    std::cout << "5. Back to Main Menu\n";
    std::cout << "Enter choice: ";
    int choice;
    std::cin >> choice;
    return choice;
}

int showMiscellaneousMenu() {
    system("cls");
    std::cout << "\nMiscellaneous:\n";
    std::cout << "1. Number Guessing Game\n";
    std::cout << "2. Currency Converter\n";
    std::cout << "3. Random Password Generator\n";
    std::cout << "4. Text-to-Speech\n";
    std::cout << "5. Back to Main Menu\n";
    std::cout << "Enter choice: ";
    int choice;
    std::cin >> choice;
    return choice;
}

void clipboardHistory() {
    system("powershell Get-Clipboard");
    pause();
}

void quickNotes() {
    std::ofstream file("quick_notes.txt", std::ios::app);
    std::string note;
    std::cout << "Enter a note: ";
    std::cin.ignore();
    std::getline(std::cin, note);
    file << note << "\n";
    file.close();
    std::cout << "Note saved.\n";
    pause();
}

void shutdownTimer() {
    int seconds;
    std::cout << "Enter shutdown timer in seconds: ";
    std::cin >> seconds;
    std::string command = "shutdown /s /t " + std::to_string(seconds);
    system(command.c_str());
    pause();
}

void wifiManager() {
    system("netsh wlan show networks");
    pause();
}

void uninstaller() {
    system("appwiz.cpl");
    pause();
}

void updateChecker() {
    system("ms-settings:windowsupdate");
    pause();
}

void commandPromptShortcut() {
    system("cmd");
    pause();
}

void textToSpeech() {
    std::string text;
    std::cout << "Enter text to speak: ";
    std::cin.ignore();
    std::getline(std::cin, text);
    std::string command = "powershell -Command \"Add-Type -TypeDefinition 'using System.Speech; class TTS { static void Speak(string text) { var synth = new Speech.Synthesis.SpeechSynthesizer(); synth.Speak(text); } }' -Language CSharp; [TTS]::Speak('" + text + "')\"";
    system(command.c_str());
    pause();
}

void calculator() {
    char op;
    double num1, num2, result;

    std::cout << "********** CALCULATOR ************\n";

    std::cout << "Enter either (+ - * /): ";
    std::cin >> op;

    std::cout << "Enter 1: ";
    std::cin >> num1;

    std::cout << "Enter 2: ";
    std::cin >> num2;

    switch (op) {
        case '+':
            result = num1 + num2;
            break;
        case '-':
            result = num1 - num2;
            break;
        case '*':
            result = num1 * num2;
            break;
        case '/':
            if (num2 != 0) {
                result = num1 / num2;
            } else {
                std::cout << "Error: Division by zero!\n";
                return;
            }
            break;
        default:
            std::cout << "Invalid operator\n";
            return;
    }
    std::cout << "Result: " << result << std::endl;
    std::cout << "*************************************\n";
}

void temperatureConverter() {
    double temp;
    char unit;

    std::cout << "***** Temperature Converter *****\n";
    std::cout << "F = Fahrenheit\n";
    std::cout << "C = Celsius\n";
    std::cout << "What unit would you like to convert to: ";
    std::cin >> unit;

    if (unit == 'F' || unit == 'f') {
        std::cout << "Enter temperature in Celsius: ";
        std::cin >> temp;

        temp = (1.8 * temp) + 32;
        std::cout << "Temperature in Fahrenheit: " << temp << " F\n";
    }
    else if (unit == 'C' || unit == 'c') {
        std::cout << "Enter temperature in Fahrenheit: ";
        std::cin >> temp;

        temp = (temp - 32) / 1.8;
        std::cout << "Temperature in Celsius: " << temp << " C\n";
    }
    else {
        std::cout << "Please enter a valid unit (C or F).\n";
    }

    std::cout << "*********************************\n";
}

void numberGuessingGame() {
    std::cout << "Downloading the script...\n";
    std::string dwnld_URL = "https://raw.githubusercontent.com/SchooiCodes/smt/refs/heads/main/Files/CommandLineGame.bat";
    std::string savepath = std::getenv("TEMP") ? std::string(std::getenv("TEMP")) + "\\CommandLineGame.bat" : "C:\\Temp\\CommandLineGame.bat";
    if (downloadTemplate(dwnld_URL, savepath) == S_OK) {
        std::cout << "Download complete. Running script...\n";
        std::string run = "start /WAIT \"\" \"" + savepath + "\"";
        system(run.c_str());
    } else {
        std::cout << "Download failed.\n";
    }
    pause();
}

void bmiCalculator() {
    int weight;
    int height;
    float bmi;
    std::cout << "Enter your height in cm: ";
    std::cin >> height;
    std::cout << "Enter your weight: ";
    std::cin >> weight;
    bmi = (weight / (float)(height * height)) * 10000;
    std::cout << "Your BMI: " << bmi << "\n";
    pause();
}

void currencyConverter() {
    double amount;
    std::string fromCurrency, toCurrency;
    double rate = 0.0;

    std::cout << "***** Currency Converter *****\n";
    std::cout << "Enter amount: ";
    std::cin >> amount;
    std::cout << "From currency (USD, EUR, GBP): ";
    std::cin >> fromCurrency;
    std::cout << "To currency (USD, EUR, GBP): ";
    std::cin >> toCurrency;

    if (fromCurrency == "USD" && toCurrency == "EUR") rate = 0.85;
    else if (fromCurrency == "USD" && toCurrency == "GBP") rate = 0.75;
    else if (fromCurrency == "EUR" && toCurrency == "USD") rate = 1.18;
    else if (fromCurrency == "EUR" && toCurrency == "GBP") rate = 0.88;
    else if (fromCurrency == "GBP" && toCurrency == "USD") rate = 1.33;
    else if (fromCurrency == "GBP" && toCurrency == "EUR") rate = 1.14;
    else if (fromCurrency == toCurrency) rate = 1.0;
    else {
        std::cout << "Unsupported currency conversion.\n";
        pause();
        return;
    }

    double converted = amount * rate;
    std::cout << amount << " " << fromCurrency << " = " << converted << " " << toCurrency << "\n";
    std::cout << "******************************\n";
    pause();
}

void passwordGenerator() {
    std::cout << "Downloading the script...\n";
    std::string dwnld_URL = "https://raw.githubusercontent.com/SchooiCodes/smt/refs/heads/main/Files/PasswordGenerator.bat";
    std::string savepath = std::getenv("TEMP") ? std::string(std::getenv("TEMP")) + "\\PasswordGenerator.bat" : "C:\\Temp\\PasswordGenerator.bat";
    if (URLDownloadToFile(NULL, dwnld_URL.c_str(), savepath.c_str(), 0, NULL) == S_OK) {
        std::cout << "Download complete. Running script...\n";
        std::string run = "start /WAIT \"\" \"" + savepath + "\"";
        system(run.c_str());
    } else {
        std::cout << "Download failed.\n";
    }
    pause();
}

void createRestorePoint() {
    system("wmic shadowcopy call create Volume='C:\\'");
    std::cout << "Restore Point Created!\n";
    pause();
}

void systemRestorePoint() {
    system("wmic shadowcopy call create Volume='C:\\'");
    std::cout << "Restore Point Created!\n";
    pause();
}

void checkDiskSpace() {
    system("wmic logicaldisk get size,freespace,caption");
    pause();
}

void systemInfo() {
    system("systeminfo");
    pause();
}

void listProcesses() {
    system("tasklist");
    pause();
}

void shutdownPC() {
    std::cout << "Shutting down in 10 seconds...\n";
    system("shutdown /s /t 10");
    pause();
}

void createTextFile() {
    std::ofstream file("output.txt");
    file << "This is a sample text file.";
    file.close();
    std::cout << "File created as output.txt\n";
    pause();
}

void readTextFile() {
    std::ifstream file("output.txt");
    std::string line;
    while (getline(file, line)) {
        std::cout << line << "\n";
    }
    file.close();
    pause();
}

void checkInternetConnection() {
    system("ping 8.8.8.8 -n 1");
    pause();
}

void pingWebsite() {
    std::string website;
    std::cout << "Enter website to ping: ";
    std::cin >> website;
    std::string command = "ping " + website;
    system(command.c_str());
    pause();
}

void downloadFile() {
    std::string link;
    std::string path;
    std::cout << "Enter the download link: ";
    std::cin >> link;
    std::cout << "Enter the download path (like C:\\Temp\\file.txt): ";
    std::cin >> path;
    std::cout << "Downloading the file...\n";
    if (downloadTemplate(link, path) == S_OK) {
        std::cout << "Download complete. File can be located in " << path << ".\n";
    } else {
        std::cout << "Download failed.\n";
    }
    pause();
}

HRESULT downloadTemplate(const std::string& link, const std::string& path) {
    size_t lastSlash = path.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        std::string dirPath = path.substr(0, lastSlash);
        if (!CreateDirectoryRecursive(dirPath)) {
            std::cout << "Failed to create download directory.\n";
            return E_FAIL;
        }
    }
    return URLDownloadToFile(NULL, link.c_str(), path.c_str(), 0, NULL);
}

void primeChecker() {
    int num;
    std::cout << "Enter a number: ";
    std::cin >> num;
    bool isPrime = true;
    for (int i = 2; i <= std::sqrt(num); i++) {
        if (num % i == 0) isPrime = false;
    }
    std::cout << (isPrime ? "Prime" : "Not Prime") << "\n";
    pause();
}

void factorialCalculator() {
    int num;
    long long factorial = 1;
    std::cout << "Enter a number: ";
    std::cin >> num;
    for (int i = 1; i <= num; i++) factorial *= i;
    std::cout << "Factorial: " << factorial << "\n";
    pause();
}

void baseConverter() {
    int number, base;
    std::cout << "Enter a number: ";
    std::cin >> number;
    std::cout << "Enter the base to convert to (2-36): ";
    std::cin >> base;
    if (base < 2 || base > 36) {
        std::cout << "Invalid base. Please enter a base between 2 and 36.\n";
        return;
    }
    std::string result = "";
    const char digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int temp = number;
    do {
        result = digits[temp % base] + result;
        temp /= base;
    } while (temp > 0);
    std::cout << "Converted number: " << result << "\n";
    pause();
}

void pause() {
    system("pause");
    system("cls");
}
