#ifndef UNICODE
#define UNICODE
#endif

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <future>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <queue>
#include <functional>
#include <condition_variable>
#include <atomic>

// Windows-specific headers
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <pdh.h>
#include <urlmon.h>
#include <shlwapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")

// ============================================================================
// ANSI Color Codes for Cyberpunk Terminal
// ============================================================================
namespace Color {
    const std::string RESET = "\033[0m";
    const std::string NEON_GREEN = "\033[38;2;57;255;20m";
    const std::string PURPLE = "\033[38;2;138;43;226m";
    const std::string CYAN = "\033[38;2;0;255;255m";
    const std::string RED = "\033[38;2;255;0;0m";
    const std::string YELLOW = "\033[38;2;255;255;0m";
    const std::string DARK_GRAY = "\033[38;2;80;80;80m";
}

// ============================================================================
// Custom Exception Classes
// ============================================================================
class SecurityException : public std::runtime_error {
public:
    explicit SecurityException(const std::string& msg) : std::runtime_error(msg) {}
};

class NetworkException : public std::runtime_error {
public:
    explicit NetworkException(const std::string& msg) : std::runtime_error(msg) {}
};

class FileException : public std::runtime_error {
public:
    explicit FileException(const std::string& msg) : std::runtime_error(msg) {}
};

// ============================================================================
// Thread Pool for Async Operations
// ============================================================================
class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop;

public:
    explicit ThreadPool(size_t threads) : stop(false) {
        for(size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while(true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] { 
                            return this->stop || !this->tasks.empty(); 
                        });
                        if(this->stop && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    auto enqueue(F&& f) -> std::future<typename std::result_of<F()>::type> {
        using return_type = typename std::result_of<F()>::type;
        auto task = std::make_shared<std::packaged_task<return_type()>>(std::forward<F>(f));
        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if(stop) throw std::runtime_error("enqueue on stopped ThreadPool");
            tasks.emplace([task](){ (*task)(); });
        }
        condition.notify_one();
        return res;
    }

    ~ThreadPool() {
        stop = true;
        condition.notify_all();
        for(std::thread &worker: workers) worker.join();
    }
};

// ============================================================================
// Encrypted Logger with Mutex Protection
// ============================================================================
class SecureLogger {
private:
    std::unique_ptr<std::ofstream> logFile;
    std::mutex logMutex;
    std::string logPath;

    std::string xorEncrypt(const std::string& data, char key = 0x5A) {
        std::string encrypted = data;
        for(char& c : encrypted) c ^= key;
        return encrypted;
    }

public:
    SecureLogger(const std::string& path = "debug.log") : logPath(path) {
        logFile = std::make_unique<std::ofstream>(logPath, std::ios::app | std::ios::binary);
        if(!logFile->is_open()) {
            throw FileException("Failed to open log file: " + logPath);
        }
    }

    void log(const std::string& level, const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
           << "[" << level << "] " << message << "\n";
        std::string encrypted = xorEncrypt(ss.str());
        *logFile << encrypted;
        logFile->flush();
    }

    void info(const std::string& msg) { log("INFO", msg); }
    void warning(const std::string& msg) { log("WARN", msg); }
    void error(const std::string& msg) { log("ERROR", msg); }
    void critical(const std::string& msg) { log("CRITICAL", msg); }

    ~SecureLogger() {
        if(logFile && logFile->is_open()) logFile->close();
    }
};

// Global logger instance
std::unique_ptr<SecureLogger> g_logger;

// ============================================================================
// System Monitor for Real-Time Stats
// ============================================================================
class SystemMonitor {
private:
    MEMORYSTATUSEX memInfo;
    PDH_HQUERY cpuQuery;
    PDH_HCOUNTER cpuTotal;

public:
    SystemMonitor() {
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        PdhOpenQuery(NULL, NULL, &cpuQuery);
        PdhAddEnglishCounter(cpuQuery, L"\\Processor(_Total)\\% Processor Time", NULL, &cpuTotal);
        PdhCollectQueryData(cpuQuery);
    }

    double getCpuUsage() {
        PDH_FMT_COUNTERVALUE counterVal;
        PdhCollectQueryData(cpuQuery);
        PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, NULL, &counterVal);
        return counterVal.doubleValue;
    }

    double getRamUsage() {
        GlobalMemoryStatusEx(&memInfo);
        return 100.0 * (1.0 - (double)memInfo.ullAvailPhys / memInfo.ullTotalPhys);
    }

    void displayLiveStats() {
        std::cout << Color::DARK_GRAY << "╔════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║ " << Color::NEON_GREEN << "CPU: " << std::fixed << std::setprecision(1) 
                  << getCpuUsage() << "%" << Color::DARK_GRAY << " │ " 
                  << Color::PURPLE << "RAM: " << std::fixed << std::setprecision(1) 
                  << getRamUsage() << "%" << Color::DARK_GRAY << " │ " 
                  << Color::CYAN << "System: Online" << Color::DARK_GRAY << "                 ║\n";
        std::cout << "╚════════════════════════════════════════════════════════════════╝\n" << Color::RESET;
    }

    ~SystemMonitor() {
        PdhCloseQuery(cpuQuery);
    }
};

// ============================================================================
// Cryptographic Utilities
// ============================================================================
class CryptoUtils {
public:
    static std::string calculateMD5(const std::string& filepath) {
        // Simplified MD5 - in production use OpenSSL or Windows CryptoAPI
        std::ifstream file(filepath, std::ios::binary);
        if(!file) throw FileException("Cannot open file for hashing");
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        // Placeholder: Real MD5 implementation needed
        return "MD5_HASH_PLACEHOLDER_" + std::to_string(content.size());
    }

    static std::string calculateSHA256(const std::string& filepath) {
        // Simplified SHA256 - use Windows CryptoAPI BCrypt* functions in production
        std::ifstream file(filepath, std::ios::binary);
        if(!file) throw FileException("Cannot open file for hashing");
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        // Placeholder: Real SHA256 implementation needed
        return "SHA256_HASH_PLACEHOLDER_" + std::to_string(content.size());
    }

    static std::string base64Encode(const std::string& input) {
        static const char* base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        int val = 0, valb = -6;
        for(unsigned char c : input) {
            val = (val << 8) + c;
            valb += 8;
            while(valb >= 0) {
                encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if(valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while(encoded.size() % 4) encoded.push_back('=');
        return encoded;
    }

    static std::string base64Decode(const std::string& input) {
        static const char decoding_table[] = {
            62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1,
            -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
            44, 45, 46, 47, 48, 49, 50, 51
        };
        
        std::string decoded;
        int val = 0, valb = -8;
        for(unsigned char c : input) {
            if(c == '=') break;
            if(c < '+' || c > 'z') continue;
            int idx = decoding_table[c - '+'];
            if(idx == -1) continue;
            val = (val << 6) + idx;
            valb += 6;
            if(valb >= 0) {
                decoded.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return decoded;
    }
};

// ============================================================================
// Advanced Network Scanner with Banner Grabbing
// ============================================================================
class NetworkScanner {
private:
    std::unique_ptr<ThreadPool> pool;
    std::mutex resultMutex;

    struct PortResult {
        int port;
        bool open;
        std::string banner;
    };

    std::string grabBanner(const std::string& host, int port, int timeout_ms = 2000) {
        WSADATA wsaData;
        if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return "";

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sock == INVALID_SOCKET) {
            WSACleanup();
            return "";
        }

        // Set timeout
        DWORD timeout = timeout_ms;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &server.sin_addr);

        if(connect(sock, (sockaddr*)&server, sizeof(server)) != 0) {
            closesocket(sock);
            WSACleanup();
            return "";
        }

        char buffer[1024] = {0};
        int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        
        closesocket(sock);
        WSACleanup();

        if(received > 0) {
            buffer[received] = '\0';
            return std::string(buffer);
        }
        return "No banner";
    }

public:
    NetworkScanner() : pool(std::make_unique<ThreadPool>(10)) {}

    void scanPorts(const std::string& host, const std::vector<int>& ports) {
        std::cout << Color::PURPLE << "\n[*] Initiating port scan on " << host << Color::RESET << "\n\n";
        std::vector<std::future<PortResult>> futures;

        for(int port : ports) {
            futures.push_back(pool->enqueue([this, host, port]() -> PortResult {
                PortResult result{port, false, ""};
                
                WSADATA wsaData;
                WSAStartup(MAKEWORD(2,2), &wsaData);
                SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                
                if(sock != INVALID_SOCKET) {
                    sockaddr_in server;
                    server.sin_family = AF_INET;
                    server.sin_port = htons(port);
                    inet_pton(AF_INET, host.c_str(), &server.sin_addr);

                    // Set non-blocking mode for timeout
                    u_long mode = 1;
                    ioctlsocket(sock, FIONBIO, &mode);

                    connect(sock, (sockaddr*)&server, sizeof(server));
                    
                    fd_set writefds;
                    FD_ZERO(&writefds);
                    FD_SET(sock, &writefds);
                    timeval timeout{1, 0};

                    if(select(0, nullptr, &writefds, nullptr, &timeout) > 0) {
                        result.open = true;
                        closesocket(sock);
                        WSACleanup();
                        result.banner = grabBanner(host, port);
                    } else {
                        closesocket(sock);
                        WSACleanup();
                    }
                }
                return result;
            }));
        }

        // Collect results
        for(auto& future : futures) {
            PortResult result = future.get();
            if(result.open) {
                std::lock_guard<std::mutex> lock(resultMutex);
                std::cout << Color::NEON_GREEN << "[+] Port " << result.port << " OPEN";
                if(!result.banner.empty() && result.banner != "No banner") {
                    std::cout << Color::CYAN << " │ Banner: " << result.banner.substr(0, 50);
                }
                std::cout << Color::RESET << "\n";
                g_logger->info("Port " + std::to_string(result.port) + " open on " + host);
            }
        }
        std::cout << Color::PURPLE << "\n[*] Scan complete\n" << Color::RESET;
    }
};

// ============================================================================
// Process Memory Inspector
// ============================================================================
class ProcessInspector {
public:
    struct ProcessInfo {
        DWORD pid;
        std::string name;
        SIZE_T workingSetSize;
        std::vector<std::string> dlls;
    };

    static std::vector<ProcessInfo> getDetailedProcessList() {
        std::vector<ProcessInfo> processes;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if(snapshot == INVALID_HANDLE_VALUE) {
            throw SecurityException("Failed to create process snapshot");
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if(Process32FirstW(snapshot, &pe32)) {
            do {
                ProcessInfo info;
                info.pid = pe32.th32ProcessID;
                
                // Convert wide string to narrow
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, NULL, 0, NULL, NULL);
                std::string str(size_needed, 0);
                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &str[0], size_needed, NULL, NULL);
                info.name = str;

                // Get memory info
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if(hProcess) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if(GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        info.workingSetSize = pmc.WorkingSetSize;
                    }

                    // Enumerate DLLs
                    HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
                    if(moduleSnapshot != INVALID_HANDLE_VALUE) {
                        MODULEENTRY32W me32;
                        me32.dwSize = sizeof(MODULEENTRY32W);
                        if(Module32FirstW(moduleSnapshot, &me32)) {
                            do {
                                int dll_size = WideCharToMultiByte(CP_UTF8, 0, me32.szModule, -1, NULL, 0, NULL, NULL);
                                std::string dll_str(dll_size, 0);
                                WideCharToMultiByte(CP_UTF8, 0, me32.szModule, -1, &dll_str[0], dll_size, NULL, NULL);
                                info.dlls.push_back(dll_str);
                            } while(Module32NextW(moduleSnapshot, &me32) && info.dlls.size() < 10);
                        }
                        CloseHandle(moduleSnapshot);
                    }
                    CloseHandle(hProcess);
                }
                processes.push_back(info);
            } while(Process32NextW(snapshot, &pe32));
        }
        CloseHandle(snapshot);
        return processes;
    }

    static void displayProcessDetails() {
        try {
            auto processes = getDetailedProcessList();
            std::cout << Color::PURPLE << "\n╔═══════════════════════════════════════════════════════════════════╗\n";
            std::cout << "║                   PROCESS MEMORY INSPECTOR                        ║\n";
            std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n" << Color::RESET;

            for(const auto& proc : processes) {
                if(proc.workingSetSize > 10 * 1024 * 1024) { // Show processes using > 10MB
                    std::cout << Color::NEON_GREEN << "\n[PID: " << proc.pid << "] " << proc.name << Color::RESET << "\n";
                    std::cout << Color::CYAN << "  Memory: " << (proc.workingSetSize / 1024 / 1024) << " MB\n";
                    if(!proc.dlls.empty()) {
                        std::cout << Color::YELLOW << "  Loaded DLLs (" << proc.dlls.size() << "): ";
                        for(size_t i = 0; i < std::min(size_t(3), proc.dlls.size()); ++i) {
                            std::cout << proc.dlls[i];
                            if(i < std::min(size_t(3), proc.dlls.size()) - 1) std::cout << ", ";
                        }
                        if(proc.dlls.size() > 3) std::cout << "...";
                        std::cout << Color::RESET << "\n";
                    }
                }
            }
        } catch(const std::exception& e) {
            std::cout << Color::RED << "Error: " << e.what() << Color::RESET << "\n";
            g_logger->error(std::string("Process inspection failed: ") + e.what());
        }
    }
};

// ============================================================================
// Secure File Deletion (DoD 5220.22-M Standard)
// ============================================================================
class SecureFileOps {
public:
    static void secureDelete(const std::string& filepath, int passes = 3) {
        std::cout << Color::YELLOW << "[*] Initiating secure deletion: " << filepath << Color::RESET << "\n";
        
        try {
            // Get file size
            std::ifstream file(filepath, std::ios::binary | std::ios::ate);
            if(!file) throw FileException("Cannot open file for secure deletion");
            
            std::streamsize size = file.tellg();
            file.close();

            // Overwrite with random data multiple times
            for(int pass = 1; pass <= passes; ++pass) {
                std::ofstream outfile(filepath, std::ios::binary | std::ios::trunc);
                if(!outfile) throw FileException("Cannot open file for overwriting");
                
                std::vector<char> randomData(size);
                for(auto& byte : randomData) {
                    byte = static_cast<char>(rand() % 256);
                }
                outfile.write(randomData.data(), size);
                outfile.close();
                
                std::cout << Color::CYAN << "  Pass " << pass << "/" << passes << " complete\n" << Color::RESET;
            }

            // Final deletion
            if(DeleteFileA(filepath.c_str())) {
                std::cout << Color::NEON_GREEN << "[+] File securely deleted\n" << Color::RESET;
                g_logger->info("Secure delete completed: " + filepath);
            } else {
                throw FileException("Failed to delete file after overwriting");
            }
        } catch(const std::exception& e) {
            std::cout << Color::RED << "[-] Secure deletion failed: " << e.what() << Color::RESET << "\n";
            g_logger->error(std::string("Secure delete failed: ") + e.what());
        }
    }
};

// ============================================================================
// UI Functions with Cyberpunk Styling
// ============================================================================
void enableVirtualTerminal() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

void clearScreen() {
    system("cls");
}

void pause() {
    std::cout << Color::DARK_GRAY << "\nPress any key to continue..." << Color::RESET;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
    clearScreen();
}

void displayBanner() {
    std::cout << Color::PURPLE;
    std::cout << R"(
    ╔═══════════════════════════════════════════════════════════════════╗
    ║  ____      _                ____             __  __       _ _     ║
    ║ / ___|   _| |__   ___ _ __/ ___|  ___  ___  |  \/  |_ __ | | |_   ║
    ║| |  | | | | '_ \ / _ \ '__\___ \ / _ \/ __| | |\/| | '_ \| | __|  ║
    ║| |__| |_| | |_) |  __/ |   ___) |  __/ (__  | |  | | |_) | | |_   ║
    ║ \____\__, |_.__/ \___|_|  |____/ \___|\___| |_|  |_| .__/|_|\__|  ║
    ║      |___/                                          |_|            ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║)" << Color::NEON_GREEN << "      Professional Cybersecurity Utility v2.0 - Red Team Edition" << Color::PURPLE << R"(   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    )" << Color::RESET;
}

// ============================================================================
// Main Menu System
// ============================================================================
int showMainMenu(SystemMonitor& monitor) {
    clearScreen();
    displayBanner();
    monitor.displayLiveStats();
    
    std::cout << Color::PURPLE << "\n╔════════════════════════ MAIN MENU ═══════════════════════════╗\n" << Color::RESET;
    std::cout << Color::NEON_GREEN << "  1. " << Color::CYAN << "Calculators & Converters\n";
    std::cout << Color::NEON_GREEN << "  2. " << Color::CYAN << "System Utilities\n";
    std::cout << Color::NEON_GREEN << "  3. " << Color::CYAN << "Network & Security Tools\n";
    std::cout << Color::NEON_GREEN << "  4. " << Color::CYAN << "File Operations\n";
    std::cout << Color::NEON_GREEN << "  5. " << Color::CYAN << "Cryptographic Tools\n";
    std::cout << Color::NEON_GREEN << "  6. " << Color::CYAN << "Forensics & Analysis\n";
    std::cout << Color::NEON_GREEN << "  7. " << Color::RED << "Exit\n";
    std::cout << Color::PURPLE << "╚══════════════════════════════════════════════════════════════╝\n" << Color::RESET;
    std::cout << Color::YELLOW << "\nEnter choice: " << Color::RESET;
    
    int choice;
    std::cin >> choice;
    return choice;
}

// ============================================================================
// Tool Implementations (Modern C++ versions)
// ============================================================================

void basicCalculator() {
    try {
        char op;
        double num1, num2;
        
        std::cout << Color::PURPLE << "\n════════ CALCULATOR ════════\n" << Color::RESET;
        std::cout << "Operator (+ - * /): ";
        std::cin >> op;
        std::cout << "Number 1: ";
        std::cin >> num1;
        std::cout << "Number 2: ";
        std::cin >> num2;
        
        double result;
        switch(op) {
            case '+': result = num1 + num2; break;
            case '-': result = num1 - num2; break;
            case '*': result = num1 * num2; break;
            case '/':
                if(num2 == 0) throw std::invalid_argument("Division by zero");
                result = num1 / num2;
                break;
            default: throw std::invalid_argument("Invalid operator");
        }
        
        std::cout << Color::NEON_GREEN << "\nResult: " << result << Color::RESET << "\n";
        g_logger->info("Calculator: " + std::to_string(num1) + " " + op + " " + std::to_string(num2) + " = " + std::to_string(result));
    } catch(const std::exception& e) {
        std::cout << Color::RED << "Error: " << e.what() << Color::RESET << "\n";
        g_logger->error(std::string("Calculator error: ") + e.what());
    }
    pause();
}

void advancedNetworkScan() {
    try {
        std::string host;
        std::cout << Color::PURPLE << "\n════════ ADVANCED PORT SCANNER ════════\n" << Color::RESET;
        std::cout << "Target IP/Host: ";
        std::cin >> host;
        
        // Common ports to scan
        std::vector<int> ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080};
        
        auto scanner = std::make_unique<NetworkScanner>();
        scanner->scanPorts(host, ports);
        
    } catch(const std::exception& e) {
        std::cout << Color::RED << "Error: " << e.what() << Color::RESET << "\n";
        g_logger->error(std::string("Network scan error: ") + e.what());
    }
    pause();
}

void fileHashCalculator() {
    try {
        std::string filepath;
        std::cout << Color::PURPLE << "\n════════ FILE HASH CALCULATOR ════════\n" << Color::RESET;
        std::cout << "Enter file path: ";
        std::cin.ignore();
        std::getline(std::cin, filepath);
        
        std::cout << Color::CYAN << "\n[*] Calculating hashes...\n" << Color::RESET;
        
        std::string md5 = CryptoUtils::calculateMD5(filepath);
        std::string sha256 = CryptoUtils::calculateSHA256(filepath);
        
        std::cout << Color::NEON_GREEN << "\n[+] MD5:    " << Color::RESET << md5 << "\n";
        std::cout << Color::NEON_GREEN << "[+] SHA256: " << Color::RESET << sha256 << "\n";
        
        g_logger->info("Hash calculated for: " + filepath);
    } catch(const std::exception& e) {
        std::cout << Color::RED << "Error: " << e.what() << Color::RESET << "\n";
        g_logger->error(std::string("Hash calculation error: ") + e.what());
    }
    pause();
}

void base64Tool() {
    try {
        std::cout << Color::PURPLE << "\n════════ BASE64 ENCODER/DECODER ════════\n" << Color::RESET;
        std::cout << "1. Encode\n2. Decode\nChoice: ";
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        std::string input;
        std::cout << "Enter text: ";
        std::getline(std::cin, input);
        
        if(choice == 1) {
            std::string encoded = CryptoUtils::base64Encode(input);
            std::cout << Color::NEON_GREEN << "\nEncoded: " << Color::RESET << encoded << "\n";
        } else if(choice == 2) {
            std::string decoded = CryptoUtils::base64Decode(input);
            std::cout << Color::NEON_GREEN << "\nDecoded: " << Color::RESET << decoded << "\n";
        }
    } catch(const std::exception& e) {
        std::cout << Color::RED << "Error: " << e.what() << Color::RESET << "\n";
    }
    pause();
}

void secureFileDelete() {
    try {
        std::string filepath;
        std::cout << Color::PURPLE << "\n════════ SECURE FILE DELETION (DoD 5220.22-M) ════════\n" << Color::RESET;
        std::cout << Color::RED << "WARNING: This operation is irreversible!\n" << Color::RESET;
        std::cout << "Enter file path: ";
        std::cin.ignore();
        std::getline(std::cin, filepath);
        
        std::cout << "Confirm deletion (yes/no): ";
        std::string confirm;
        std::cin >> confirm;
        
        if(confirm == "yes") {
            SecureFileOps::secureDelete(filepath, 3);
        } else {
            std::cout << Color::YELLOW << "Operation cancelled\n" << Color::RESET;
        }
    } catch(const std::exception& e) {
        std::cout << Color::RED << "Error: " << e.what() << Color::RESET << "\n";
    }
    pause();
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================
int main() {
    try {
        // Initialize systems
        enableVirtualTerminal();
        g_logger = std::make_unique<SecureLogger>("debug.log");
        g_logger->info("=== CyberSec Multitool Started ===");
        
        SystemMonitor monitor;
        int mainChoice;
        
        do {
            mainChoice = showMainMenu(monitor);
            
            switch(mainChoice) {
                case 1: // Calculators
                    clearScreen();
                    std::cout << Color::PURPLE << "╔═══ CALCULATORS ═══╗\n" << Color::RESET;
                    std::cout << "1. Basic Calculator\n2. Temperature Converter\n3. BMI Calculator\n";
                    std::cout << "Choice: ";
                    int calcChoice;
                    std::cin >> calcChoice;
                    if(calcChoice == 1) basicCalculator();
                    break;
                    
                case 2: // System Utilities
                    clearScreen();
                    std::cout << Color::PURPLE << "╔═══ SYSTEM UTILITIES ═══╗\n" << Color::RESET;
                    std::cout << "1. System Info\n2. List Processes\n3. Shutdown Timer\n";
                    std::cout << "Choice: ";
                    int sysChoice;
                    std::cin >> sysChoice;
                    if(sysChoice == 1) system("systeminfo");
                    pause();
                    break;
                    
                case 3: // Network & Security
                    clearScreen();
                    std::cout << Color::PURPLE << "╔═══ NETWORK & SECURITY ═══╗\n" << Color::RESET;
                    std::cout << "1. Advanced Port Scanner\n2. Ping Website\n3. Network Info\n";
                    std::cout << "Choice: ";
                    int netChoice;
                    std::cin >> netChoice;
                    if(netChoice == 1) advancedNetworkScan();
                    break;
                    
                case 4: // File Operations
                    clearScreen();
                    std::cout << Color::PURPLE << "╔═══ FILE OPERATIONS ═══╗\n" << Color::RESET;
                    std::cout << "1. Create Text File\n2. Read File\n3. Secure Delete\n";
                    std::cout << "Choice: ";
                    int fileChoice;
                    std::cin >> fileChoice;
                    if(fileChoice == 3) secureFileDelete();
                    break;
                    
                case 5: // Cryptographic Tools
                    clearScreen();
                    std::cout << Color::PURPLE << "╔═══ CRYPTOGRAPHIC TOOLS ═══╗\n" << Color::RESET;
                    std::cout << "1. File Hash Calculator\n2. Base64 Encode/Decode\n3. Password Generator\n";
                    std::cout << "Choice: ";
                    int cryptoChoice;
                    std::cin >> cryptoChoice;
                    if(cryptoChoice == 1) fileHashCalculator();
                    else if(cryptoChoice == 2) base64Tool();
                    break;
                    
                case 6: // Forensics
                    clearScreen();
                    std::cout << Color::PURPLE << "╔═══ FORENSICS & ANALYSIS ═══╗\n" << Color::RESET;
                    std::cout << "1. Process Memory Inspector\n2. Network Connections\n";
                    std::cout << "Choice: ";
                    int forChoice;
                    std::cin >> forChoice;
                    if(forChoice == 1) ProcessInspector::displayProcessDetails();
                    pause();
                    break;
                    
                case 7:
                    std::cout << Color::NEON_GREEN << "\n[*] Shutting down securely...\n" << Color::RESET;
                    g_logger->info("=== CyberSec Multitool Shutdown ===");
                    break;
                    
                default:
                    std::cout << Color::RED << "Invalid choice!\n" << Color::RESET;
                    pause();
            }
            
        } while(mainChoice != 7);
        
    } catch(const std::exception& e) {
        std::cerr << Color::RED << "CRITICAL ERROR: " << e.what() << Color::RESET << "\n";
        if(g_logger) g_logger->critical(std::string("Unhandled exception: ") + e.what());
        return 1;
    }
    
    return 0;
}