#include <cstdlib>   
#include <cstdio>   
#include <cstring>   
#include <vector>  
#include <sstream>  
#include <iostream> 
#include <fstream> 
#include <nlohmann/json.hpp> 
 
using json = nlohmann::json; 
 
void extract_firmware(const char* pcap_file, const char* firmware_dir) {   
    char cmd[1024];   
 
    int n = snprintf(cmd, sizeof(cmd), "tshark -r \"%s\" -T json", pcap_file);  
      
    if (n <= 0 || n >= sizeof(cmd)) {  
        printf("Formating error!\n");  
        return;  
    }  
  
    FILE* pipe = popen(cmd, "r");   
    if (pipe) {   
        std::vector<char> buffer(1024);  
        size_t n;  
        size_t firmware_count = 0;  
  
        while ((n = fread(buffer.data(), 1, buffer.size(), pipe)) > 0) {  
            json j = json::parse(buffer.data(), buffer.data() + n); 
            if (j.find("_source") != j.end() && j["_source"].find("layers") != j["_source"].end()) { 
                auto layers = j["_source"]["layers"]; 
                if (layers.find("data") != layers.end()) { 
                    std::string hex_data = layers["data"]; 
                    std::string byte_str; 
                    for (std::size_t i = 0; i < hex_data.length(); i += 2) { 
                        byte_str.push_back((char)std::stoi(hex_data.substr(i, 2), nullptr, 16)); 
                    } 
                    std::ostringstream filename;  
                    filename << firmware_dir << "/firmware" << firmware_count << ".bin";  
 
                    std::ofstream out(filename.str(), std::ios::binary); 
  
                    if (out.is_open()) {  
                        out.write(byte_str.c_str(), byte_str.length());  
                        out.close();  
                    } else {  
                        printf("Ошибка открытия файла %s!\n", filename.str().c_str());  
                    }  
 
                    firmware_count++;  
                } 
            } 
        }  
  
        pclose(pipe);   
    } else {  
        printf("Ошибка открытия файла %s!\n", pcap_file);  
    }  
}  
  
int main()  
{  
  const char* pcap_file = "traffic.pcap";  
  const char* firmware_dir = "D:\\vsstudio\\DSR";  
  extract_firmware(pcap_file, firmware_dir);  
  return 0;  
}
