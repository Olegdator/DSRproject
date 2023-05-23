#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <sstream>

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
            std::string json_str(buffer.data(), n);
            std::map<std::string, std::string> layers;

            // parsing json
            size_t pos = 0;
            while (pos < json_str.length()) {
                size_t start = json_str.find("\"_source\":{", pos);
                if (start == std::string::npos) {
                    break;
                }
                start += 10;
                size_t end = json_str.find("}}}", start);
                if (end == std::string::npos) {
                    break;
                }
                end += 3;
                std::string source_str = json_str.substr(start, end - start);
                pos = end;

                // check source
                size_t layer_pos = 0;
                while (layer_pos < source_str.length()) {
                    size_t layer_start = source_str.find("\"layers\":{", layer_pos);
                    if (layer_start == std::string::npos) {
                        break;
                    }
                    layer_start += 10;
                    size_t layer_end = source_str.find("}", layer_start);
                    if (layer_end == std::string::npos) {
                        break;
                    }
                    layer_end += 1;
                    std::string layers_str = source_str.substr(layer_start, layer_end - layer_start);
                    layer_pos = layer_end;

                    // check layers
                    size_t data_pos = 0;
                    while (data_pos < layers_str.length()) {
                        size_t data_start = layers_str.find("\"data\":", data_pos);
                        if (data_start == std::string::npos) {
                            break;
                        }
                        data_start += 7;
                        size_t data_end = layers_str.find("\"", data_start);
                        if (data_end == std::string::npos) {
                            break;
                        }
                        std::string data_str = layers_str.substr(data_start, data_end - data_start);
                        data_pos = data_end;

                        // data to dict
                        layers["data"] = data_str;
                        std::ostringstream filename;
                        filename << firmware_dir << "/firmware" << firmware_count << ".bin";
                        std::ofstream out(filename.str(), std::ios::binary);
                        if (out.is_open()) {
                            out.write(data_str.c_str(), data_str.length());
                            out.close();
                        } else {
                            printf("Ошибка открытия файла %s!\n", filename.str().c_str());
                        }
                        firmware_count++;
                    }
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
