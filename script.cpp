#include <cstdlib> 
#include <cstdio> 
#include <cstring> 
#include <vector>
#include <sstream>

void extract_firmware(const char* pcap_file, const char* firmware_dir) { 
    char cmd[1024]; 

    int n = snprintf(cmd, sizeof(cmd), "tshark -r \"%s\" -T fields -e data", pcap_file);
    
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

            std::ostringstream filename;
            filename << firmware_dir << "/firmware" << firmware_count << ".bin";

            FILE* out = fopen(filename.str().c_str(), "wb");

            if (out) {
                fwrite(buffer.data(), 1, n, out);
                fclose(out);
            } else {
                printf("Ошибка открытия файла %s!\n", filename.str().c_str());
            }

            firmware_count++;

            if (n == buffer.size()) {
                buffer.resize(buffer.size() * 2);
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
