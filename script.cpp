#include <cstdlib> 
#include <cstdio> 
#include <cstring> 
#include <vector>
 
void extract_firmware(const char* pcap_file, const char* firmware_file) { 
    char cmd[1024]; 

    int n = snprintf(cmd, sizeof(cmd), "tshark -r \"%s\" -T fields -e data", pcap_file);
    
    if (n <= 0 || n >= sizeof(cmd)) {
        printf("Formating error!\n");
        return;
    }

    FILE* pipe = popen(cmd, "r"); 
    FILE* out = fopen(firmware_file, "wb");

    if (pipe && out) { 
        std::vector<char> buffer(1024);
        size_t n; 

        while ((n = fread(buffer.data(), 1, buffer.size(), pipe)) > 0) {
            fwrite(buffer.data(), 1, n, out); 

            if (n == buffer.size()) {
                buffer.resize(buffer.size() * 2);
            }
        }

        fclose(out);
        pclose(pipe); 
    } else {
        printf("Error of opening!\n");

        if (pipe) {
            pclose(pipe);
        }

        if (out) {
            fclose(out);
        }
    }
}

int main()
{
  const char* pcap_file = "traffic.pcap";
  const char* firmware_file = "firmware.bin";
  extract_firmware(pcap_file, firmware_file);
  return 0;
}
