#include <cstdlib>
#include <cstdio>
#include <cstring>

void extract_firmware(const char* pcap_file, const char* firmware_file) 
{
    // request for tshark
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "tshark -r %s -T fields -e data", pcap_file);

    // save result in buffer
    FILE* pipe = popen(cmd, "r");
    char buffer[1024];
    size_t n = fread(buffer, 1, sizeof(buffer), pipe);
    pclose(pipe);

    // removing \n from buffer
    for (size_t i = 0; i < n; i++) 
    {
        if (buffer[i] == '\n') 
        {
            buffer[i] = '\0';
            break;
        }
    }

    // writing uploads to file
    FILE* out = fopen(firmware_file, "wb");
    if (out) 
    {
        fwrite(buffer, 1, n, out);
        fclose(out);
    }
}

int main()
{
  const char* pcap_file = "traffic.pcap";
  const char* firmware_file = "firmware.bin";
  extract_firmware(pcap_file, firmware_file);
  return 0;
}
