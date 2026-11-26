#include <iostream>
#include <vector>
#include <unordered_map>
#include <cmath>
#include <string>
#include <iomanip>

struct Packet {
    std::string src_ip;
    int dst_port;
    int payload_bytes;
};

class NetworkEntropyIDS {
private:
    double entropy_threshold;
    int burst_limit;

    double compute_shannon_entropy(const std::unordered_map<int, int>& counts, int total) {
        if (total == 0) return 0.0;
        double entropy = 0.0;
        for (const auto& pair : counts) {
            double p = static_cast<double>(pair.second) / total;
            if (p > 0) {
                entropy -= p * std::log2(p);
            }
        }
        return entropy;
    }

public:
    NetworkEntropyIDS(double threshold = 2.8, int limit = 8)
        : entropy_threshold(threshold), burst_limit(limit) {}

    void analyze_window(const std::vector<Packet>& window, int window_id) {
        std::unordered_map<std::string, int> ip_counts;
        std::unordered_map<int, int> port_counts;
        long long total_bytes = 0;

        for (const auto& pkt : window) {
            ip_counts[pkt.src_ip]++;
            port_counts[pkt.dst_port]++;
            total_bytes += pkt.payload_bytes;
        }

        double port_entropy = compute_shannon_entropy(port_counts, window.size());
        bool burst_detected = false;
        std::string suspicious_ip = "None";

        for (const auto& pair : ip_counts) {
            if (pair.second >= burst_limit) {
                burst_detected = true;
                suspicious_ip = pair.first;
                break;
            }
        }

        std::cout << "=== Telemetry Window #" << window_id << " ===\n";
        std::cout << "Total Packets : " << window.size() << " | Total Bytes: " << total_bytes << "\n";
        std::cout << std::fixed << std::setprecision(4);
        std::cout << "Port Entropy  : " << port_entropy << " bits\n";

        if (port_entropy > entropy_threshold && burst_detected) {
            std::cout << "[CRITICAL ALERT] Zero-Day Distributed Port Scan detected from IP: " << suspicious_ip << "\n\n";
        } else if (burst_detected) {
            std::cout << "[WARNING] High-Frequency DoS Traffic Burst from IP: " << suspicious_ip << "\n\n";
        } else if (port_entropy > entropy_threshold) {
            std::cout << "[WARNING] Anomalous Destination Port Dispersion (Reconnaissance)\n\n";
        } else {
            std::cout << "[STATUS] Normal Baseline Traffic\n\n";
        }
    }
};

int main() {
    NetworkEntropyIDS ids(2.5, 6);

    std::vector<Packet> normal_traffic = {
        {"192.168.1.10", 443, 512}, {"192.168.1.11", 443, 1024},
        {"192.168.1.12", 80, 256},  {"192.168.1.10", 443, 640},
        {"192.168.1.14", 53, 128},  {"192.168.1.15", 443, 890}
    };

    std::vector<Packet> attack_traffic = {
        {"10.0.0.99", 21, 64},  {"10.0.0.99", 22, 64},
        {"10.0.0.99", 23, 64},  {"10.0.0.99", 25, 64},
        {"10.0.0.99", 80, 64},  {"10.0.0.99", 443, 64},
        {"10.0.0.99", 3306, 64},{"10.0.0.99", 8080, 64}
    };

    ids.analyze_window(normal_traffic, 1);
    ids.analyze_window(attack_traffic, 2);

    return 0;
}
