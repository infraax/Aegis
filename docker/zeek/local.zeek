# Zeek local configuration for Aegis
# Loads SSL/TLS fingerprinting and connection logging

@load base/protocols/ssl
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/conn

# JA3 fingerprinting (built into Zeek 4+)
@load policy/protocols/ssl/ja3

# Log all connections with community ID for Suricata correlation
@load policy/frameworks/network/community-id

# Capture full certificate chains for HIVE-style cert detection
redef SSL::log_include_certs_subject = T;

# Log DNS for tunneling/DGA detection
redef DNS::max_pending_msgs = 50000;
