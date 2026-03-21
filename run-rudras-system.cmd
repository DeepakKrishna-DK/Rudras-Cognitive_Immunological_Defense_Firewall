@echo off
set RUDRAS_MODE=client
set RUDRAS_API_ADMIN_TOKEN=38IyUhJKXGoY7jt2Q2DkbCKN4lIplYVpeMOlOhOY
set RUDRAS_METRICS_TOKEN=38IyUhJKXGoY7jt2Q2DkbCKN4lIplYVpeMOlOhOY
set PCAP_LIB_PATH=C:\npcap-sdk\Lib\x64
set RUST_LOG=info

cd /d "C:\Users\dk-32\OneDrive\Desktop\Project_2"
"C:\Users\dk-32\OneDrive\Desktop\Project_2\target\release\rudras.exe" --mode client --config "C:\Users\dk-32\OneDrive\Desktop\Project_2\config\rudras.toml"
