import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROUTERS = {
    "router1": {"ip": "172.20.20.3", "iface_ip": "10.0.0.1/30"},
    "router2": {"ip": "172.20.20.2", "iface_ip": "10.0.0.2/30"}
}

USERNAME = "admin"
PASSWORD = "NokiaSrl1!"

def configure_router(router_name, mgmt_ip, iface_ip):
    print(f"Configuring {router_name} ({mgmt_ip})")
    
    url = f"https://{mgmt_ip}/jsonrpc"
    
    commands = [
        "enter candidate",
        "interface ethernet-1/1 admin-state enable",
        "interface ethernet-1/1 subinterface 0 ipv4 admin-state enable",
        f"interface ethernet-1/1 subinterface 0 ipv4 address {iface_ip}",
        "network-instance default interface ethernet-1/1.0",
        "commit now"
    ]
    
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "cli",
        "params": {
            "commands": commands
        }
    }
    
    try:
        response = requests.post(
            url, 
            auth=(USERNAME, PASSWORD), 
            json=payload, 
            verify=False 
        )
        
        if response.status_code == 200:
            print(f"{router_name} has been configured.\n")
        else:
            print(f"Error on {router_name}: {response.text}\n")
            
    except Exception as e:
        print(f"Failed to connect to {router_name}: {e}\n")

if __name__ == "__main__":
    print("Starting network automation\n")
    for name, data in ROUTERS.items():
        configure_router(name, data["ip"], data["iface_ip"])