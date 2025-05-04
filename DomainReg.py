import requests

# Replace with your DuckDNS token
token = "84c79deb-491f-4c02-bae6-8c1e5c5c4782"
domain = "ksharish"

# Update DuckDNS
url = f"https://www.duckdns.org/update?domains={domain}&token={token}"
print(requests.get(url).text)
