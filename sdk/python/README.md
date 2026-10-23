# Python SDK

The preferred import for any application is:

```python
from license_platform_sdk import LicenseClient

client = LicenseClient(
    base_url="https://licenses.example.com",
    app_id="your-application",
    storage_path="license-token.json",
)

activation = client.activate(customer_license_key)
client.validate_online()

# After activation, show activation["pairing"]["scan_path"] as a QR code in your app.
pairing = activation["pairing"]
if pairing["status"] == "pending":
    print(pairing["scan_path"])
    # Poll until the customer scans the QR in LicenseStack.
    print(client.pairing_status(pairing["pairing_id"]))
```

The REST API is language-neutral, so applications written in JavaScript,
.NET, Java, C++, Go, or another language can call the same endpoints directly.

`cyclo_license` remains as a compatibility import for the early prototype; new
applications should use `license_platform_sdk`.
