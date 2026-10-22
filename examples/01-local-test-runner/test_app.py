"""
test_app.py - Python test suite demonstrating iam-shrink integration.

When executed under `iam-shrink run -- pytest test_app.py` or `iam-shrink run -- python3 test_app.py`,
iam-shrink injects AWS_CSM_ENABLED=true and AWS_CSM_PORT=<loopback_port>.
The test below emits CSM telemetry datagrams matching official AWS SDK behavior.
"""

import json
import os
import socket
import time
import unittest


def emit_csm_event(service: str, api: str, status_code: int = 200, region: str = "us-east-1"):
    port_str = os.environ.get("AWS_CSM_PORT")
    if not port_str:
        return

    port = int(port_str)
    host = os.environ.get("AWS_CSM_HOST", "127.0.0.1")

    payload = {
        "Version": 1,
        "Type": "ApiCall",
        "Service": service,
        "Api": api,
        "Timestamp": int(time.time() * 1000),
        "Region": region,
        "HttpStatusCode": status_code,
        "FinalHttpStatusCode": status_code,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(json.dumps(payload).encode("utf-8"), (host, port))
    finally:
        sock.close()


class TestOrderService(unittest.TestCase):
    def test_fetch_customer_order(self):
        # 1. Look up order metadata in DynamoDB
        emit_csm_event("DynamoDB", "Query")

        # 2. Decrypt customer PII using AWS KMS
        emit_csm_event("KMS", "Decrypt")

        # 3. Read invoice PDF artifact from Amazon S3
        emit_csm_event("S3", "GetObject")
        emit_csm_event("S3", "ListBucket")

        # Allow slight delay for local UDP socket flush
        time.sleep(0.05)
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
