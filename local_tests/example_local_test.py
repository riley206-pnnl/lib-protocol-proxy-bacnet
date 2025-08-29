#!/usr/bin/env python3
"""
Example test script in local_tests directory.
This file demonstrates that files in this directory are ignored by Git.
"""

import os
import sys
import json

def example_local_test():
    """Example test function for local development."""
    print("🧪 This is an example local test")
    print("📁 Current directory:", os.getcwd())
    print("📂 Script location:", os.path.dirname(__file__))
    
    # Create a test temp file
    temp_file = os.path.join(os.path.dirname(__file__), "temp_test_data.json")
    test_data = {
        "message": "This is test data that won't be committed to Git",
        "timestamp": "2025-08-11",
        "test_type": "local_development"
    }
    
    with open(temp_file, "w") as f:
        json.dump(test_data, f, indent=2)
    
    print(f"📄 Created test file: {temp_file}")
    print("✅ Local test completed successfully!")

if __name__ == "__main__":
    example_local_test()
