#!/bin/bash

# This script is running to initialize the application environment in the xrpl-unl-manager container
echo "Installing application dependencies..."
pip install -r /app/requirements.txt

echo "    Done!"

$1
