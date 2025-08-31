#!/bin/bash

echo "Starting Beekeeper Backend Server..."
echo

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    uv venv
    if [ $? -ne 0 ]; then
        echo "Failed to create virtual environment"
        exit 1
    fi
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo "Failed to activate virtual environment"
    exit 1
fi

# Install/update dependencies
echo "Installing dependencies..."
uv sync
if [ $? -ne 0 ]; then
    echo "Failed to install dependencies"
    exit 1
fi

# Start the development server
echo "Starting development server..."
echo "API will be available at http://localhost:8000"
echo "API documentation at http://localhost:8000/docs"
echo
echo "Press Ctrl+C to stop the server"
echo

uvicorn app.main:app --reload --port 8000 