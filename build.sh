#!/bin/bash

if command -v go &> /dev/null; then
    GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -modfile go.mod
    build_exit_code=$?
    
    if [ $build_exit_code -eq 0 ]; then
        echo "Build completed successfully"
    else
        echo "Build failed"
    fi
else
    echo "Error: 'go' command not found"
fi
