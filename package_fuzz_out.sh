#!/bin/bash

tar -czf "$1.tar.gz" $(find . -type d -name "$1")
