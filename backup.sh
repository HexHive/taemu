#!/bin/sh

tar cvfz $1 --exclude ".git" --exclude ".venv" --exclude "__pycache__" $2
