#!/bin/bash

python3 -m venv venv

source ./venv/bin/activate

pip3 install -r requirements.txt

python3 src/main.py

python3 -m unittest test/test_bob2_protocol.py
