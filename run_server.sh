#!/bin/bash
# This is a script to run the Flask server with the deployed model
chmod u+x run_server.sh
chmod +w run_server.sh

export FLASK_APP=chain.py
python -m flask run --host=0.0.0.0

