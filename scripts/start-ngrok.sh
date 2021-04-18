#!/bin/bash

if [ "$OSTYPE" == "msys" ]; then
  NGROK="winpty ngrok"
else
  NGROK="ngrok"
fi

$NGROK start --all --config=./scripts/ngrok.yml --log=stdout
