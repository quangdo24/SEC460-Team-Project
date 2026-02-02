#!/bin/bash

# Creates a virtual environment at ./venv and downloads prereq packages for the script
# TODO: Allow installation of packages via brew (on macOS)

if command -v python3 -m venv venv >/dev/null 2>&1; then
	echo "Creating virtual environment at ./venv ..."
	python3 -m venv venv
	echo "Entering virtual environment context..."
	source ./venv/bin/activate
	if command -v pip3 >/dev/null 2>&1; then
		echo "Making sure pip3 is up to date..."
		pip3 install --upgrade >/dev/null
		echo "Installing prerequisites (1 of 2): requests"
		pip3 install requests >/dev/null
		echo "Installing prerequisites (2 of 2): urllib3"
		pip3 install urllib3 >/dev/null
	else
		echo "Couldn't initialize pip3. Is pip installed?"
	fi
else
	echo "Couldn't create a virtual environment. Is python3-venv installed?"
fi
