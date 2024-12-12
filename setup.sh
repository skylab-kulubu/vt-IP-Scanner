#!/bin/bash

root = $(pwd)

python3 -m venv .venv

$root/.venv/bin/pip install requests

bin_path = "/usr/local/bin/scan-vt"

sudo touch $bin_path

sudo echo "#!/bin/bash" |tee -a $bin_path

sudo echo "$root/.venv/bin/python3 $root/main.py" |tee -a $bin_path

sudo chmod +x $bin_path

echo "Setup complete"

