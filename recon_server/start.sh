if [ $# -ne 1 ]; then
	echo "Enter a project path"
	exit 1
fi

project="$1"

sudo python3 recon_server.py --host 192.168.122.75 --port 5000 "$project"
