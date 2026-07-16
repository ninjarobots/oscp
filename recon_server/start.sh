if [ $# -ne 1 ]; then
	echo "Enter a project path"
	exit 1
fi

project="$1"

python3 recon_server.py --host 192.168.122.75 --port 5000 "$project" --bh-key 'NUrXqg43trOfVLNCkNb0DX/763IKWRPJMSZq0oUmJXMhgGkTJ8yNRA==' --bh-key-id 'df9f1cd9-26b9-419b-b8c0-d9425474a066' --bh-host 'http://192.168.122.75:8880' 
