echo "Building dfs application..."
gcc dfs.c -o dfs -lssl -lcrypto -I/usr/local/opt/openssl/include
echo "Build done"

sleep 2

echo "Starting DFS servers..."

./dfs DFS1 10001 &
sleep 1
#./dfs DFS2 10002 &
sleep 1
#./dfs DFS3 10003 &
sleep 1
./dfs DFS4 10004 &

echo "Started all DFS servers"
