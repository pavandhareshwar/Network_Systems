echo "Killing dfs processes..."

# Kill DFS Server 1
kill -9 `ps -e | grep DFS1 | awk 'NR==1{print $1}'`

sleep 1

# Kill DFS Server 2
kill -9 `ps -e | grep DFS2 | awk 'NR==1{print $1}'`

sleep 1

# Kill DFS Server 3
kill -9 `ps -e | grep DFS3 | awk 'NR==1{print $1}'`

sleep 1

# Kill DFS Server 4
kill -9 `ps -e | grep DFS4 | awk 'NR==1{print $1}'`

echo "Killed all dfs processes"
