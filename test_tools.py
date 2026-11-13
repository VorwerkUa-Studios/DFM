import json, subprocess, sys

proc = subprocess.Popen(
    [sys.executable, 'core/mcp_server.py'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True, encoding='utf-8'
)

proc.stdin.write(json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize','params':{}}) + '\n')
proc.stdin.write(json.dumps({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}) + '\n')
proc.stdin.flush()
proc.stdin.close()

out = proc.stdout.read()
err = proc.stderr.read()
lines = [l for l in out.strip().split('\n') if l]

resp = json.loads(lines[1])
tools = resp['result']['tools']
print(f'Total tools: {len(tools)}')
for t in tools:
    print(f'  {t["name"]}')
if err:
    print('STDERR:', err[:500])
