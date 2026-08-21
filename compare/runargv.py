import subprocess,sys,os
cwd=os.environ.get("RUN_CWD") or None
print("running", sys.argv[1:], "cwd", cwd)
r=subprocess.run(sys.argv[1:], cwd=cwd)
sys.exit(r.returncode)
