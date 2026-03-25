import sys
import os

# We must patch sys.argv BEFORE AFL initializes so the child forks share the correctly 
# evaluated memory mapping. However, `python-afl` usually operates best via std-in.
# To bypass issues where `json_decoder_stv.py` relies heavily on `--str-json`, we must 
# also verify how AFL is supplying arguments.

if len(sys.argv) > 1:
    last_arg = sys.argv[-1]
    if os.path.isfile(last_arg):
        try:
            with open(last_arg, "r") as f:
                payload = f.read()
            sys.argv[-1] = payload
        except:
            pass

try:
    import afl
    afl.init()

except ImportError:
    print("python-afl not installed. Please install it (pip install python-afl)")
    sys.exit(1)

# Dynamically set up the path so we can import the original script
target_dir = os.path.join(os.path.dirname(__file__), "..", "..", "json-decoder")
sys.path.insert(0, os.path.abspath(target_dir))

# Just run the json decoder as normal, AFL will wrap execution
import json_decoder_stv
