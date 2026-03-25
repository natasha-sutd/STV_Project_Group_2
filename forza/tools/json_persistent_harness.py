import sys
import os

try:
    import afl
except ImportError:
    print("python-afl not installed.")
    sys.exit(1)

# Dynamically set up the path so we can import ONLY the decoder
target_dir = os.path.join(os.path.dirname(__file__), "..", "..", "json-decoder")
sys.path.insert(0, os.path.abspath(target_dir))

# Import just the core function and exceptions, completely bypassing pandas, coverage, and CSV writing!
from buggy_json import loads
from buggy_json.decoder_stv import PerformanceBug, InvalidityBug, JSONDecodeError

target_file = sys.argv[-1] if len(sys.argv) > 1 else None

# PERSISTENT MODE: We tell AFL to keep the interpreter alive and just loop this section!
while afl.loop(1000):
    try:
        if target_file and os.path.isfile(target_file):
            with open(target_file, "r") as f:
                payload = f.read()
        else:
            # Fallback
            payload = ""
            
        # Execute the target directly
        loads(payload)
        
    except (PerformanceBug, InvalidityBug):
        # IMPORTANT: AFL only detects OS-level crashes (Segfaults). 
        # Since Python safely catches exceptions, we must explicitly crash the 
        # OS process so AFL knows your target's bug was hit!
        os.abort()
        
    except JSONDecodeError:
        # Expected parsing errors are NOT programmatic crashes, ignore them.
        pass
        
    except Exception:
        # Any other unknown unhandled exceptions are bonus crashes!
        os.abort()
