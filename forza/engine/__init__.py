# engine/__init__.py
# Makes engine/ a Python package so fuzzer.py can import from it cleanly:
#   from engine.target_runner import load_config, run_both
#   from engine.output_parser import BugOracle, BugType
#   from engine.mutation_engine import MutationEngine