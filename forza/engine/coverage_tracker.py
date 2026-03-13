"""
Tracks which code paths have been hit across all fuzz iterations, 
and tells the mutation engine which strategies are working.

For the binary targets (cidrize, ip_parser) where coverage.py can't reach, 
it approximates coverage using behavioural novelty, treating each unique bug_key as a "new path"
"""