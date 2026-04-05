import csv
from pathlib import Path

# Check all duplicates across all targets
results_dir = Path('forza/results')

targets = ['cidrize', 'ipv4_parser', 'ipv6_parser']

for target in targets:
    csv_file = results_dir / f'{target}_bugs.csv'
    if not csv_file.exists():
        continue
    
    line = "="*70
    print(f'\n\n{line}')
    print(f'TARGET: {target}')
    print(line)
    
    # Get all bug_keys and group by type
    bug_map = {}  # bug_key -> list of (bug_type, input, bug_num)
    
    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 1):
            key = row['bug_key']
            if key not in bug_map:
                bug_map[key] = []
            bug_map[key].append((
                row['bug_type'],
                row['input_data'][:30],
                i
            ))
    
    # Show duplicates
    duplicates = {k: v for k, v in bug_map.items() if len(v) > 1}
    if not duplicates:
        print('No duplicates')
        continue
    
    # Sort by frequency
    sorted_dupes = sorted(duplicates.items(), key=lambda x: len(x[1]), reverse=True)
    
    for bug_key, entries in sorted_dupes[:5]:  # top 5 duplicates
        print(f'\nDuplicate key: {bug_key} (appears {len(entries)} times)')
        for bug_type, inp, row_num in entries[:3]:  # show first 3
            print(f'  Row {row_num}: [{bug_type:12}] input: {inp}')
        if len(entries) > 3:
            print(f'  ... and {len(entries)-3} more')
