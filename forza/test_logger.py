import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "engine"))
import random
from engine.bug_oracle import BugResult, BugType
from engine.bug_logger import FuzzLogger


def test_my_logger():
    # 1. Setup the logger
    logger = FuzzLogger(output_dir="test_results", target="mock_ipv4_target")

    print("Starting Mock Fuzzing Test...")

    # 2. Simulate 100 iterations
    for i in range(1, 101):
        # Simulate a random bug type
        chosen_type = random.choices(
            [BugType.NORMAL, BugType.CRASH, BugType.TIMEOUT, BugType.INVALIDITY],
            weights=[80, 5, 5, 10]
        )[0]

        # Create a dummy BugResult
        mock_result = BugResult(
            input_data=b"\x00\x01\x02mock_data",
            stdout="Fake stdout content",
            stderr="Fake error message" if chosen_type != BugType.NORMAL else "",
            exit_code=0 if chosen_type == BugType.NORMAL else 1,
            timed_out=(chosen_type == BugType.TIMEOUT),
            bug_type=chosen_type,
            bug_key=("mock_cat", "MockExc",
                     "Sample error") if chosen_type != BugType.NORMAL else None,
            is_new_behavior=(
                chosen_type != BugType.NORMAL and random.random() > 0.5)
        )

        # 3. Trigger the logger methods your teammates will eventually call
        logger.record(mock_result, corpus_size=10)

        if i % 10 == 0:
            logger.print_status(corpus_size=10)

    # 4. Final snapshot
    logger.snapshot(corpus_size=12)
    print(f"\nTest Complete! Check the folder: {logger.out_dir}")


if __name__ == "__main__":
    test_my_logger()
