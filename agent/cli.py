"""Local CLI for testing the pipeline without deploying.

Usage:
    python -m agent.cli                      # analyze a built-in sample
    python -m agent.cli --sample bank_phishing
    python -m agent.cli --file email.txt     # analyze a file
    echo "..." | python -m agent.cli -       # analyze stdin
    python -m agent.cli --quiz "lương"       # quiz mode
"""
from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv

load_dotenv()

from . import pipeline, quiz  # noqa: E402
from samples.phishing_samples import SAMPLES  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="Phishing Guardian CLI")
    ap.add_argument("input", nargs="?", default=None,
                    help="text to analyze, or '-' for stdin")
    ap.add_argument("--sample", choices=sorted(SAMPLES),
                    help="analyze a built-in sample")
    ap.add_argument("--file", help="analyze the contents of a text file")
    ap.add_argument("--eml", help="analyze an email file (.eml/.msg/.html)")
    ap.add_argument("--quiz", nargs="?", const="", metavar="TOPIC",
                    help="generate a real-vs-phishing quiz pair")
    args = ap.parse_args()

    if args.quiz is not None:
        result = quiz.generate(args.quiz or None)
        if result.get("error"):
            print("ERROR:", result["error"], file=sys.stderr)
            sys.exit(1)
        for e in result.get("emails", []):
            print(f"\n===== Email {e.get('label')} =====\n{e.get('content')}")
        print(f"\n----- Giải thích -----\n{result.get('explanation', '')}")
        return

    if args.eml:
        with open(args.eml, "rb") as fh:
            result = pipeline.analyze_email_file(fh.read(), args.eml)
        if result.get("error"):
            print("ERROR:", result["error"], file=sys.stderr)
            sys.exit(1)
        print(result["display"])
        return

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    elif args.sample:
        text = SAMPLES[args.sample]
    elif args.input == "-":
        text = sys.stdin.read()
    elif args.input:
        text = args.input
    else:
        text = SAMPLES["hr_phishing"]
        print("(no input given — analyzing built-in 'hr_phishing' sample)\n")

    result = pipeline.analyze(text)
    if result.get("error"):
        print("ERROR:", result["error"], file=sys.stderr)
        sys.exit(1)
    print(result["display"])


if __name__ == "__main__":
    main()
