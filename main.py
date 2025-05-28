import argparse
from agent import PoCky

def main():
    parser = argparse.ArgumentParser(description='CVE PoC Collector Agent')
    parser.add_argument('cve_id', help='CVE ID to search for (e.g., CVE-2023-1234)')
    args = parser.parse_args()
    
    pocky = PoCky()

    pocky.run_workflow(args.cve_id, stream=True)

if __name__ == "__main__":
    main() 