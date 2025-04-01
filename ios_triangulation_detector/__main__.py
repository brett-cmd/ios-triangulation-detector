from colorama import Fore, Style
import colorama
import sys
import os
from datetime import datetime, timezone
from . import IOSFilesystemChecker

def main():
    colorama.init()

    if len(sys.argv) == 1:
        print('iOS Triangulation Detector: Scan full iOS filesystem images for traces of compromise by Operation Triangulation')
        print('\n  Based on Kaspersky\'s triangle_check tool (© 2023 AO Kaspersky Lab)')
        print('  More info: https://securelist.com/operation-triangulation/109842/')
        print('\nUsage: python -m ios_triangulation_detector /path/to/mounted_ios_image')
        return
    
    root_path = sys.argv[1]
    
    # Verify the path exists and is a directory
    if not os.path.isdir(root_path):
        print(Fore.LIGHTRED_EX + f"Error: {root_path} is not a directory or doesn't exist" + Fore.RESET)
        return
    
    # Check if we can find the iOS directory structure
    ios_dirs = ['private/var/mobile', 'private/var/root', 'private/var/containers']
    missing_dirs = [d for d in ios_dirs if not os.path.isdir(os.path.join(root_path, d))]
    
    if missing_dirs:
        print(Fore.LIGHTYELLOW_EX + f"Warning: This doesn't appear to be a typical iOS filesystem. Missing directories: {', '.join(missing_dirs)}" + Fore.RESET)
        print(Fore.LIGHTYELLOW_EX + "Continuing anyway, but results may not be reliable." + Fore.RESET)
    
    checker = IOSFilesystemChecker()
    try:
        print(f"Scanning {root_path} for signs of Operation Triangulation compromise...")
        results = checker.scan_filesystem(root_path)
    except Exception as e:
        print(Fore.LIGHTRED_EX + str(e) + Fore.RESET)
        return

    if len(results) > 0:
        print(Fore.LIGHTRED_EX + '==== IDENTIFIED TRACES OF COMPROMISE (Operation Triangulation) ====' + Fore.RESET)
            
        for k in sorted(results):  # k is a UNIX timestamp of detection
            for detection in results[k]:
                dt = datetime.fromtimestamp(k, tz=timezone.utc)
                explanation = checker.detection_to_string(detection)
                if detection[0] == 'exact':
                    print(f'{dt} ' + Fore.LIGHTRED_EX + 'DETECTED' + Fore.RESET + ' ' + explanation)
                elif detection[0] == 'heuristics':
                    print(f'{dt} ' + Fore.LIGHTYELLOW_EX + 'SUSPICION' + Fore.RESET + ' ' + explanation)
        sys.exit(2)
    else:
        print(Fore.GREEN + 'No traces of compromise were identified' + Fore.RESET)
        print("Note: If relevant paths were not found or could not be analyzed, this result may not be conclusive.")
        print("Check console output above for any warnings or errors.")
        sys.exit(0)

if __name__ == "__main__":
    main()
