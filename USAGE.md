# iOS Triangulation Detector - Usage Guide

This guide explains how to use the iOS Triangulation Detector tool to analyze full iOS filesystem images for signs of Operation Triangulation compromise.

## Prerequisites

- Python 3.6 or higher
- A mounted iOS filesystem image
- Basic understanding of digital forensics concepts

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/brett-cmd/ios-triangulation-detector.git
   cd ios-triangulation-detector
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Basic Usage

```
python -m ios_triangulation_detector /path/to/mounted_ios_image
```

Where `/path/to/mounted_ios_image` is the root directory of your mounted iOS filesystem image.

## Output Interpretation

The tool will analyze the filesystem and output one of two results:

1. **No traces found**: 
   ```
   No traces of compromise were identified
   ```

2. **Compromise detected**:
   ```
   ==== IDENTIFIED TRACES OF COMPROMISE (Operation Triangulation) ====
   2025-03-28 18:07:20+00:00 SUSPICION Suspicious combination of events: 
    * file modification: Library/SMS/Attachments/ff/15
    * file attribute change: Library/SMS/Attachments/ff/15
    * file modification: Library/SMS/Attachments/76/06
    * file attribute change: Library/SMS/Attachments/76/06
    * file attribute change: Library/Preferences/com.apple.locationd.StatusBarIconManager.plist
    * file modification: Library/Preferences/com.apple.imservice.ids.FaceTime.plist
   ```

## What The Tool Checks

1. **SMS Attachment Directories**
   - Looks for empty SMS attachment directories with suspicious modification patterns
   - Checks for coordinated changes across multiple attachment directories

2. **System Preferences**
   - Analyzes modification timestamps for key system preference files
   - Looks for unusual changes to location services and FaceTime configurations

3. **Network Activity**
   - Checks for suspicious processes with network activity
   - Analyzes data usage patterns for known malicious processes

4. **Location Services**
   - Checks for unusual location services activity
   - Looks for specific suspicious location bundles

## Preparing Your Filesystem Image

For best results:

1. Use a forensic tool like FTK Imager, Cellebrite, or similar to create a full filesystem image
2. Mount the image as read-only to prevent accidental modifications
3. Point the tool to the root of the mounted filesystem

## Example Workflow with Magnet AXIOM

1. Use Magnet AXIOM to create a full filesystem image of the iOS device
2. Export the filesystem image to a directory
3. Mount the filesystem image (or locate the extracted files)
4. Run the tool against the mounted/extracted filesystem
5. Compare the results with other evidence found in AXIOM

## Important Notes

- This tool is most effective on iOS 16.2 and earlier, as these versions are known to be vulnerable to Operation Triangulation
- Empty SMS attachment directories with synchronized modification times are a strong indicator of compromise
- The tool focuses on filesystem artifacts and may not detect all variants of Operation Triangulation
- For comprehensive analysis, combine these results with network traffic analysis and other forensic techniques

## Common Issues

1. **Missing Files or Directories**
   - Some iOS filesystem images may have different structures
   - Check that you're pointing to the correct root directory

2. **Permission Errors**
   - Ensure you have read access to all files in the image

3. **False Positives**
   - Some legitimate iOS behaviors can trigger alerts
   - Always correlate findings with other evidence

## Security Considerations

- Always work with write-protected copies of evidence
- Document all findings thoroughly
- Escalate potential compromises to your security team for further analysis
