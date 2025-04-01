#!/usr/bin/env python3 
# Checks full iOS filesystem images for traces of compromise by Operation Triangulation
# Based on Kaspersky's triangle_check tool (© 2023 AO Kaspersky Lab. All Rights Reserved)

import sqlite3
import plistlib
import os
import os.path
import stat
from datetime import datetime, timezone

# Main class that handles the filesystem image scanning
class IOSFilesystemChecker:
    def __init__(self):
        self.timeline = {}
        self.detections = {}

    def append_map(self, timestamp, item, map):
        if not timestamp in map:
            map[timestamp] = []
        map[timestamp].append(item)

    def append_timeline(self, timestamp, item):
        self.append_map(timestamp, item, self.timeline)

    def append_detection(self, timestamp, item):
        self.append_map(timestamp, item, self.detections)

    def run_heuristics(self, event_window):
        """Analyzes a window of filesystem events for suspicious patterns"""
        sms_attachment_directories = {}
        timestamp_start = event_window[0][0]

        event_classes = set()

        for (event_timestamp, event) in event_window:
            event_type = event[0]
            if event_type in ['M', 'C', 'B']:  # filesystem events
                path = event[1]
                if 'Library/SMS/Attachments/' in path:
                    # The paths we want to detect are like:
                    # /private/var/mobile/Library/SMS/Attachments/ff/15
                    # /private/var/mobile/Library/SMS/Attachments/76/06
                    path_parts = path.split('Library/SMS/Attachments/')[1].split('/')
                    
                    # Check path depth to ensure we're looking at directories, not actual files
                    if len(path_parts) <= 2:
                        sms_attachment_directories[path] = sms_attachment_directories.get(path, {})
                        sms_attachment_directories[path][event_type] = True
                    else:
                        return  # False positive - actual attachment file
                else:  # other suspicious locations
                    event_classes.add('file')
            elif event_type in ['NetTimestamp', 'NetUsage', 'NetFirst', 'NetTimestamp2']:
                event_classes.add('net')
            elif event_type == 'LocationTimeStopped':
                event_classes.add('location')

        # Check that directories have both modification (M) and attribute change (C) events
        for k, v in sms_attachment_directories.items():
            if (not 'M' in v) or (not 'C' in v):
                return False
            
        if (len(sms_attachment_directories) > 0):
            event_classes.add('sms')

        # Alert if we have multiple suspicious event classes
        detection_threshold = 2
        if len(event_classes) >= detection_threshold:
            self.append_detection(timestamp_start, ('heuristics', event_window))

    def scan_filesystem(self, root_path):
        """Scans a full iOS filesystem image for signs of compromise"""
        self.root_path = root_path
        
        # Path mappings for key files we need to analyze
        self.paths = {
            'sms_attachments_dir': os.path.join(root_path, 'private/var/mobile/Library/SMS/Attachments'),
            'locationd_plist': os.path.join(root_path, 'private/var/mobile/Library/Preferences/com.apple.locationd.StatusBarIconManager.plist'),
            'facetime_plist': os.path.join(root_path, 'private/var/mobile/Library/Preferences/com.apple.imservice.ids.FaceTime.plist'),
            'imageio_plist': os.path.join(root_path, 'private/var/mobile/Library/Preferences/com.apple.ImageIO.plist'),
            'osanalytics_plist': os.path.join(root_path, 'private/var/mobile/Library/Preferences/com.apple.osanalytics.addaily.plist'),
            'datausage_db': os.path.join(root_path, 'private/var/mobile/Library/Databases/DataUsage.sqlite'),
            'locationd_clients': os.path.join(root_path, 'private/var/mobile/Library/Caches/locationd/clients.plist')
        }
        
        # Verify the path exists and is a directory
        if not os.path.isdir(self.paths['sms_attachments_dir']):
            raise FileNotFoundError(f"SMS attachments directory not found at {self.paths['sms_attachments_dir']}")
        
        # Start gathering file metadata for key files and directories
        self._check_sms_attachments()
        self._check_system_plists()
        self._check_analytics_data()
        
        # Analyze the timeline for suspicious patterns
        expanded_timeline = []
        for k in sorted(self.timeline):
            for item in self.timeline[k]:
                expanded_timeline.append((k, item))

        # Use a sliding window to look for suspicious event combinations
        events_max = 10
        time_delta_max = 60*5  # 5 minutes window
        for i in range(len(expanded_timeline)-events_max):
            timestamp_start = expanded_timeline[i][0]
            event_window = expanded_timeline[i:i+events_max]
            for j in range(len(event_window)):
                timestamp_item = event_window[j][0]
                if timestamp_item - timestamp_start > time_delta_max:
                    event_window = event_window[:j]
                    break

            self.run_heuristics(event_window)

        return self.detections
    
    def _check_sms_attachments(self):
        """Check SMS attachment directories for suspicious patterns"""
        # Walk through all the SMS attachment directories
        for root, dirs, files in os.walk(self.paths['sms_attachments_dir']):
            rel_path = root.replace(self.root_path, '').lstrip('/')
            if rel_path.count('/') >= 3:  # Only want to check the directory structure, not actual files
                continue
                
            # Get file stats
            try:
                stats = os.stat(root)
                mtime = stats.st_mtime
                ctime = stats.st_ctime
                birthtime = stats.st_birthtime if hasattr(stats, 'st_birthtime') else ctime
                
                # Record these events in our timeline
                self.append_timeline(mtime, ('M', rel_path))
                self.append_timeline(ctime, ('C', rel_path))
                self.append_timeline(birthtime, ('B', rel_path))
                
                # Check if directory is empty and record that
                if len(os.listdir(root)) == 0 and rel_path.count('/') >= 2:
                    # Empty attachment directory is suspicious
                    print(f"Empty attachment directory found: {rel_path} modified at {datetime.fromtimestamp(mtime)}")
            except Exception as e:
                print(f"Error accessing {rel_path}: {str(e)}")
    
    def _check_system_plists(self):
        """Check system preference files that are often modified during exploitation"""
        # List of important plist files to check
        plist_files = [
            ('locationd_plist', 'com.apple.locationd.StatusBarIconManager.plist'),
            ('facetime_plist', 'com.apple.imservice.ids.FaceTime.plist'),
            ('imageio_plist', 'com.apple.ImageIO.plist')
        ]
        
        for key, description in plist_files:
            path = self.paths[key]
            if os.path.exists(path):
                try:
                    stats = os.stat(path)
                    mtime = stats.st_mtime
                    ctime = stats.st_ctime
                    birthtime = stats.st_birthtime if hasattr(stats, 'st_birthtime') else ctime
                    
                    rel_path = path.replace(self.root_path, '').lstrip('/')
                    rel_path = '/'.join(rel_path.split('/')[-2:])  # Just get Library/Preferences/file.plist
                    
                    self.append_timeline(mtime, ('M', rel_path))
                    self.append_timeline(ctime, ('C', rel_path))
                    self.append_timeline(birthtime, ('B', rel_path))
                except Exception as e:
                    print(f"Error accessing {path}: {str(e)}")
    
    def _check_analytics_data(self):
        """Check analytics data for suspicious network activity"""
        # Check OS Analytics plist
        if os.path.exists(self.paths['osanalytics_plist']):
            try:
                with open(self.paths['osanalytics_plist'], 'rb') as f:
                    osanalytics = plistlib.load(f)
                
                if 'netUsageBaseline' in osanalytics:
                    baseline = osanalytics['netUsageBaseline']
                    
                    # Known suspicious processes
                    process_IOCs_exact = ['BackupAgent']
                    process_IOCs_implicit = ['nehelper', 'com.apple.WebKit.WebContent', 'powerd/com.apple.datausage.diagnostics', 'lockdownd/com.apple.datausage.security']
                    
                    for package in baseline:
                        if package in process_IOCs_exact:
                            self.append_detection(baseline[package][0].replace(tzinfo=timezone.utc).timestamp(), ('exact', 'NetUsage', package))
                        if (package in process_IOCs_implicit) or (package in process_IOCs_exact):
                            self.append_timeline(baseline[package][0].replace(tzinfo=timezone.utc).timestamp(), ('NetUsage', package))
            except Exception as e:
                print(f"Error analyzing OS analytics: {str(e)}")
        
        # Check DataUsage database
        if os.path.exists(self.paths['datausage_db']):
            try:
                datausage = sqlite3.connect(self.paths['datausage_db'])
                data_cur = datausage.cursor()
                
                # Need to adjust Apple's timestamp (2001 epoch) to Unix timestamp
                cocoa_delta = 978307200.0
                
                # Known suspicious processes
                process_IOCs_exact = ['BackupAgent']
                process_IOCs_implicit = ['nehelper', 'com.apple.WebKit.WebContent', 'powerd/com.apple.datausage.diagnostics', 'lockdownd/com.apple.datausage.security']
                
                # Query process and usage data
                for first_timestamp, proc_timestamp, procname, bundlename, pk, timestamp in data_cur.execute(
                    'SELECT ZPROCESS.ZFIRSTTIMESTAMP,ZPROCESS.ZTIMESTAMP,ZPROCESS.ZPROCNAME,ZPROCESS.ZBUNDLENAME,ZPROCESS.Z_PK,'
                    'ZLIVEUSAGE.ZTIMESTAMP FROM ZLIVEUSAGE LEFT JOIN ZPROCESS ON ZLIVEUSAGE.ZHASPROCESS = ZPROCESS.Z_PK UNION '
                    'SELECT ZFIRSTTIMESTAMP, ZTIMESTAMP, ZPROCNAME, ZBUNDLENAME, Z_PK, NULL FROM ZPROCESS WHERE Z_PK NOT IN (SELECT ZHASPROCESS FROM ZLIVEUSAGE)'):
                    
                    if procname in process_IOCs_exact:
                        self.append_detection(cocoa_delta + first_timestamp, ('exact', 'NetFirst', procname))
                        self.append_detection(cocoa_delta + proc_timestamp, ('exact', 'NetTimestamp', procname))
                        if timestamp is not None:
                            self.append_detection(cocoa_delta + timestamp, ('exact', 'NetTimestamp2', procname))
                    elif (procname in process_IOCs_implicit):
                        self.append_timeline(cocoa_delta + first_timestamp, ('NetFirst', procname))
                        self.append_timeline(cocoa_delta + proc_timestamp, ('NetTimestamp', procname))
                        if timestamp is not None:
                            self.append_timeline(cocoa_delta + timestamp, ('NetTimestamp2', procname))
                
                datausage.close()
            except Exception as e:
                print(f"Error analyzing data usage: {str(e)}")
        
        # Check LocationD clients
        if os.path.exists(self.paths['locationd_clients']):
            try:
                with open(self.paths['locationd_clients'], 'rb') as f:
                    locationd_clients = plistlib.load(f)
                
                location_client_IOCs = [
                    'com.apple.locationd.bundle-/System/Library/LocationBundles/IonosphereHarvest.bundle',
                    'com.apple.locationd.bundle-/System/Library/LocationBundles/WRMLinkSelection.bundle'
                ]
                
                cocoa_delta = 978307200.0
                
                for package in locationd_clients:
                    item = locationd_clients[package]
                    if (package in location_client_IOCs) and ('LocationTimeStopped' in item):
                        self.append_timeline(cocoa_delta + item['LocationTimeStopped'], ('LocationTimeStopped', package))
            except Exception as e:
                print(f"Error analyzing location clients: {str(e)}")
    
    def detection_to_string(self, detection):
        """Convert a detection to a human-readable string"""
        if detection[0] == 'exact':
            return f'Exact match by {detection[1]} : {detection[2]}'
        elif detection[0] == 'heuristics':
            result = f'Suspicious combination of events: '
            for timestamp, event in detection[1]:
                event_type = event[0]
                if event_type == 'M':
                    result += f'\n * file modification: {event[1]}'
                elif event_type == 'C':
                    result += f'\n * file attribute change: {event[1]}'
                elif event_type == 'B':
                    result += f'\n * file birth: {event[1]}'
                elif event_type == 'LocationTimeStopped':
                    result += f'\n * location service stopped: {event[1]}'
                elif event_type in ['NetTimestamp', 'NetUsage', 'NetFirst', 'NetTimestamp2']:
                    result += f'\n * traffic by process {event[1]}'
                else:
                    raise RuntimeError(f'Unknown detection event {event_type}')
            return result
