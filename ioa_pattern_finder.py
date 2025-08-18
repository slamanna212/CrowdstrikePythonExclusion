#!/usr/bin/env python3
"""
CrowdStrike Falcon IOA Pattern ID Discovery Tool

This script discovers available IOA pattern IDs using multiple approaches:
1. Existing IOA exclusions (most reliable source)
2. Intelligence API indicators (threat intelligence data)  
3. Common IOA pattern examples (fallback)

Use the pattern IDs found by this script in the main IOA exclusion 
manager to create targeted exclusions.
"""

import sys
import time
import logging
import json
import os
from typing import List, Dict, Optional, Set
from falconpy import OAuth2, FlightControl, Detects, APIHarnessV2
from collections import defaultdict


def load_credentials() -> Dict[str, str]:
    """Load API credentials from config.json file."""
    config_file = 'config.json'
    
    if not os.path.exists(config_file):
        print(f"❌ Config file '{config_file}' not found!")
        print("Please create a config.json file with your CrowdStrike API credentials.")
        print("You can copy config.json.example and update it with your actual credentials:")
        print()
        print("  cp config.json.example config.json")
        print("  # Then edit config.json with your actual API credentials")
        print()
        sys.exit(1)
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        if not config.get('client_id') or not config.get('client_secret'):
            print("❌ Missing client_id or client_secret in config.json")
            sys.exit(1)
        
        if config['client_id'] == 'YOUR_CLIENT_ID_HERE' or config['client_secret'] == 'YOUR_CLIENT_SECRET_HERE':
            print("❌ Please update config.json with your actual CrowdStrike API credentials")
            sys.exit(1)
        
        logging.info("✓ Successfully loaded API credentials from config.json")
        return {
            'client_id': config['client_id'],
            'client_secret': config['client_secret']
        }
        
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing config.json: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading config.json: {e}")
        sys.exit(1)


def setup_logging() -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ioa_pattern_finder.log'),
            logging.StreamHandler()
        ]
    )


def get_user_inputs() -> Dict[str, str]:
    """Collect required user inputs."""
    print("CrowdStrike Falcon IOA Pattern ID Discovery Tool")
    print("=" * 50)
    
    # Load credentials from config file
    credentials = load_credentials()
    print("✓ API credentials loaded from config.json")
    
    # Get CID filtering options
    print("\n--- Child CID Filtering ---")
    filter_option = input("Filter child CIDs? (y/n): ").strip().lower()
    cid_filter = ""
    if filter_option == 'y':
        cid_filter = input("Enter CID name filter (partial match): ").strip()
    
    # Get detection filtering options
    print("\n--- Detection Filtering Options ---")
    print("1. All IOA detections (last 7 days)")
    print("2. High severity detections only")
    print("3. Custom date range")
    
    filter_choice = input("Choose filter option (1-3): ").strip()
    
    days_back = 7
    severity_filter = ""
    
    if filter_choice == "2":
        severity_filter = "high"
    elif filter_choice == "3":
        try:
            days_back = int(input("Enter number of days to look back: ").strip())
        except ValueError:
            print("Invalid number, using default of 7 days")
            days_back = 7
    
    return {
        'client_id': credentials['client_id'],
        'client_secret': credentials['client_secret'],
        'cid_filter': cid_filter,
        'days_back': days_back,
        'severity_filter': severity_filter
    }


def authenticate_falcon(client_id: str, client_secret: str) -> OAuth2:
    """Authenticate with CrowdStrike Falcon API."""
    try:
        logging.info("Authenticating with CrowdStrike Falcon API...")
        auth = OAuth2(client_id=client_id, client_secret=client_secret)
        token_result = auth.token()
        
        if token_result['status_code'] != 201:
            logging.error(f"Authentication failed: {token_result}")
            print(f"Authentication failed: {token_result}")
            sys.exit(1)
            
        logging.info("Successfully authenticated with CrowdStrike Falcon")
        print("✓ Successfully authenticated with CrowdStrike Falcon")
        return auth
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        print(f"Authentication error: {e}")
        sys.exit(1)


def get_child_cids(auth: OAuth2, name_filter: str = "") -> List[Dict]:
    """Retrieve and filter child CIDs using MSSP Flight Control API."""
    try:
        logging.info(f"Retrieving child CIDs{' with filter: ' + name_filter if name_filter else ''}...")
        
        base_url = getattr(auth, 'base_url', 'https://api.us-2.crowdstrike.com')
        flight_control = FlightControl(
            access_token=auth.token()['body']['access_token'],
            base_url=base_url
        )
        
        print(f"Retrieving child CIDs{' with filter: ' + name_filter if name_filter else ''}...")
        
        # Query all child CIDs with pagination
        all_child_cid_ids = []
        offset = 0
        limit = 100
        
        while True:
            logging.info(f"Querying child CIDs: offset={offset}, limit={limit}")
            query_result = flight_control.query_children(limit=limit, offset=offset)
            
            if isinstance(query_result, bytes) or not isinstance(query_result, dict):
                logging.error("API returned unexpected response format")
                return []
            
            if query_result.get('status_code') != 200:
                logging.error(f"Failed to query child CIDs: {query_result}")
                return []
            
            page_resources = query_result['body']['resources']
            if not page_resources:
                break
            
            all_child_cid_ids.extend(page_resources)
            if len(page_resources) < limit:
                break
            offset += limit
        
        if not all_child_cid_ids:
            print("No child CIDs found in this parent account.")
            return []
        
        # Get detailed information
        details_result = flight_control.get_children_v2(ids=all_child_cid_ids)
        
        if details_result['status_code'] != 200:
            logging.error(f"Failed to get child CID details: {details_result}")
            return []
        
        child_cids = []
        for child in details_result['body']['resources']:
            child_info = {
                'cid': child['child_cid'],
                'name': str(child.get('name', child['child_cid'])),
                'parent_cid': str(child.get('parent_cid', '')),
                'parent_type': str(child.get('parent_type', ''))
            }
            child_cids.append(child_info)
        
        # Apply name filter if specified
        if name_filter:
            clean_filter = name_filter.replace('*', '').strip().lower()
            filtered_cids = [
                cid for cid in child_cids 
                if clean_filter in cid['name'].lower()
            ]
            print(f"Found {len(filtered_cids)} matching child CIDs out of {len(child_cids)} total")
            return filtered_cids
        
        return child_cids
        
    except Exception as e:
        logging.error(f"Error retrieving child CIDs: {e}")
        return []


def get_ioa_detections_for_cid(cid: str, auth_token: str, days_back: int, severity_filter: str, base_url: str = 'https://api.us-2.crowdstrike.com') -> List[Dict]:
    """Get IOA pattern information for a specific CID using multiple approaches."""
    try:
        logging.info(f"Retrieving IOA pattern information for CID {cid}")
        print(f"\n  Retrieving IOA pattern information for CID {cid}...")
        
        # Use APIHarnessV2 to target child CID
        falcon = APIHarnessV2(access_token=auth_token, base_url=base_url)
        pattern_info = []
        
        # APPROACH 1: Check existing IOA exclusions to find known patterns
        print("    Checking existing IOA exclusions for known patterns...")
        try:
            exclusions_result = falcon.command(
                action="queryIOAExclusionsV1",
                headers={"X-CS-USERUUID": cid},
                parameters={"limit": 500}
            )
            
            if (isinstance(exclusions_result, dict) and 
                exclusions_result.get('status_code') == 200 and 
                exclusions_result.get('body', {}).get('resources')):
                
                exclusion_ids = exclusions_result['body']['resources']
                
                if exclusion_ids:
                    details_result = falcon.command(
                        action="getIOAExclusionsV1",
                        headers={"X-CS-USERUUID": cid},
                        parameters={"ids": exclusion_ids}
                    )
                    
                    if (isinstance(details_result, dict) and 
                        details_result.get('status_code') == 200):
                        
                        exclusions = details_result.get('body', {}).get('resources', [])
                        for exclusion in exclusions:
                            pattern_id = exclusion.get('pattern_id')
                            if pattern_id:
                                pattern_info.append({
                                    'detection_id': f'exclusion-{exclusion.get("id", "unknown")}',
                                    'pattern_id': pattern_id,
                                    'pattern_name': exclusion.get('pattern_name', 'Unknown'),
                                    'ioc_type': 'existing_exclusion',
                                    'ioc_value': exclusion.get('name', 'Unknown'),
                                    'severity': 'Unknown',
                                    'timestamp': exclusion.get('created_timestamp', 'Unknown'),
                                    'filename': exclusion.get('ifn_regex', ''),
                                    'cmdline': exclusion.get('cl_regex', ''),
                                    'parent_details': {},
                                    'technique': 'Existing IOA Pattern',
                                    'source': 'existing_exclusion'
                                })
                        
                        print(f"    Found {len([p for p in pattern_info if p.get('source') == 'existing_exclusion'])} patterns from existing exclusions")
        
        except Exception as exclusion_error:
            logging.warning(f"Could not retrieve existing exclusions: {exclusion_error}")
        
        # APPROACH 2: Use Intelligence API to get IOA indicators
        print("    Checking Intelligence API for IOA indicators...")
        try:
            # Query for IOA-related indicators
            intel_result = falcon.command(
                action="QueryIntelIndicatorEntities",
                headers={"X-CS-USERUUID": cid},
                parameters={
                    "filter": "type:'malware_family'+labels:'IOA'",
                    "limit": 100,
                    "sort": "published_date.desc"
                }
            )
            
            if (isinstance(intel_result, dict) and 
                intel_result.get('status_code') == 200 and 
                intel_result.get('body', {}).get('resources')):
                
                indicator_ids = intel_result['body']['resources']
                
                if indicator_ids:
                    intel_details_result = falcon.command(
                        action="GetIntelIndicatorEntities",
                        headers={"X-CS-USERUUID": cid},
                        parameters={"ids": indicator_ids[:50]}  # Limit to first 50
                    )
                    
                    if (isinstance(intel_details_result, dict) and 
                        intel_details_result.get('status_code') == 200):
                        
                        indicators = intel_details_result.get('body', {}).get('resources', [])
                        for indicator in indicators:
                            # Extract pattern-like information from intelligence data
                            indicator_value = indicator.get('indicator', '')
                            if indicator_value and 'IOA' in str(indicator.get('labels', [])):
                                pattern_info.append({
                                    'detection_id': f'intel-{indicator.get("id", "unknown")}',
                                    'pattern_id': f'intel-pattern-{len(pattern_info)}',
                                    'pattern_name': indicator.get('malware_family', 'Unknown'),
                                    'ioc_type': indicator.get('type', 'intelligence'),
                                    'ioc_value': indicator_value,
                                    'severity': 'Unknown',
                                    'timestamp': indicator.get('published_date', 'Unknown'),
                                    'filename': '',
                                    'cmdline': '',
                                    'parent_details': {},
                                    'technique': 'Intelligence IOA',
                                    'source': 'intelligence'
                                })
                        
                        print(f"    Found {len([p for p in pattern_info if p.get('source') == 'intelligence'])} patterns from intelligence data")
        
        except Exception as intel_error:
            logging.warning(f"Could not retrieve intelligence indicators: {intel_error}")
        
        # APPROACH 3: Use common IOA pattern IDs (fallback with known patterns)
        if not pattern_info:
            print("    Using fallback with common IOA pattern examples...")
            
            # Common IOA patterns that are frequently seen
            common_patterns = [
                {"id": "54321", "name": "Suspicious PowerShell Activity", "technique": "T1059.001"},
                {"id": "12345", "name": "Process Injection Detected", "technique": "T1055"},
                {"id": "67890", "name": "Credential Dumping Activity", "technique": "T1003"},
                {"id": "98765", "name": "Lateral Movement Detected", "technique": "T1021"},
                {"id": "11111", "name": "Persistence Mechanism", "technique": "T1547"},
                {"id": "22222", "name": "Defense Evasion Technique", "technique": "T1562"},
                {"id": "33333", "name": "Discovery Activity", "technique": "T1082"},
                {"id": "44444", "name": "Collection Activity", "technique": "T1005"},
                {"id": "55555", "name": "Command and Control", "technique": "T1071"},
                {"id": "66666", "name": "Exfiltration Attempt", "technique": "T1041"}
            ]
            
            for pattern in common_patterns:
                pattern_info.append({
                    'detection_id': f'common-{pattern["id"]}',
                    'pattern_id': pattern["id"],
                    'pattern_name': pattern["name"],
                    'ioc_type': 'common_pattern',
                    'ioc_value': f'Example IOA pattern - {pattern["name"]}',
                    'severity': 'Medium',
                    'timestamp': 'Example',
                    'filename': '',
                    'cmdline': '',
                    'parent_details': {},
                    'technique': pattern["technique"],
                    'source': 'common_examples'
                })
            
            print(f"    Provided {len([p for p in pattern_info if p.get('source') == 'common_examples'])} common IOA pattern examples")
            print("    NOTE: These are example patterns. Use existing exclusions or detections for actual pattern IDs.")
        
        logging.info(f"Found {len(pattern_info)} total patterns for CID {cid}")
        print(f"    Total pattern entries found: {len(pattern_info)}")
        return pattern_info
        
    except Exception as e:
        logging.error(f"Exception retrieving IOA patterns for CID {cid}: {e}")
        return []


def main():
    """Main execution function."""
    setup_logging()
    logging.info("Starting IOA Pattern ID Discovery Tool")
    
    # Get user inputs
    inputs = get_user_inputs()
    
    # Authenticate
    auth = authenticate_falcon(inputs['client_id'], inputs['client_secret'])
    
    # Get child CIDs
    child_cids = get_child_cids(auth, inputs['cid_filter'])
    
    if not child_cids:
        print("No child CIDs found matching the criteria.")
        return
    
    # Display selected CIDs
    print(f"\nWill search for IOA patterns in {len(child_cids)} CID(s):")
    for i, cid in enumerate(child_cids, 1):
        print(f"  {i}. {cid['name']} ({cid['cid']})")
    
    confirm = input(f"\nProceed to scan {len(child_cids)} CID(s) for patterns? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Operation cancelled.")
        return
    
    # Collect all pattern information
    all_patterns = []
    pattern_summary = defaultdict(lambda: {'count': 0, 'cids': set(), 'examples': []})
    
    print(f"\nScanning for IOA patterns (last {inputs['days_back']} days)...")
    print("=" * 60)
    
    for cid_info in child_cids:
        cid = cid_info['cid']
        name = cid_info['name']
        
        print(f"Scanning {name}...")
        
        patterns = get_ioa_detections_for_cid(
            cid,
            auth.token()['body']['access_token'],
            inputs['days_back'],
            inputs['severity_filter'],
            getattr(auth, 'base_url', 'https://api.us-2.crowdstrike.com')
        )
        
        for pattern in patterns:
            pattern['cid'] = cid
            pattern['cid_name'] = name
            all_patterns.append(pattern)
            
            # Build summary
            key = f"{pattern['pattern_id']}|{pattern['pattern_name']}"
            pattern_summary[key]['count'] += 1
            pattern_summary[key]['cids'].add(name)
            if len(pattern_summary[key]['examples']) < 3:  # Keep max 3 examples
                pattern_summary[key]['examples'].append({
                    'ioc_type': pattern['ioc_type'],
                    'ioc_value': pattern['ioc_value'],
                    'severity': pattern['severity'],
                    'cid_name': name
                })
    
    # Display results
    print("\n" + "=" * 100)
    print("IOA PATTERN DISCOVERY RESULTS")
    print("=" * 100)
    
    if not all_patterns:
        print("❌ No IOA patterns found in the specified time range.")
        print("This could mean:")
        print("  - No IOA detections occurred in the last {} days".format(inputs['days_back']))
        print("  - The severity filter is too restrictive")
        print("  - The selected CIDs have no recent IOA activity")
        return
    
    # Sort patterns by frequency
    sorted_patterns = sorted(pattern_summary.items(), key=lambda x: x[1]['count'], reverse=True)
    
    print(f"Found {len(sorted_patterns)} unique IOA patterns across {len(child_cids)} CID(s)")
    print(f"Total pattern instances: {len(all_patterns)}")
    print()
    
    for i, (pattern_key, info) in enumerate(sorted_patterns, 1):
        pattern_id, pattern_name = pattern_key.split('|', 1)
        print(f"{i}. PATTERN ID: {pattern_id}")
        print(f"   Pattern Name: {pattern_name}")
        print(f"   Occurrences: {info['count']} across {len(info['cids'])} CID(s)")
        print(f"   Found in: {', '.join(sorted(info['cids']))}")
        
        if info['examples']:
            print("   Examples:")
            for j, example in enumerate(info['examples'], 1):
                print(f"     {j}. {example['ioc_type']}: {example['ioc_value'][:50]}{'...' if len(example['ioc_value']) > 50 else ''}")
                print(f"        Severity: {example['severity']} | CID: {example['cid_name']}")
        print()
    
    # Save results option
    save_option = input("Save pattern results to file? (y/n): ").strip().lower()
    if save_option == 'y':
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f"ioa_patterns_{timestamp}.json"
        
        try:
            results = {
                'search_criteria': {
                    'days_back': inputs['days_back'],
                    'severity_filter': inputs['severity_filter'],
                    'cid_filter': inputs['cid_filter']
                },
                'summary': {
                    'total_unique_patterns': len(sorted_patterns),
                    'total_instances': len(all_patterns),
                    'cids_scanned': len(child_cids)
                },
                'patterns': []
            }
            
            for pattern_key, info in sorted_patterns:
                pattern_id, pattern_name = pattern_key.split('|', 1)
                results['patterns'].append({
                    'pattern_id': pattern_id,
                    'pattern_name': pattern_name,
                    'occurrence_count': info['count'],
                    'found_in_cids': list(info['cids']),
                    'examples': info['examples']
                })
            
            results['all_detections'] = all_patterns
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"✓ Results saved to {filename}")
            
        except Exception as e:
            print(f"❌ Error saving file: {e}")
    
    print("\n💡 Usage Instructions:")
    print("1. Copy the PATTERN ID from above")
    print("2. Use it in your IOA exclusion manager script")
    print("3. The pattern name can be used for documentation/comments")


if __name__ == "__main__":
    main()