#!/usr/bin/env python3
#Test git with new line
"""
CrowdStrike Falcon IOA Exclusion Manager

This script manages IOA (Indicator of Attack) exclusions across multiple child CIDs
under a parent CrowdStrike Falcon account. It allows filtering of child CIDs
by name and applies IOA exclusions to selected environments.
"""

import sys
import getpass
import time
import logging
import json
import os
from typing import List, Dict, Optional
from falconpy import OAuth2, IOAExclusions, FlightControl, HostGroup


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
            logging.FileHandler('crowdstrike_exclusion_manager.log'),
            logging.StreamHandler()
        ]
    )


def rate_limit_delay(operation_count: int, max_operations_per_minute: int = 30) -> None:
    """Add delay to respect API rate limits."""
    if operation_count > 0 and operation_count % max_operations_per_minute == 0:
        logging.info("Rate limiting: Waiting 60 seconds...")
        time.sleep(60)
    elif operation_count > 0 and operation_count % 5 == 0:
        # Small delay every 5 operations
        time.sleep(1)


def get_user_inputs() -> Dict[str, str]:
    """Collect required user inputs."""
    print("CrowdStrike Falcon IOA Exclusion Manager")
    print("=" * 40)
    
    # Load credentials from config file
    credentials = load_credentials()
    print("✓ API credentials loaded from config.json")
    
    # Get CID filtering options
    print("\n--- Child CID Filtering ---")
    filter_option = input("Filter child CIDs? (y/n): ").strip().lower()
    cid_filter = ""
    if filter_option == 'y':
        cid_filter = input("Enter CID name filter (partial match): ").strip()
    
    # Get IOA exclusion details
    print("\n--- IOA Exclusion Details ---")
    print("Note: pattern_id comes from existing IOA detections in CrowdStrike Console")
    print("Go to Activity > Detections, find the IOA detection, and copy the pattern ID")
    pattern_id = input("Enter IOA pattern_id (required): ").strip()
    pattern_name = input("Enter pattern name (optional): ").strip()
    exclusion_name = input("Enter exclusion name: ").strip()
    exclusion_description = input("Enter exclusion description (optional): ").strip()
    image_filename = input("Enter image filename pattern (regex, optional): ").strip()
    command_line = input("Enter command line pattern (regex, optional): ").strip()
    exclusion_comment = input("Enter exclusion comment (optional): ").strip()
    
    # Validate required field
    if not pattern_id:
        print("❌ Error: pattern_id is required for IOA exclusions!")
        print("Please find the pattern_id from an IOA detection in the CrowdStrike console.")
        sys.exit(1)
    
    return {
        'client_id': credentials['client_id'],
        'client_secret': credentials['client_secret'],
        'cid_filter': cid_filter,
        'pattern_id': pattern_id,
        'pattern_name': pattern_name,
        'exclusion_name': exclusion_name,
        'exclusion_description': exclusion_description,
        'image_filename': image_filename,
        'command_line': command_line,
        'exclusion_comment': exclusion_comment
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
        
        # Initialize Flight Control service with the same base URL as OAuth2
        # Get the base URL from the auth object to ensure consistency
        base_url = getattr(auth, 'base_url', 'https://api.us-2.crowdstrike.com')
        logging.debug(f"Using base URL for FlightControl: {base_url}")
        flight_control = FlightControl(
            access_token=auth.token()['body']['access_token'],
            base_url=base_url
        )
        
        print(f"Retrieving child CIDs{' with filter: ' + name_filter if name_filter else ''}...")
        
        # Query all child CIDs with pagination support
        logging.debug("About to call flight_control.query_children() with pagination")
        all_child_cid_ids = []
        offset = 0
        limit = 100  # Request more per page
        
        while True:
            try:
                # Call with limit and offset for pagination
                logging.info(f"Querying child CIDs: offset={offset}, limit={limit}")
                print(f"Querying child CIDs: offset={offset}, limit={limit}")
                
                query_result = flight_control.query_children(
                    limit=limit,
                    offset=offset
                )
                logging.debug(f"query_children() returned: type={type(query_result)}")
                
            except Exception as query_error:
                logging.error(f"Error in query_children(): {query_error}")
                logging.debug(f"Query error type: {type(query_error)}")
                raise
        
            # Handle case where API returns bytes instead of dict (usually due to 308 redirect)
            if isinstance(query_result, bytes):
                logging.error("API returned bytes instead of expected dict response")
                print("API endpoint returned unexpected response format (likely due to 308 redirect)")
                print("This may indicate a region-specific endpoint issue or API version mismatch")
                return []
            
            # Handle case where API returns non-dict response
            if not isinstance(query_result, dict):
                logging.error(f"API returned unexpected type: {type(query_result)}")
                print(f"API returned unexpected response type: {type(query_result)}")
                return []
            
            logging.debug(f"query_result status_code: {query_result.get('status_code', 'No status_code key')}")
            
            if query_result.get('status_code') != 200:
                logging.error(f"Failed to query child CIDs: {query_result}")
                print(f"Failed to query child CIDs: {query_result}")
                
                # Handle 308 redirect specifically
                if query_result.get('status_code') == 308:
                    logging.info("Received 308 redirect, this may be a region-specific endpoint issue")
                    print("Received 308 redirect - this may indicate a region-specific endpoint issue")
                
                return []
            
            # Get the resources from this page
            page_resources = query_result['body']['resources']
            
            if not page_resources:
                # No more results, break the pagination loop
                logging.info(f"No more child CIDs found at offset {offset}")
                break
            
            # Add this page's results to our total list
            all_child_cid_ids.extend(page_resources)
            logging.info(f"Retrieved {len(page_resources)} child CIDs on this page (total so far: {len(all_child_cid_ids)})")
            print(f"  Retrieved {len(page_resources)} child CIDs on this page (total so far: {len(all_child_cid_ids)})")
            
            # Check if we got fewer results than requested, indicating last page
            if len(page_resources) < limit:
                logging.info("Retrieved fewer results than limit, assuming last page")
                break
            
            # Move to next page
            offset += limit
        
        child_cid_ids = all_child_cid_ids
        
        if not child_cid_ids:
            logging.warning("No child CIDs found in this parent account.")
            print("No child CIDs found in this parent account.")
            return []
        
        logging.info(f"Found {len(child_cid_ids)} total child CID IDs: {child_cid_ids}")
        print(f"\n✓ Successfully retrieved {len(child_cid_ids)} total child CID IDs from all pages")
        
        # Get detailed information for each child CID
        logging.debug(f"Calling get_children_v2 with {len(child_cid_ids)} IDs")
        details_result = flight_control.get_children_v2(ids=child_cid_ids)
        
        logging.debug(f"get_children_v2 result type: {type(details_result)}")
        logging.debug(f"get_children_v2 keys: {details_result.keys() if isinstance(details_result, dict) else 'Not a dict'}")
        
        if details_result['status_code'] != 200:
            logging.error(f"Failed to get child CID details: {details_result}")
            print(f"Failed to get child CID details: {details_result}")
            return []
        
        logging.debug(f"Body type: {type(details_result['body'])}")
        logging.debug(f"Resources type: {type(details_result['body']['resources'])}")
        
        child_cids = []
        for i, child in enumerate(details_result['body']['resources']):
            try:
                logging.debug(f"Processing child {i}: type={type(child)}, content={child}")
                child_info = {
                    'cid': child['child_cid'],
                    'name': str(child.get('name', child['child_cid'])),  # Ensure name is string
                    'parent_cid': str(child.get('parent_cid', '')),
                    'parent_type': str(child.get('parent_type', ''))
                }
                child_cids.append(child_info)
            except Exception as child_error:
                logging.error(f"Error processing child {i}: {child_error}")
                logging.debug(f"Child data: {child}")
                raise
        
        # Apply name filter if specified
        if name_filter:
            logging.info(f"Applying filter '{name_filter}' to {len(child_cids)} child CIDs")
            # Remove wildcards from the filter for substring matching
            clean_filter = name_filter.replace('*', '').strip()
            logging.info(f"Cleaned filter: '{clean_filter}'")
            
            filtered_cids = []
            for cid in child_cids:
                try:
                    cid_name_lower = cid['name'].lower()
                    clean_filter_lower = clean_filter.lower()
                    match = clean_filter_lower in cid_name_lower
                    
                    if match:
                        filtered_cids.append(cid)
                        logging.info(f"Match found: {cid['name']}")
                        
                except Exception as filter_error:
                    logging.error(f"Error filtering CID {cid}: {filter_error}")
                    logging.debug(f"CID data: {cid}")
                    logging.debug(f"CID name type: {type(cid.get('name', 'N/A'))}")
                    logging.debug(f"Filter type: {type(clean_filter)}")
            logging.info(f"Found {len(filtered_cids)} matching child CIDs out of {len(child_cids)} total")
            print(f"\n✓ Found {len(filtered_cids)} matching child CIDs out of {len(child_cids)} total")
            
            if filtered_cids:
                print("\nChild CIDs that will be affected:")
                for i, cid in enumerate(filtered_cids, 1):
                    print(f"  {i}. {cid['name']} ({cid['cid']})")
            
            return filtered_cids
        
        logging.info(f"Found {len(child_cids)} child CIDs total")
        print(f"Found {len(child_cids)} child CIDs")
        return child_cids
        
    except Exception as e:
        logging.error(f"Error retrieving child CIDs: {e}")
        print(f"Error retrieving child CIDs: {e}")
        # Fallback to sample data for testing
        logging.warning("Using sample data for testing...")
        print("Using sample data for testing...")
        sample_cids = [
            {"cid": "sample-child1-cid", "name": "Production Environment", "parent_cid": "", "parent_type": ""},
            {"cid": "sample-child2-cid", "name": "Staging Environment", "parent_cid": "", "parent_type": ""},
            {"cid": "sample-child3-cid", "name": "Development Environment", "parent_cid": "", "parent_type": ""}
        ]
        
        if name_filter:
            filtered_cids = [cid for cid in sample_cids if name_filter.lower() in cid['name'].lower()]
            return filtered_cids
        
        return sample_cids


def get_host_groups_for_cid(cid: str, auth_token: str, base_url: str = 'https://api.us-2.crowdstrike.com') -> List[Dict]:
    """Get all host groups with details (ID and name) for a specific CID."""
    try:
        logging.info(f"Retrieving host groups for CID {cid}")
        
        # Initialize HostGroup service for specific CID
        # Use member_cid parameter to target the child CID
        host_groups_service = HostGroup(access_token=auth_token, base_url=base_url, member_cid=cid)
        
        # Query all host group IDs
        query_result = host_groups_service.query_host_groups()
        
        if isinstance(query_result, bytes) or not isinstance(query_result, dict):
            logging.error(f"HostGroup API returned unexpected type for CID {cid}: {type(query_result)}")
            return []
        
        if query_result.get('status_code') != 200:
            logging.error(f"Failed to query host groups for CID {cid}: {query_result}")
            return []
        
        group_ids = query_result['body']['resources']
        logging.info(f"Found {len(group_ids)} host group IDs for CID {cid}")
        
        if not group_ids:
            return []
        
        # Get detailed information for each group
        details_result = host_groups_service.get_host_groups(ids=group_ids)
        
        if isinstance(details_result, bytes) or not isinstance(details_result, dict):
            logging.error(f"HostGroup details API returned unexpected type for CID {cid}: {type(details_result)}")
            return []
        
        if details_result.get('status_code') != 200:
            logging.error(f"Failed to get host group details for CID {cid}: {details_result}")
            return []
        
        groups_with_details = []
        for group in details_result['body']['resources']:
            groups_with_details.append({
                'id': group['id'],
                'name': group.get('name', 'Unknown'),
                'description': group.get('description', '')
            })
        
        logging.info(f"Retrieved details for {len(groups_with_details)} host groups for CID {cid}")
        for group in groups_with_details:
            logging.info(f"  Group: {group['name']} ({group['id']})")
        
        return groups_with_details
        
    except Exception as e:
        logging.error(f"Exception retrieving host groups for CID {cid}: {e}")
        return []


def find_windows_hosts_group(host_groups: List[Dict]) -> List[str]:
    """Find the best matching host group for 'Windows Hosts'."""
    if not host_groups:
        return []
    
    # Exact match first
    for group in host_groups:
        if group['name'].lower() == 'windows hosts':
            logging.info(f"Found exact match for 'Windows Hosts': {group['name']} ({group['id']})")
            return [group['id']]
    
    # Fuzzy matching - look for groups containing 'windows' and 'host'
    windows_groups = []
    for group in host_groups:
        group_name_lower = group['name'].lower()
        if 'windows' in group_name_lower and 'host' in group_name_lower:
            windows_groups.append(group)
            logging.info(f"Found Windows host group match: {group['name']} ({group['id']})")
    
    if windows_groups:
        # If multiple matches, prefer the one with the shortest name (most specific)
        best_match = min(windows_groups, key=lambda g: len(g['name']))
        logging.info(f"Selected best Windows host group match: {best_match['name']} ({best_match['id']})")
        return [best_match['id']]
    
    # Fallback - look for groups containing just 'windows'
    for group in host_groups:
        if 'windows' in group['name'].lower():
            logging.info(f"Found fallback Windows group: {group['name']} ({group['id']})")
            return [group['id']]
    
    # Last resort - look for any group containing 'host'
    for group in host_groups:
        if 'host' in group['name'].lower():
            logging.info(f"Found fallback host group: {group['name']} ({group['id']})")
            return [group['id']]
    
    # If no good matches, use the first available group
    if host_groups:
        logging.warning(f"No Windows/host groups found, using first available: {host_groups[0]['name']} ({host_groups[0]['id']})")
        return [host_groups[0]['id']]
    
    return []


def create_ioa_exclusion_for_cid(cid: str, pattern_id: str, pattern_name: str, exclusion_name: str, exclusion_description: str, image_filename: str, command_line: str, comment: str, auth_token: str, base_url: str = 'https://api.us-2.crowdstrike.com') -> Dict:
    """Create IOA exclusion for a specific CID."""
    try:
        logging.info(f"Creating IOA exclusion for CID {cid}: {exclusion_name}")
        
        # Initialize IOAExclusions service for specific CID
        ioa_exclusions = IOAExclusions(access_token=auth_token, base_url=base_url, member_cid=cid)
        
        # Get host groups for this CID and find Windows Hosts group
        host_groups_details = get_host_groups_for_cid(cid, auth_token, base_url)
        
        if not host_groups_details:
            logging.warning(f"No host groups found for CID {cid}, creating exclusion without group restriction")
            target_group_ids = []  # Empty list means no specific groups
        else:
            # Find the best matching Windows Hosts group
            target_group_ids = find_windows_hosts_group(host_groups_details)
            if target_group_ids:
                # Find the group name for logging
                selected_group = next((g for g in host_groups_details if g['id'] == target_group_ids[0]), None)
                if selected_group:
                    logging.info(f"Targeting Windows Hosts group: {selected_group['name']} ({selected_group['id']})")
                    print(f"  Targeting group: {selected_group['name']}")
            else:
                logging.warning(f"No suitable Windows Hosts group found for CID {cid}")
                target_group_ids = []
        
        # Create the IOA exclusion - pattern_id is required, others are optional
        exclusion_params = {
            'pattern_id': pattern_id,
            'groups': target_group_ids
        }
        
        if pattern_name:
            exclusion_params['pattern_name'] = pattern_name
        if exclusion_name:
            exclusion_params['name'] = exclusion_name
        if exclusion_description:
            exclusion_params['description'] = exclusion_description
        if image_filename:
            exclusion_params['ifn_regex'] = image_filename
        if command_line:
            exclusion_params['cl_regex'] = command_line
        if comment:
            exclusion_params['comment'] = comment
        
        result = ioa_exclusions.create_exclusions(**exclusion_params)
        
        # Handle case where API returns bytes instead of dict (usually due to 308 redirect)
        if isinstance(result, bytes):
            logging.error(f"IOAExclusions API returned bytes for CID {cid}")
            return {
                'success': False,
                'status_code': 0,
                'response': {'error': 'API returned bytes instead of expected dict response'},
                'exclusion_id': ''
            }
        
        # Handle case where API returns non-dict response
        if not isinstance(result, dict):
            logging.error(f"IOAExclusions API returned unexpected type for CID {cid}: {type(result)}")
            return {
                'success': False,
                'status_code': 0,
                'response': {'error': f'API returned unexpected response type: {type(result)}'},
                'exclusion_id': ''
            }
        
        success = result['status_code'] in [200, 201]
        exclusion_id = ''
        
        if success and 'body' in result and 'resources' in result['body'] and result['body']['resources']:
            exclusion_id = result['body']['resources'][0].get('id', '')
        
        if success:
            logging.info(f"Successfully created exclusion for CID {cid}, ID: {exclusion_id}")
        else:
            logging.error(f"Failed to create exclusion for CID {cid}: {result}")
        
        return {
            'success': success,
            'status_code': result['status_code'],
            'response': result,
            'exclusion_id': exclusion_id
        }
            
    except Exception as e:
        logging.error(f"Exception creating exclusion for CID {cid}: {e}")
        return {
            'success': False,
            'status_code': 0,
            'response': {'error': str(e)},
            'exclusion_id': ''
        }


def main():
    """Main execution function."""
    # Setup logging
    setup_logging()
    
    logging.info("Starting CrowdStrike Falcon IOA Exclusion Manager")
    
    # Get user inputs
    inputs = get_user_inputs()
    
    # Authenticate
    auth = authenticate_falcon(inputs['client_id'], inputs['client_secret'])
    
    # Get child CIDs
    child_cids = get_child_cids(auth, inputs['cid_filter'])
    
    if not child_cids:
        print("No child CIDs found matching the criteria.")
        return
    
    # Display selected CIDs and confirm
    print(f"\nSelected Child CIDs ({len(child_cids)}):")
    for cid in child_cids:
        print(f"  - {cid['name']} ({cid['cid']})")
    
    confirm = input(f"\nProceed to add exclusion to {len(child_cids)} CID(s)? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Operation cancelled.")
        return
    
    # Apply exclusions
    successful_cids = []
    failed_cids = []
    operation_count = 0
    
    logging.info(f"Starting to apply IOA exclusion '{inputs['exclusion_name']}' to {len(child_cids)} CIDs")
    print(f"\nApplying IOA exclusion: {inputs['exclusion_name']}")
    print("=" * 50)
    
    for cid_info in child_cids:
        cid = cid_info['cid']
        name = cid_info['name']
        operation_count += 1
        
        print(f"Processing {name} ({cid})...")
        
        # Apply rate limiting
        rate_limit_delay(operation_count)
        
        result = create_ioa_exclusion_for_cid(
            cid, 
            inputs['pattern_id'],
            inputs['pattern_name'],
            inputs['exclusion_name'],
            inputs['exclusion_description'],
            inputs['image_filename'],
            inputs['command_line'],
            inputs['exclusion_comment'],
            auth.token()['body']['access_token'],
            getattr(auth, 'base_url', 'https://api.us-2.crowdstrike.com')
        )
        
        if result['success']:
            cid_info['exclusion_id'] = result['exclusion_id']
            successful_cids.append(cid_info)
            print(f"✓ Successfully added exclusion to {name}")
            if result['exclusion_id']:
                print(f"  Exclusion ID: {result['exclusion_id']}")
        else:
            cid_info['error'] = result['response']
            failed_cids.append(cid_info)
            print(f"✗ Failed to add exclusion to {name}")
            print(f"  Error: {result['response']}")
    
    # Summary report
    print("\n" + "=" * 50)
    print("SUMMARY REPORT")
    print("=" * 50)
    print(f"Total CIDs processed: {len(child_cids)}")
    print(f"Successful: {len(successful_cids)}")
    print(f"Failed: {len(failed_cids)}")
    
    print(f"\nIOA Exclusion Details:")
    print(f"  Pattern ID: {inputs['pattern_id']}")
    print(f"  Pattern Name: {inputs['pattern_name'] or 'None'}")
    print(f"  Name: {inputs['exclusion_name']}")
    print(f"  Description: {inputs['exclusion_description'] or 'None'}")
    print(f"  Image Filename Pattern (ifn_regex): {inputs['image_filename'] or 'None'}")
    print(f"  Command Line Pattern (cl_regex): {inputs['command_line'] or 'None'}")
    print(f"  Comment: {inputs['exclusion_comment'] or 'None'}")
    
    if successful_cids:
        print("\n✓ Successfully modified CIDs:")
        for cid_info in successful_cids:
            exclusion_id = cid_info.get('exclusion_id', 'N/A')
            print(f"  - {cid_info['name']} ({cid_info['cid']})")
            print(f"    Exclusion ID: {exclusion_id}")
    
    if failed_cids:
        print("\n✗ Failed CIDs:")
        for cid_info in failed_cids:
            print(f"  - {cid_info['name']} ({cid_info['cid']})")
            error_msg = str(cid_info.get('error', 'Unknown error'))
            print(f"    Error: {error_msg[:100]}{'...' if len(error_msg) > 100 else ''}")


if __name__ == "__main__":
    main()