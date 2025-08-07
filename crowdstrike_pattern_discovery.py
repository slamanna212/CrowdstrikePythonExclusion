#!/usr/bin/env python3
"""
CrowdStrike Falcon IOA Exclusion Discovery Tool

This script lists existing IOA exclusions across multiple child CIDs
under a parent CrowdStrike Falcon account. It allows filtering of child CIDs
by name and shows current IOA exclusions with their pattern IDs.
"""

import sys
import time
import logging
import json
import os
from typing import List, Dict, Optional
from falconpy import OAuth2, IOAExclusions, FlightControl, APIHarnessV2


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
            logging.FileHandler('crowdstrike_pattern_discovery.log'),
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
    print("CrowdStrike Falcon IOA Exclusion Discovery Tool")
    print("=" * 47)
    
    # Load credentials from config file
    credentials = load_credentials()
    print("✓ API credentials loaded from config.json")
    
    # Get CID filtering options
    print("\n--- Child CID Filtering ---")
    filter_option = input("Filter child CIDs? (y/n): ").strip().lower()
    cid_filter = ""
    if filter_option == 'y':
        cid_filter = input("Enter CID name filter (partial match): ").strip()
    
    return {
        'client_id': credentials['client_id'],
        'client_secret': credentials['client_secret'],
        'cid_filter': cid_filter
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
        limit = 100
        
        while True:
            try:
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
        
            # Handle case where API returns bytes instead of dict
            if isinstance(query_result, bytes):
                logging.error("API returned bytes instead of expected dict response")
                print("API endpoint returned unexpected response format (likely due to 308 redirect)")
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
        
        if details_result['status_code'] != 200:
            logging.error(f"Failed to get child CID details: {details_result}")
            print(f"Failed to get child CID details: {details_result}")
            return []
        
        child_cids = []
        for i, child in enumerate(details_result['body']['resources']):
            try:
                child_info = {
                    'cid': child['child_cid'],
                    'name': str(child.get('name', child['child_cid'])),
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
            
            logging.info(f"Found {len(filtered_cids)} matching child CIDs out of {len(child_cids)} total")
            print(f"\n✓ Found {len(filtered_cids)} matching child CIDs out of {len(child_cids)} total")
            
            if filtered_cids:
                print("\nFiltered Child CIDs:")
                for i, cid in enumerate(filtered_cids, 1):
                    print(f"  {i}. {cid['name']} ({cid['cid']})")
            
            return filtered_cids
        
        logging.info(f"Found {len(child_cids)} child CIDs total")
        print(f"Found {len(child_cids)} child CIDs")
        return child_cids
        
    except Exception as e:
        logging.error(f"Error retrieving child CIDs: {e}")
        print(f"Error retrieving child CIDs: {e}")
        return []


def get_ioa_exclusions_for_cid(cid: str, auth_token: str, base_url: str = 'https://api.us-2.crowdstrike.com') -> List[Dict]:
    """Get existing IOA exclusions for a specific CID."""
    try:
        logging.info(f"Retrieving IOA exclusions for CID {cid}")
        print(f"\nRetrieving IOA exclusions for CID {cid}...")
        
        # Use Uber Class approach to target child CID with X-CS-USERUUID header
        falcon = APIHarnessV2(access_token=auth_token, base_url=base_url)
        
        # First, query for exclusion IDs using the child CID context
        query_result = falcon.command(
            action="queryIOAExclusionsV1",
            headers={"X-CS-USERUUID": cid},
            parameters={"limit": 500}
        )
        
        if isinstance(query_result, bytes) or not isinstance(query_result, dict):
            logging.error(f"IOA Exclusions query API returned unexpected type for CID {cid}: {type(query_result)}")
            return []
        
        if query_result.get('status_code') != 200:
            logging.error(f"Failed to query IOA exclusions for CID {cid}: {query_result}")
            print(f"  Error querying IOA exclusions: {query_result.get('body', {}).get('errors', 'Unknown error')}")
            return []
        
        exclusion_ids = query_result.get('body', {}).get('resources', [])
        
        if not exclusion_ids:
            print(f"  No IOA exclusions found for this CID")
            return []
        
        print(f"  Found {len(exclusion_ids)} exclusion IDs, getting details...")
        
        # Get detailed exclusion information using the child CID context
        details_result = falcon.command(
            action="getIOAExclusionsV1",
            headers={"X-CS-USERUUID": cid},
            parameters={"ids": exclusion_ids}
        )
        
        if isinstance(details_result, bytes) or not isinstance(details_result, dict):
            logging.error(f"IOA Exclusions details API returned unexpected type for CID {cid}: {type(details_result)}")
            return []
        
        if details_result.get('status_code') != 200:
            logging.error(f"Failed to get IOA exclusion details for CID {cid}: {details_result}")
            print(f"  Error getting IOA exclusion details: {details_result.get('body', {}).get('errors', 'Unknown error')}")
            return []
        
        exclusions = details_result.get('body', {}).get('resources', [])
        
        print(f"  Found {len(exclusions)} IOA exclusions")
        
        exclusion_list = []
        for i, exclusion in enumerate(exclusions):
            try:
                exclusion_info = {
                    'exclusion_id': exclusion.get('id', 'Unknown'),
                    'name': exclusion.get('name', 'Unnamed'),
                    'description': exclusion.get('description', 'No description'),
                    'pattern_id': exclusion.get('pattern_id', 'Unknown'),
                    'pattern_name': exclusion.get('pattern_name', 'Unknown'),
                    'cl_regex': exclusion.get('cl_regex', ''),
                    'ifn_regex': exclusion.get('ifn_regex', ''),
                    'groups': exclusion.get('groups', []),
                    'comment': exclusion.get('comment', ''),
                    'created_by': exclusion.get('created_by', 'Unknown'),
                    'created_timestamp': exclusion.get('created_timestamp', 'Unknown'),
                    'modified_by': exclusion.get('modified_by', 'Unknown'),
                    'modified_timestamp': exclusion.get('modified_timestamp', 'Unknown'),
                    'enabled': exclusion.get('enabled', False)
                }
                
                exclusion_list.append(exclusion_info)
                
            except Exception as exclusion_error:
                logging.error(f"Error processing IOA exclusion {i}: {exclusion_error}")
                continue
        
        logging.info(f"Found {len(exclusion_list)} IOA exclusions for CID {cid}")
        return exclusion_list
        
    except Exception as e:
        logging.error(f"Exception retrieving IOA exclusions for CID {cid}: {e}")
        return []


def main():
    """Main execution function."""
    # Setup logging
    setup_logging()
    
    logging.info("Starting CrowdStrike Falcon IOA Exclusion Discovery Tool")
    
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
    print(f"\nAvailable Child CIDs ({len(child_cids)}):")
    for i, cid in enumerate(child_cids, 1):
        print(f"  {i}. {cid['name']} ({cid['cid']})")
    
    # Let user select which CID to analyze
    while True:
        try:
            selection = input(f"\nSelect CID to analyze (1-{len(child_cids)}) or 'q' to quit: ").strip()
            if selection.lower() == 'q':
                return
            
            selection_idx = int(selection) - 1
            if 0 <= selection_idx < len(child_cids):
                selected_cid = child_cids[selection_idx]
                break
            else:
                print(f"Please enter a number between 1 and {len(child_cids)}")
        except ValueError:
            print("Please enter a valid number or 'q' to quit")
    
    print(f"\nAnalyzing IOA exclusions for: {selected_cid['name']} ({selected_cid['cid']})")
    print("=" * 60)
    
    # Get IOA exclusions for the selected CID
    exclusions = get_ioa_exclusions_for_cid(
        selected_cid['cid'],
        auth.token()['body']['access_token'],
        getattr(auth, 'base_url', 'https://api.us-2.crowdstrike.com')
    )
    
    if not exclusions:
        print("❌ No IOA exclusions found for this CID.")
        print("This means:")
        print("  - No IOA exclusions have been created yet for this CID")
        print("  - This is a fresh environment with no exclusions configured")
        print("  - You can create new exclusions using the main exclusion script")
        return
    
    # Display exclusions
    print(f"\n✓ Found {len(exclusions)} existing IOA exclusions:")
    print("\n" + "=" * 100)
    
    for i, exclusion in enumerate(exclusions, 1):
        print(f"\n{i}. EXCLUSION: {exclusion['name']}")
        print(f"   Exclusion ID: {exclusion['exclusion_id']}")
        print(f"   Pattern ID: {exclusion['pattern_id']}")
        print(f"   Pattern Name: {exclusion['pattern_name']}")
        print(f"   Description: {exclusion['description']}")
        if exclusion['cl_regex']:
            print(f"   Command Line Regex: {exclusion['cl_regex']}")
        if exclusion['ifn_regex']:
            print(f"   Image Filename Regex: {exclusion['ifn_regex']}")
        print(f"   Groups: {exclusion['groups'] if exclusion['groups'] else 'All groups'}")
        print(f"   Enabled: {exclusion['enabled']}")
        if exclusion['comment']:
            print(f"   Comment: {exclusion['comment']}")
        print(f"   Created by: {exclusion['created_by']} | Modified by: {exclusion['modified_by']}")
    
    print("\n" + "=" * 100)
    print(f"\n📋 SUMMARY: {len(exclusions)} IOA exclusions currently configured")
    print("\n💡 Pattern IDs shown above can be referenced when creating new exclusions.")
    
    # Optionally save to file
    save_option = input(f"\nSave exclusions to file? (y/n): ").strip().lower()
    if save_option == 'y':
        filename = f"ioa_exclusions_{selected_cid['name'].replace(' ', '_')}_{selected_cid['cid']}.json"
        try:
            with open(filename, 'w') as f:
                json.dump({
                    'cid': selected_cid['cid'],
                    'cid_name': selected_cid['name'],
                    'exclusions': exclusions,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }, f, indent=2)
            print(f"✓ Exclusions saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving file: {e}")


if __name__ == "__main__":
    main()