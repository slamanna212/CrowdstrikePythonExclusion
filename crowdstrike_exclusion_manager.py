#!/usr/bin/env python3
#Test git with new line
"""
CrowdStrike Falcon Sensor Visibility Exclusion Manager

This script manages sensor visibility exclusions across multiple child CIDs
under a parent CrowdStrike Falcon account. It allows filtering of child CIDs
by name and applies exclusions to selected environments.
"""

import sys
import getpass
import time
import logging
from typing import List, Dict, Optional
from falconpy import OAuth2, SensorVisibilityExclusions, FlightControl


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
    print("CrowdStrike Falcon Exclusion Manager")
    print("=" * 40)
    
    client_id = input("Enter CrowdStrike API Client ID: ").strip()
    client_secret = getpass.getpass("Enter CrowdStrike API Client Secret: ")
    
    # Get CID filtering options
    print("\n--- Child CID Filtering ---")
    filter_option = input("Filter child CIDs? (y/n): ").strip().lower()
    cid_filter = ""
    if filter_option == 'y':
        cid_filter = input("Enter CID name filter (partial match): ").strip()
    
    # Get exclusion details
    print("\n--- Exclusion Details ---")
    exclusion_value = input("Enter exclusion value (path/process): ").strip()
    exclusion_comment = input("Enter exclusion comment: ").strip()
    
    return {
        'client_id': client_id,
        'client_secret': client_secret,
        'cid_filter': cid_filter,
        'exclusion_value': exclusion_value,
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
        
        # Query all child CIDs
        # First get the list of child CID IDs
        logging.debug("About to call flight_control.query_children()")
        try:
            query_result = flight_control.query_children()
            logging.debug(f"query_children() returned: type={type(query_result)}, content={query_result}")
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
            if query_result['status_code'] == 308:
                logging.info("Received 308 redirect, this may be a region-specific endpoint issue")
                print("Received 308 redirect - this may indicate a region-specific endpoint issue")
            
            return []
        
        child_cid_ids = query_result['body']['resources']
        
        if not child_cid_ids:
            logging.warning("No child CIDs found in this parent account.")
            print("No child CIDs found in this parent account.")
            return []
        
        logging.info(f"Found {len(child_cid_ids)} child CID IDs, retrieving details...")
        
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
            logging.debug(f"Applying filter '{name_filter}' to {len(child_cids)} child CIDs")
            filtered_cids = []
            for cid in child_cids:
                try:
                    if name_filter.lower() in cid['name'].lower():
                        filtered_cids.append(cid)
                except Exception as filter_error:
                    logging.error(f"Error filtering CID {cid}: {filter_error}")
                    logging.debug(f"CID data: {cid}")
                    logging.debug(f"CID name type: {type(cid.get('name', 'N/A'))}")
                    logging.debug(f"Filter type: {type(name_filter)}")
            # filtered_cids = [cid for cid in child_cids if name_filter.lower() in cid['name'].lower()]
            logging.info(f"Found {len(filtered_cids)} matching child CIDs out of {len(child_cids)} total")
            print(f"Found {len(filtered_cids)} matching child CIDs out of {len(child_cids)} total")
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


def create_exclusion_for_cid(cid: str, exclusion_value: str, comment: str, auth_token: str) -> Dict:
    """Create sensor visibility exclusion for a specific CID."""
    try:
        logging.info(f"Creating exclusion for CID {cid}: {exclusion_value}")
        
        # Initialize SensorVisibilityExclusions service for specific CID
        exclusions = SensorVisibilityExclusions(access_token=auth_token, member_cid=cid)
        
        # Create the exclusion
        exclusion_data = {
            "comment": comment,
            "value": exclusion_value,
            "groups": []  # Empty groups means apply to all host groups
        }
        
        result = exclusions.create_exclusions(**exclusion_data)
        
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
    
    logging.info("Starting CrowdStrike Falcon Exclusion Manager")
    
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
    
    logging.info(f"Starting to apply exclusion '{inputs['exclusion_value']}' to {len(child_cids)} CIDs")
    print(f"\nApplying exclusion: {inputs['exclusion_value']}")
    print("=" * 50)
    
    for cid_info in child_cids:
        cid = cid_info['cid']
        name = cid_info['name']
        operation_count += 1
        
        print(f"Processing {name} ({cid})...")
        
        # Apply rate limiting
        rate_limit_delay(operation_count)
        
        result = create_exclusion_for_cid(
            cid, 
            inputs['exclusion_value'], 
            inputs['exclusion_comment'],
            auth.token()['body']['access_token']
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
    
    print(f"\nExclusion Details:")
    print(f"  Value: {inputs['exclusion_value']}")
    print(f"  Comment: {inputs['exclusion_comment']}")
    
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