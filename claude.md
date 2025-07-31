# Tech Stack
 - Python3
 - Crowdstrike Falcon Python module, falconpy
 - Runs in terminal

# Project Structure
 - Script is used to add sensor visibility exclusions to a bunch of child CIDs under a parent crowdstrike account. We should be able to filter what child CIDs we use, filtered by name
 - script will be given a parent CID, it will then gather a list of child CIDs, filter them based on input at the start, and then one at a time, log into them, add an exclusion we give it, and then when done should list out all child CIDs it touched. 
 - The script should ask for crowdstrike api key, secret, any client filtering, and then exclusion information ( I am unsure what format this needs to be)
