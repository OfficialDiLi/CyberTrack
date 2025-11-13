import whois
import time # Import the time module

def get_domain_info(domain_name):
    """
    Retrieves WHOIS information for a given domain name.
    """
    try:
        print(f"Attempting to retrieve WHOIS info for {domain_name}...")
        domain_info = whois.whois(domain_name)
        if not domain_info or domain_info.domain_name is None:
            print(f"Warning: WHOIS data for {domain_name} appears to be empty or incomplete.")
            # This could happen if the connection was reset but an empty object was returned
        return domain_info
    except Exception as e:
        print(f"Error retrieving WHOIS info for {domain_name}: {e}")
        return None

if __name__ == "__main__":
    domains_to_lookup = ["bosu.gov.ng", "thenkiri.com", "mkvdrama.net","dramakey.com"] # Add more domains to test

    for domain in domains_to_lookup:
        info = get_domain_info(domain)

        if info and info.domain_name: # Check if info is not None and has actual domain data
            print(f"\nWHOIS Information for {domain}:")
            print(f"  Registrar: {info.registrar}")
            print(f"  Creation Date: {info.creation_date}")
            print(f"  Expiration Date: {info.expiration_date}")
            print(f"  Last Updated: {info.updated_date}")
            print(f"  Name Servers: {info.name_servers}")
            print(f"  Emails: {info.emails}")
            print(f"  Organization: {info.org}")
            print(f"  Address: {info.address}")
            print(f"  City: {info.city}")
            print(f"  State: {info.state}")
            print(f"  Zipcode: {info.zipcode}")
            print(f"  Country: {info.country}")
            print("\nFull WHOIS Record:")
            print(info)
        else:
            print(f"\nCould not retrieve complete WHOIS information for {domain}.")

        time.sleep(2) # Wait for 2 seconds before the next lookup to avoid rate limits
